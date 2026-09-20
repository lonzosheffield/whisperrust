//! WhisperRust - local offline push-to-talk voice dictation for Windows.
//!
//! # Phase 1a scope
//!
//! The I/O spine, end to end, with **canned text instead of transcription**. No audio
//! capture, no model. That is deliberate: it lets the dangerous half of the system - a
//! global keyboard hook, the guards, and synthetic input into other people's applications
//! - be exercised and verified before any of it is entangled with inference.
//!
//! # Threading (PLAN.md 3.2)
//!
//! Three OS threads, no async runtime. There is no async I/O in this program.
//!
//! * **main**   - Win32 message pump, keyboard hook, watchdogs, injection.
//!                Nothing here may take longer than ~10 ms: a slow hook procedure gets
//!                silently unregistered by Windows, with no notification.
//! * **worker** - the session state machine and, from Phase 3, inference.
//! * **audio**  - Phase 2.
//!
//! worker -> main is a **doorbell**: `PostThreadMessageW(WM_APP)` carrying no payload,
//! then main drains a channel. Never a pointer: any process can post `WM_APP` to our
//! thread, and we would be dereferencing attacker-controlled data (REDTEAM S-03).

mod clipboard;
mod fsm;
mod hook;
mod inject;
mod policy;
mod preflight;
mod sanitize;
mod target;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crossbeam_channel::{bounded, Receiver, Sender};
use windows::Win32::Foundation::{LPARAM, WPARAM};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, PeekMessageW, PostThreadMessageW, TranslateMessage, MSG, PM_REMOVE, WM_APP,
    WM_QUIT,
};

use fsm::{Action, Event, Fsm};
use hook::{Heartbeat, PttEvent, StuckKeyWatchdog};
use inject::{ClipboardPort, InjectGuard};
use preflight::{Decision, Request};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);
static DISABLED: AtomicBool = AtomicBool::new(false);
static WORKER_HEARTBEAT: Heartbeat = Heartbeat::new();

/// A unit of work handed from worker to main for injection.
struct DeliverJob {
    utterance_id: u64,
    text: String,
    hold: Duration,
    end_cause: preflight::EndCause,
    target_at_capture: Option<target::TargetContext>,
}

// ---------------------------------------------------------------------------------------
// Startup refusals
// ---------------------------------------------------------------------------------------

/// I-1: the daemon refuses to run elevated.
///
/// An elevated daemon reading a user-writable model path through ggml's hand-written
/// binary deserializer is a privilege-escalation path, with the microphone, a global
/// keyboard hook and SendInput already in hand (REDTEAM S-01, rated Critical). The user
/// has confirmed they do not dictate into elevated windows, so this is unconditional.
fn refuse_if_elevated() {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            eprintln!("FATAL: cannot inspect own token; refusing to start.");
            std::process::exit(1);
        }
        let mut elev = TOKEN_ELEVATION::default();
        let mut ret = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elev as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        )
        .is_ok();
        let _ = CloseHandle(token);

        if !ok {
            eprintln!("FATAL: cannot determine elevation; refusing to start.");
            std::process::exit(1);
        }
        if elev.TokenIsElevated != 0 {
            eprintln!(
                "FATAL: WhisperRust must not run elevated (invariant I-1).\n\
                 A daemon holding a keyboard hook, the microphone and SendInput must not\n\
                 also hold admin rights. Run it as a normal user.\n\
                 Elevated windows are a documented no-go: dictation aimed at them falls\n\
                 back to the clipboard."
            );
            std::process::exit(1);
        }
    }
}

/// Emergency stop layer 6: an administrator can disable the daemon machine-wide.
fn refuse_if_disabled() {
    if std::path::Path::new(policy::DISABLE_SENTINEL).exists() {
        eprintln!(
            "WhisperRust is disabled by {}\nRemove that file to re-enable.",
            policy::DISABLE_SENTINEL
        );
        std::process::exit(0);
    }
}

// ---------------------------------------------------------------------------------------
// Worker thread
// ---------------------------------------------------------------------------------------

struct WorkerCtx {
    rx: Receiver<PttEvent>,
    jobs: Sender<DeliverJob>,
    main_thread: u32,
    canned: String,
    fake_latency: Duration,
}

/// Wake the main thread. Doorbell only - no payload.
fn ring_doorbell(main_thread: u32) {
    unsafe {
        let _ = PostThreadMessageW(main_thread, WM_APP, WPARAM(0), LPARAM(0));
    }
}

fn worker_main(ctx: WorkerCtx) {
    let mut machine = Fsm::new();
    let mut watchdog = StuckKeyWatchdog::new();

    loop {
        if SHUTDOWN.load(Ordering::Relaxed) {
            return;
        }
        WORKER_HEARTBEAT.beat();

        // Watchdog B: a capture whose key-up we never saw - for example because the key
        // was released while an elevated window had focus - must not hang here forever.
        if let Some(reason) = watchdog.poll() {
            watchdog.on_capture_end();
            let actions = machine.handle(Event::ForcedEnd { at: Instant::now(), reason });
            run_actions(&mut machine, actions, &ctx, &mut watchdog);
            continue;
        }

        match ctx.rx.recv_timeout(policy::STUCK_KEY_POLL) {
            Ok(PttEvent::Down) => {
                let a = machine.handle(Event::PttDown { at: Instant::now() });
                run_actions(&mut machine, a, &ctx, &mut watchdog);
            }
            Ok(PttEvent::Up) => {
                let a = machine.handle(Event::PttUp { at: Instant::now() });
                run_actions(&mut machine, a, &ctx, &mut watchdog);
            }
            Ok(PttEvent::KillChord) => {
                let a = machine.handle(Event::KillChord);
                run_actions(&mut machine, a, &ctx, &mut watchdog);
            }
            Ok(PttEvent::LivenessPong) => tracing::trace!("hook liveness confirmed"),
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn run_actions(
    machine: &mut Fsm,
    actions: Vec<Action>,
    ctx: &WorkerCtx,
    watchdog: &mut StuckKeyWatchdog,
) {
    for action in actions {
        match action {
            Action::StartCapture { utterance_id } => {
                watchdog.on_capture_start();
                tracing::info!(utterance_id, "capture started");
                println!("  [recording #{utterance_id}]");
            }

            Action::DiscardCapture { utterance_id, why } => {
                watchdog.on_capture_end();
                tracing::info!(utterance_id, why, "capture discarded");
                println!("  [discarded #{utterance_id}: {why}]");
            }

            Action::FinishCapture { utterance_id, hold, end_cause } => {
                watchdog.on_capture_end();

                // Record where the text was aimed at the moment the user stopped
                // speaking. preflight compares this against the target at inject time,
                // which is what stops dictation landing in the wrong window after an
                // alt-tab, and what catches focus moving between fields of the same
                // window (REDTEAM B-03).
                machine.target_at_capture = target::probe();

                tracing::info!(utterance_id, ?hold, cause = end_cause.as_str(), "capture finished");
                println!("  [transcribing #{utterance_id}...]");

                // Phase 1a stands in for inference with a fixed delay. Phase 3 swaps in
                // the real backend; nothing around this changes.
                std::thread::sleep(ctx.fake_latency);

                let a = machine.handle(Event::TranscriptReady { text: ctx.canned.clone() });
                run_actions(machine, a, ctx, watchdog);
            }

            Action::Deliver { utterance_id, text, hold, end_cause } => {
                let job = DeliverJob {
                    utterance_id,
                    text,
                    hold,
                    end_cause,
                    target_at_capture: machine.target_at_capture.clone(),
                };
                if ctx.jobs.try_send(job).is_ok() {
                    ring_doorbell(ctx.main_thread);
                } else {
                    tracing::warn!(utterance_id, "delivery queue full; dropping");
                }
            }

            Action::Notify(msg) => {
                tracing::info!("{msg}");
                println!("  [{msg}]");
            }

            Action::Disable => {
                DISABLED.store(true, Ordering::Relaxed);
                println!("  [DISABLED by kill chord - Ctrl+C to exit]");
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// Main thread: pump, watchdogs, injection
// ---------------------------------------------------------------------------------------

struct MainGuard;
impl InjectGuard for MainGuard {
    fn may_continue(&self) -> bool {
        !SHUTDOWN.load(Ordering::Relaxed)
            && !DISABLED.load(Ordering::Relaxed)
            && hook::HEALTHY.load(Ordering::Relaxed)
    }
    fn modifiers_held(&self) -> bool {
        inject::modifiers_physically_down()
    }
}

/// Take a delivery job through preflight, then act on the decision.
fn deliver(job: DeliverJob, cb: &mut dyn ClipboardPort) {
    let (clean, report) = sanitize::sanitize(&job.text);
    if !report.is_clean() {
        tracing::info!(utterance_id = job.utterance_id, ?report, "sanitizer modified text");
    }

    let now = target::probe();
    let req = Request {
        text: &clean,
        hold: job.hold,
        end_cause: job.end_cause,
        target_at_capture: job.target_at_capture.as_ref(),
        target_now: now.as_ref(),
        modifiers_held: inject::modifiers_physically_down(),
        healthy: hook::HEALTHY.load(Ordering::Relaxed) && !DISABLED.load(Ordering::Relaxed),
        app_denied: false,
    };

    match preflight::preflight(&req) {
        Decision::Inject(clearance) => {
            let guard = MainGuard;
            let outcome = inject::inject(clearance, &clean, &guard, cb);
            tracing::info!(utterance_id = job.utterance_id, ?outcome, "delivered");
            println!("  [#{} {:?}]", job.utterance_id, outcome);
        }
        Decision::ClipboardOnly(reason) => {
            // The text is still useful; the user just pastes it themselves.
            match cb.set_text(&clean) {
                Ok(()) => println!(
                    "  [#{} {} - left on clipboard]",
                    job.utterance_id,
                    reason.user_message()
                ),
                Err(e) => println!(
                    "  [#{} refused ({}); clipboard also failed: {e}]",
                    job.utterance_id,
                    reason.as_str()
                ),
            }
            tracing::info!(
                utterance_id = job.utterance_id,
                reason = reason.as_str(),
                "clipboard-only"
            );
        }
        Decision::Drop(reason) => {
            // Nothing written anywhere. This is the password-field path: putting it on
            // the clipboard would only relocate the exposure.
            println!("  [#{} DROPPED - {}]", job.utterance_id, reason.user_message());
            tracing::info!(
                utterance_id = job.utterance_id,
                reason = reason.as_str(),
                "dropped"
            );
        }
    }
}

fn run_daemon(canned: String, fake_latency: Duration) {
    let main_thread = unsafe { GetCurrentThreadId() };

    let (ptt_tx, ptt_rx) = bounded::<PttEvent>(64);
    let (job_tx, job_rx) = bounded::<DeliverJob>(8);

    if let Err(e) = hook::install(ptt_tx, policy::DEFAULT_PTT_VK) {
        eprintln!("FATAL: {e}");
        std::process::exit(1);
    }

    let worker = std::thread::Builder::new()
        .name("whisperrust-worker".into())
        .spawn(move || {
            worker_main(WorkerCtx {
                rx: ptt_rx,
                jobs: job_tx,
                main_thread,
                canned,
                fake_latency,
            })
        })
        .expect("spawn worker");

    let mut cb = clipboard::WinClipboard::new();
    let mut last_liveness = Instant::now();
    let mut last_health = Instant::now();

    println!("Listening. Hold RIGHT CTRL, then release to inject the canned text.");
    println!(
        "Kill chord: tap Right Ctrl {}x within 1s. Ctrl+C to exit.",
        policy::KILL_CHORD_TAPS
    );
    println!();

    // The pump. This thread owns the hook, so everything here stays fast.
    while !SHUTDOWN.load(Ordering::Relaxed) {
        unsafe {
            let mut msg = MSG::default();
            while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                if msg.message == WM_QUIT {
                    SHUTDOWN.store(true, Ordering::Relaxed);
                    break;
                }
                // WM_APP is the doorbell and carries NO payload; the work is in the
                // channel. Any process can post here, so a payload would be
                // attacker-controlled.
                if msg.message != WM_APP {
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
        }

        // Drain deliveries regardless of the doorbell, so a lost message cannot strand a
        // job in the queue.
        while let Ok(job) = job_rx.try_recv() {
            deliver(job, &mut cb);
        }

        // Watchdog A: prove the hook is still installed. Windows removes a slow hook with
        // no notification at all, and the only symptom is that the hotkey silently stops
        // working forever.
        if last_liveness.elapsed() >= policy::HOOK_LIVENESS_INTERVAL {
            last_liveness = Instant::now();
            if hook::liveness_probe_outstanding() {
                tracing::error!("hook liveness probe unanswered; reinstalling");
                if let Err(e) = hook::reinstall(policy::DEFAULT_PTT_VK) {
                    tracing::error!("hook reinstall failed: {e}");
                }
            }
            hook::send_liveness_probe();
        }

        if last_health.elapsed() >= Duration::from_millis(500) {
            last_health = Instant::now();
            WORKER_HEARTBEAT.refresh_health();
        }

        std::thread::sleep(Duration::from_millis(10));
    }

    hook::uninstall();
    let _ = worker.join();
    println!("stopped.");
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "whisperrust=info".into()),
        )
        .init();

    refuse_if_elevated();
    refuse_if_disabled();

    let args: Vec<String> = std::env::args().collect();

    // One-shot diagnostic: where would text go right now, and how?
    if args.iter().any(|a| a == "--probe") {
        match target::probe() {
            Some(c) => {
                println!("exe        : {}", c.exe);
                println!("title      : {}", c.title);
                println!("hwnd       : {:#x}", c.hwnd);
                println!("focus hwnd : {:?}", c.focus_hwnd);
                println!("elevated   : {}", c.elevated);
                println!("password   : {}", c.is_password);
                println!("method     : {:?}", policy::choose_method(&c.exe, 50));
                println!("restore ms : {}", policy::restore_delay_ms(&c.exe));
                println!("terminal   : {}", policy::is_terminal(&c.exe));
            }
            None => println!("no foreground window"),
        }
        return;
    }

    let canned = args
        .iter()
        .position(|a| a == "--text")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "The quick brown fox jumps over the lazy dog.".to_string());

    let latency_ms: u64 = args
        .iter()
        .position(|a| a == "--latency-ms")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(800);

    install_ctrlc_handler();

    println!("WhisperRust - Phase 1a (canned text, no audio, no model)");
    println!("  canned text  : {canned:?}");
    println!("  fake latency : {latency_ms} ms");
    println!();

    run_daemon(canned, Duration::from_millis(latency_ms));
}

/// Ctrl+C, without taking a dependency for it.
fn install_ctrlc_handler() {
    use windows::core::BOOL;
    use windows::Win32::System::Console::{SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_C_EVENT};

    unsafe extern "system" fn handler(event: u32) -> BOOL {
        if event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT {
            SHUTDOWN.store(true, Ordering::Relaxed);
            return true.into();
        }
        false.into()
    }
    unsafe {
        let _ = SetConsoleCtrlHandler(Some(handler), true);
    }
}
