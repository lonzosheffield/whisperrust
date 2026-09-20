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

mod audio;
mod backend;
mod audiocheck;
mod clipboard;
mod fsm;
mod hook;
mod inject;
mod policy;
mod postprocess;
mod preflight;
mod resample;
mod session_log;
mod stats;
mod sanitize;
mod target;
mod uia;

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

/// Timings and model facts gathered during inference, carried to the session log.
///
/// Collected here rather than logged in place because a latency number is only meaningful
/// next to the decision it produced: "1.4 s" means something different when the text was
/// typed than when a guard refused it.
#[derive(Debug, Default, Clone)]
struct InferMetrics {
    raw_audio_secs: f32,
    trimmed_audio_secs: f32,
    resample_ms: f64,
    vad_ms: f64,
    infer_ms: f64,
    no_speech_prob: f32,
    verdict: String,
    model: String,
    threads: i32,
}

/// A unit of work handed from worker to main for injection.
struct DeliverJob {
    utterance_id: u64,
    /// RAW transcript text. The join is deliberately NOT applied here.
    text: String,
    /// How this utterance should attach to the previous one.
    ///
    /// Carried rather than pre-applied because `sanitize()` trims leading whitespace - it
    /// has to, since raw model output is full of stray spacing. Applying the join before
    /// sanitize meant the separator was added and then immediately trimmed away, gluing
    /// every pair of consecutive dictations together ("First thought.Second thought.").
    /// Both functions were individually correct; the bug lived only in their ordering.
    join: postprocess::Join,
    hold: Duration,
    end_cause: preflight::EndCause,
    target_at_capture: Option<target::TargetContext>,
    /// When the PTT key was released. The CP-3 criterion is p95 of release-to-delivered,
    /// so the clock has to start here rather than at inference.
    released_at: Instant,
    metrics: InferMetrics,
    /// Cumulative audio-health counters at the time of this utterance.
    ring_overruns: u64,
    stream_errors: u64,
    device_rate: u32,
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
    /// Phase 1a fallback: used only when no model is loaded, so the I/O path stays
    /// testable without a 141 MB download.
    canned: String,
    fake_latency: Duration,
}

/// Everything the worker needs to turn audio into text. Absent in canned-text mode.
struct Pipeline {
    backend: Box<dyn backend::TranscriptionBackend>,
    capture: audio::AudioCapture,
    device_rate: u32,
    preroll: audio::PrerollRing,
    /// Audio retained for the utterance in flight, at device rate.
    utterance: Vec<f32>,
    scratch: Vec<f32>,
    capturing: bool,
    /// Previous injected text, for sentence joining.
    prev: Option<(String, Instant)>,
}

/// Wake the main thread. Doorbell only - no payload.
fn ring_doorbell(main_thread: u32) {
    unsafe {
        let _ = PostThreadMessageW(main_thread, WM_APP, WPARAM(0), LPARAM(0));
    }
}

fn worker_main(ctx: WorkerCtx, mut pipe: Option<Pipeline>) {
    let mut machine = Fsm::new();
    let mut watchdog = StuckKeyWatchdog::new();

    loop {
        // Drain the microphone every tick, whether or not we are capturing.
        //
        // The stream is ALWAYS running (PLAN 3.3): draining continuously keeps the
        // preroll ring current so that when PTT-down arrives we already hold the 400 ms
        // that preceded it. Stopping the drain while idle would let the ring overflow and
        // would make the preroll stale - which is the whole feature.
        if let Some(p) = pipe.as_mut() {
            p.scratch.clear();
            p.capture.drain_into(&mut p.scratch);
            if !p.scratch.is_empty() {
                if p.capturing {
                    p.utterance.extend_from_slice(&p.scratch);
                } else {
                    let s = std::mem::take(&mut p.scratch);
                    p.preroll.push_slice(&s);
                    p.scratch = s;
                }
            }
        }

        if SHUTDOWN.load(Ordering::Relaxed) {
            return;
        }
        WORKER_HEARTBEAT.beat();

        // Watchdog B: a capture whose key-up we never saw - for example because the key
        // was released while an elevated window had focus - must not hang here forever.
        if let Some(reason) = watchdog.poll() {
            watchdog.on_capture_end();
            // D-5: this capture is ending WITHOUT a key-up having been observed, so the
            // hook's autorepeat latch is stale. Leaving it set makes the user's next press
            // invisible.
            hook::clear_held();
            let actions = machine.handle(Event::ForcedEnd { at: Instant::now(), reason });
            run_actions(&mut machine, actions, &ctx, &mut pipe, &mut watchdog);
            continue;
        }

        match ctx.rx.recv_timeout(policy::STUCK_KEY_POLL) {
            Ok(PttEvent::Down) => {
                let a = machine.handle(Event::PttDown { at: Instant::now() });
                run_actions(&mut machine, a, &ctx, &mut pipe, &mut watchdog);
            }
            Ok(PttEvent::Up) => {
                let a = machine.handle(Event::PttUp { at: Instant::now() });
                run_actions(&mut machine, a, &ctx, &mut pipe, &mut watchdog);
            }
            Ok(PttEvent::KillChord) => {
                let a = machine.handle(Event::KillChord);
                run_actions(&mut machine, a, &ctx, &mut pipe, &mut watchdog);
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
    pipe: &mut Option<Pipeline>,
    watchdog: &mut StuckKeyWatchdog,
) {
    // Join decision for the transcript currently being delivered. Set immediately before
    // TranscriptReady is handed to the FSM.
    let mut pending_join = postprocess::Join::Fresh;
    let mut last_metrics = InferMetrics::default();
    let mut last_audio_health = (0u64, 0u64);
    let mut last_device_rate = 0u32;
    // Clock for the CP-3 criterion: release to text delivered.
    let mut released_at = Instant::now();
    for action in actions {
        match action {
            Action::StartCapture { utterance_id } => {
                watchdog.on_capture_start();
                if let Some(p) = pipe.as_mut() {
                    // Seed with the preroll: the user starts speaking slightly before the
                    // key fully registers, and without this the first word is clipped.
                    p.utterance.clear();
                    p.utterance.extend_from_slice(&p.preroll.snapshot());
                    p.capturing = true;
                }
                tracing::info!(utterance_id, "capture started");
                println!("  [recording #{utterance_id}]");
            }

            Action::DiscardCapture { utterance_id, why } => {
                watchdog.on_capture_end();
                if let Some(p) = pipe.as_mut() {
                    p.capturing = false;
                    p.utterance.clear();
                }
                tracing::info!(utterance_id, why, "capture discarded");
                println!("  [discarded #{utterance_id}: {why}]");
            }

            Action::FinishCapture { utterance_id, hold, end_cause } => {
                watchdog.on_capture_end();
                released_at = Instant::now();

                // Record where the text was aimed at the moment the user stopped
                // speaking. preflight compares this against the target at inject time,
                // which is what stops dictation landing in the wrong window after an
                // alt-tab, and what catches focus moving between fields of the same
                // window (REDTEAM B-03).
                machine.target_at_capture = target::probe();

                tracing::info!(utterance_id, ?hold, cause = end_cause.as_str(), "capture finished");
                println!("  [transcribing #{utterance_id}...]");

                let result: Option<(String, postprocess::Join)> = match pipe.as_mut() {
                    Some(p) => {
                        p.capturing = false;

                        // Grace period after key-up: people release slightly early, so
                        // this catches the last syllable. Keep draining and beating while
                        // we wait - sleeping outright would stall the audio path.
                        let grace_end = Instant::now() + policy::POST_RELEASE_GRACE;
                        while Instant::now() < grace_end {
                            std::thread::sleep(Duration::from_millis(10));
                            WORKER_HEARTBEAT.beat();
                            p.scratch.clear();
                            p.capture.drain_into(&mut p.scratch);
                            let tail = std::mem::take(&mut p.scratch);
                            p.utterance.extend_from_slice(&tail);
                            p.scratch = tail;
                        }

                        // Inference runs on its OWN thread. See transcribe_off_thread.
                        let (r, m) = transcribe_off_thread(p, utterance_id);
                        last_metrics = m;
                        last_audio_health = (p.capture.ring_overruns(), p.capture.stream_errors());
                        last_device_rate = p.device_rate;
                        r
                    }
                    None => {
                        // No model loaded: canned text keeps the I/O path exercisable.
                        std::thread::sleep(ctx.fake_latency);
                        last_metrics = InferMetrics {
                            verdict: "canned".into(),
                            model: "none".into(),
                            ..Default::default()
                        };
                        Some((ctx.canned.clone(), postprocess::Join::Fresh))
                    }
                };

                match result {
                    Some((t, join)) => {
                        pending_join = join;
                        let a = machine.handle(Event::TranscriptReady { text: t });
                        run_actions(machine, a, ctx, pipe, watchdog);
                    }
                    None => {
                        // Rejected as non-speech. Nothing is injected and nothing is said;
                        // a toast on every accidental tap would be its own annoyance.
                        let a = machine.handle(Event::TranscriptReady { text: String::new() });
                        run_actions(machine, a, ctx, pipe, watchdog);
                    }
                }
            }

            Action::Deliver { utterance_id, text, hold, end_cause } => {
                let job = DeliverJob {
                    utterance_id,
                    text,
                    join: pending_join,
                    hold,
                    end_cause,
                    target_at_capture: machine.target_at_capture.clone(),
                    released_at,
                    metrics: last_metrics.clone(),
                    ring_overruns: last_audio_health.0,
                    stream_errors: last_audio_health.1,
                    device_rate: last_device_rate,
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


/// Run inference on a helper thread while the worker keeps draining audio and beating.
///
/// # Why this is not inline
///
/// Running inference inline stopped the audio drain and the heartbeat for its whole
/// duration - measured 1.75 s for an 11 s utterance and 3.6-4.4 s for 44 s. Three things
/// broke as a result, none of which any unit test could see:
///
/// * the 2 s audio ring overran, losing audio. The Phase 2 soak reported zero overruns
///   because its harness never stalls the drain - it measured a pipeline that does not
///   exist in production.
/// * the 3 s heartbeat went stale, so every long dictation was downgraded to
///   "daemon degraded - clipboard only" and the hook went transparent mid-use.
/// * a PTT press during inference was processed afterwards with `hold ~= 0` and discarded
///   as an accidental tap, silently losing the next thing the user said.
fn transcribe_off_thread(
    p: &mut Pipeline,
    utterance_id: u64,
) -> (Option<(String, postprocess::Join)>, InferMetrics) {
    let utterance = std::mem::take(&mut p.utterance);
    let device_rate = p.device_rate;
    let prev_text = p.prev.as_ref().map(|(t, _)| t.clone());
    let join = postprocess::decide_join(p.prev.as_ref().map(|(t, i)| (t.as_str(), *i)));

    // The backend is owned by the pipeline and is not Sync, so it is moved across for the
    // duration and moved back. The worker cannot start another inference meanwhile - the
    // FSM is in Finalizing - so there is no contention.
    let mut engine =
        std::mem::replace(&mut p.backend, Box::new(backend::MockBackend::default()));

    type InferResult = (
        Box<dyn backend::TranscriptionBackend>,
        Option<String>,
        InferMetrics,
    );
    let (tx, rx) = crossbeam_channel::bounded::<InferResult>(1);

    if std::thread::Builder::new()
        .name("whisperrust-infer".into())
        .spawn(move || {
            let (text, m) =
                run_inference(&mut engine, &utterance, device_rate, prev_text, utterance_id);
            let _ = tx.send((engine, text, m));
        })
        .is_err()
    {
        tracing::error!(utterance_id, "could not spawn inference thread");
        return (None, InferMetrics::default());
    }

    // Keep the audio path and the health signal alive while we wait.
    let (text, metrics) = loop {
        match rx.recv_timeout(Duration::from_millis(20)) {
            Ok((b, text, m)) => {
                p.backend = b;
                break (text, m);
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                WORKER_HEARTBEAT.beat();
                p.scratch.clear();
                p.capture.drain_into(&mut p.scratch);
                if !p.scratch.is_empty() {
                    let s = std::mem::take(&mut p.scratch);
                    p.preroll.push_slice(&s);
                    p.scratch = s;
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                tracing::error!(utterance_id, "inference thread died");
                break (None, InferMetrics::default());
            }
        }
    };

    match text {
        Some(t) => {
            p.prev = Some((t.clone(), Instant::now()));
            (Some((t, join)), metrics)
        }
        None => (None, metrics),
    }
}

/// The inference body. Owns its audio, so it can run anywhere.
fn run_inference(
    engine: &mut Box<dyn backend::TranscriptionBackend>,
    utterance: &[f32],
    device_rate: u32,
    prev_text: Option<String>,
    utterance_id: u64,
) -> (Option<String>, InferMetrics) {
    let mut m = InferMetrics::default();
    let raw_secs = utterance.len() as f32 / device_rate as f32;
    m.raw_audio_secs = raw_secs;

    let t_resample = Instant::now();
    let pcm = match audio::finalize(utterance, device_rate) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(utterance_id, "resample failed: {e}");
            m.verdict = "resample_failed".into();
            return (None, m);
        }
    };
    m.resample_ms = t_resample.elapsed().as_secs_f64() * 1000.0;

    // VAD returning None means genuinely no speech, so the model is never called - the
    // cheapest possible fix for the most common hallucination case.
    let t_vad = Instant::now();
    let trimmed = match engine.vad_trim(&pcm) {
        Some(t) => t,
        None => {
            m.vad_ms = t_vad.elapsed().as_secs_f64() * 1000.0;
            m.verdict = "vad_no_speech".into();
            tracing::info!(utterance_id, raw_secs, "no speech detected; skipping inference");
            println!("  [#{utterance_id} no speech - skipped]");
            return (None, m);
        }
    };
    m.vad_ms = t_vad.elapsed().as_secs_f64() * 1000.0;

    let hint = backend::Hint {
        language: Some("en".into()),
        prev_text,
        ..Default::default()
    };

    let info = engine.info();
    m.model = info.model.clone();
    m.threads = info.threads;

    let transcript = match engine.transcribe(&trimmed, &hint) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(utterance_id, "inference failed: {e}");
            println!("  [#{utterance_id} inference error: {e}]");
            m.verdict = "inference_error".into();
            return (None, m);
        }
    };
    m.trimmed_audio_secs = transcript.audio_secs;
    m.infer_ms = transcript.inference.as_secs_f64() * 1000.0;
    m.no_speech_prob = transcript.max_no_speech;

    tracing::info!(
        utterance_id,
        raw_secs,
        trimmed_secs = transcript.audio_secs,
        infer_ms = transcript.inference.as_secs_f64() * 1000.0,
        no_speech = transcript.max_no_speech,
        "transcribed"
    );

    match postprocess::judge(&transcript) {
        postprocess::Verdict::Accept => {
            m.verdict = "accepted".into();
            (Some(transcript.text), m)
        }
        postprocess::Verdict::Reject(reason) => {
            m.verdict = reason.as_str().to_string();
            tracing::info!(utterance_id, reason = reason.as_str(), "rejected as non-speech");
            println!("  [#{utterance_id} filtered: {}]", reason.as_str());
            (None, m)
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
fn deliver(job: DeliverJob, cb: &mut dyn ClipboardPort, log: &session_log::SessionLog) {
    // ORDER MATTERS. Sanitize the raw model output first - it legitimately trims stray
    // leading/trailing whitespace - and only then apply the join separator. Doing it the
    // other way round added a space and then trimmed it back off, which glued every pair
    // of consecutive dictations together.
    let (sanitized, report) = sanitize::sanitize(&job.text);
    if !report.is_clean() {
        tracing::info!(utterance_id = job.utterance_id, ?report, "sanitizer modified text");
    }
    let clean = postprocess::apply_join(&sanitized, job.join);

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

    // Everything below records to the session log, including refusals. A log of only
    // successful dictations is survivorship-biased by construction: the interesting
    // records are the ones where text did NOT reach the target.
    let mut rec = session_log::UtteranceRecord {
        utterance_id: job.utterance_id,
        at: session_log::now_rfc3339(),
        hold_ms: job.hold.as_millis() as u64,
        end_cause: job.end_cause.as_str().to_string(),
        device_rate: job.device_rate,
        raw_audio_secs: job.metrics.raw_audio_secs,
        trimmed_audio_secs: job.metrics.trimmed_audio_secs,
        ring_overruns: job.ring_overruns,
        stream_errors: job.stream_errors,
        model: job.metrics.model.clone(),
        threads: job.metrics.threads,
        resample_ms: job.metrics.resample_ms,
        vad_ms: job.metrics.vad_ms,
        infer_ms: job.metrics.infer_ms,
        no_speech_prob: job.metrics.no_speech_prob,
        word_count: clean.split_whitespace().count(),
        verdict: job.metrics.verdict.clone(),
        target_exe: now.as_ref().map(|t| t.exe.clone()).unwrap_or_default(),
        target_title: now.as_ref().map(|t| t.title.clone()).unwrap_or_default(),
        target_password_state: now
            .as_ref()
            .map(|t| t.password.as_str().to_string())
            .unwrap_or_else(|| "unknown".into()),
        target_elevated: now.as_ref().map(|t| t.elevated).unwrap_or(false),
        on_battery: session_log::on_battery(),
        release_to_delivered_ms: job.released_at.elapsed().as_secs_f64() * 1000.0,
        text: Some(clean.clone()),
        ..Default::default()
    };

    match preflight::preflight(&req) {
        Decision::Inject(clearance) => {
            rec.decision = "inject".into();
            rec.inject_method = Some(format!("{:?}", clearance.method).to_lowercase());
            let guard = MainGuard;
            let outcome = inject::inject(clearance, &clean, &guard, cb);
            rec.inject_outcome = Some(match &outcome {
                inject::InjectOutcome::Injected { .. } => "injected".into(),
                inject::InjectOutcome::ClipboardOnly { reason } => format!("clipboard:{reason}"),
                inject::InjectOutcome::Aborted { reason, .. } => format!("aborted:{reason}"),
                inject::InjectOutcome::Failed { .. } => "failed".to_string(),
            });
            tracing::info!(utterance_id = job.utterance_id, ?outcome, "delivered");
            println!("  [#{} {:?}]", job.utterance_id, outcome);
        }
        Decision::ClipboardOnly(reason) => {
            rec.decision = "clipboard_only".into();
            rec.decision_reason = Some(reason.as_str().to_string());
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
            rec.decision = "drop".into();
            rec.decision_reason = Some(reason.as_str().to_string());
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

    log.record(rec);
}

fn run_daemon(canned: String, fake_latency: Duration, model: Option<String>, threads: i32) {
    let main_thread = unsafe { GetCurrentThreadId() };

    // Build the real pipeline if a model was given. Failure here is not fatal: falling
    // back to canned text keeps the I/O half of the daemon usable and testable, which is
    // more useful than refusing to start.
    let pipeline = match model {
        Some(path) => {
            println!("loading model: {path}");
            let vad_path = "models/ggml-silero-v6.2.0.bin";
            match backend::WhisperCppBackend::new(
                &path,
                Some(vad_path),
                threads,
                false,
            ) {
                Ok(mut b) => {
                    use backend::TranscriptionBackend;
                    println!("  vad: {}", if b.has_vad() { "enabled" } else { "MISSING - no silence trimming" });
                    print!("  warming... ");
                    use std::io::Write;
                    let _ = std::io::stdout().flush();
                    let t0 = Instant::now();
                    match b.warm() {
                        Ok(()) => println!("{:?}", t0.elapsed()),
                        Err(e) => println!("failed: {e}"),
                    }

                    match audio::start(None) {
                        Ok(cap) => {
                            let rate = cap.device_rate();
                            println!("  audio: {rate} Hz, preroll {} frames", audio::preroll_frames(rate));
                            Some(Pipeline {
                                backend: Box::new(b),
                                capture: cap,
                                device_rate: rate,
                                preroll: audio::PrerollRing::new(audio::preroll_frames(rate)),
                                utterance: Vec::with_capacity(rate as usize * 30),
                                scratch: Vec::with_capacity(8192),
                                capturing: false,
                                prev: None,
                            })
                        }
                        Err(e) => {
                            eprintln!("  audio FAILED: {e}");
                            eprintln!("  falling back to canned text");
                            None
                        }
                    }
                }
                Err(e) => {
                    eprintln!("  model load FAILED: {e}");
                    eprintln!("  falling back to canned text");
                    None
                }
            }
        }
        None => None,
    };
    let has_pipeline = pipeline.is_some();

    let (ptt_tx, ptt_rx) = bounded::<PttEvent>(64);
    let (job_tx, job_rx) = bounded::<DeliverJob>(8);

    if let Err(e) = hook::install(ptt_tx, policy::DEFAULT_PTT_VK) {
        eprintln!("FATAL: {e}");
        std::process::exit(1);
    }

    let worker = std::thread::Builder::new()
        .name("whisperrust-worker".into())
        .spawn(move || {
            worker_main(
                WorkerCtx {
                    rx: ptt_rx,
                    jobs: job_tx,
                    main_thread,
                    canned,
                    fake_latency,
                },
                pipeline,
            )
        })
        .expect("spawn worker");

    let mut cb = clipboard::WinClipboard::new();

    // Text logging is OPT-IN and off by default.
    //
    // Audio retention is on (PLAN 10.5) for the voice-style work, but the transcript is
    // the more directly sensitive artifact: it is searchable, and on this machine it may
    // contain client-confidential material. Metadata is always recorded - it is what makes
    // the log useful for latency, WPM and failure analysis, and it carries none of the
    // content risk.
    let log_text = std::env::args().any(|a| a == "--log-text");
    let session = session_log::SessionLog::open(log_text);
    println!(
        "session log  : {}{}",
        session.path().display(),
        if log_text { "   (TEXT LOGGING ENABLED)" } else { "" }
    );
    let mut last_liveness = Instant::now();
    let mut last_health = Instant::now();

    if has_pipeline {
        println!("Listening. Hold RIGHT CTRL, speak, release.");
    } else {
        println!("Listening (NO MODEL - canned text). Hold RIGHT CTRL, then release.");
    }
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
            deliver(job, &mut cb, &session);
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

    // Analytics over the session log (PLAN 7A.1).
    if args.iter().any(|a| a == "stats" || a == "--stats") {
        let wpm: f64 = args
            .iter()
            .position(|a| a == "--typing-wpm")
            .and_then(|i| args.get(i + 1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(65.0);
        std::process::exit(stats::run(wpm));
    }

    // Phase 2 verification: soak the audio path and print CP-2 numbers.
    if args.iter().any(|a| a == "--audio-check") {
        let secs: u64 = args
            .iter()
            .position(|a| a == "--audio-check")
            .and_then(|i| args.get(i + 1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);
        let out = format!("evidence/phase-2");
        std::process::exit(audiocheck::run(secs, &out));
    }

    // List input devices, so a mic-selection problem is diagnosable.
    if args.iter().any(|a| a == "--devices") {
        use cpal::traits::{DeviceTrait, HostTrait};
        let host = cpal::default_host();
        let default = host
            .default_input_device()
            .and_then(|d| d.description().ok().map(|x| x.name().to_string()));
        println!("default input: {}", default.unwrap_or_else(|| "<none>".into()));
        if let Ok(devs) = host.input_devices() {
            for d in devs {
                let name = d.description().ok().map(|x| x.name().to_string()).unwrap_or_default();
                let rates: Vec<String> = d
                    .supported_input_configs()
                    .map(|cs| {
                        cs.take(4)
                            .map(|c| format!("{}-{}Hz x{}", c.min_sample_rate(), c.max_sample_rate(), c.channels()))
                            .collect()
                    })
                    .unwrap_or_default();
                println!("  {name}");
                for r in rates {
                    println!("      {r}");
                }
            }
        }
        return;
    }

    // One-shot diagnostic: where would text go right now, and how?
    if args.iter().any(|a| a == "--probe") {
        match target::probe() {
            Some(c) => {
                println!("exe        : {}", c.exe);
                println!("title      : {}", c.title);
                println!("hwnd       : {:#x}", c.hwnd);
                println!("focus hwnd : {:?}", c.focus_hwnd);
                println!("elevated   : {}", c.elevated);
                println!("password   : {}", c.password.as_str());
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

    let model = args
        .iter()
        .position(|a| a == "--model")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .or_else(|| {
            // Convenience: pick up a model sitting in models/ without being told.
            for candidate in [
                "models/ggml-base.en.bin",
                "models/ggml-small.en-q5_1.bin",
                "models/ggml-tiny.en.bin",
            ] {
                if std::path::Path::new(candidate).exists() {
                    return Some(candidate.to_string());
                }
            }
            None
        });

    // 8 threads measured best on this hybrid P/E CPU; 14 was 23x slower (docs/TOOLING.md
    // trap #6). Never default to "all logical processors".
    let threads: i32 = args
        .iter()
        .position(|a| a == "--threads")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(8);

    install_ctrlc_handler();

    match &model {
        Some(m) => println!("WhisperRust - Phase 3 (model: {m}, {threads} threads)"),
        None => println!("WhisperRust - no model found; canned-text mode"),
    }
    println!();

    run_daemon(canned, Duration::from_millis(latency_ms), model, threads);
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
