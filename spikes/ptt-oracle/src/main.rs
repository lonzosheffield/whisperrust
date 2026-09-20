//! Phase 0 spike — PTT state oracle.
//!
//! QUESTION THIS ANSWERS
//! ---------------------
//! PLAN.md §0.2 claims Watchdog B is built on a false premise. The daemon's keyboard hook
//! *swallows* the PTT key (returns 1) so applications never see a bare Ctrl. The claim is
//! that a swallowed key never reaches the asynchronous key-state table, so
//! `GetAsyncKeyState` would report UP for the entire hold — which would make Watchdog B
//! fire ~50 ms into every capture and kill every dictation before it started.
//!
//! If true, the swallow decision and the stuck-key oracle are coupled, and the state
//! machine cannot be written until we know which of three options is viable:
//!
//!   A. Do not swallow            -> GetAsyncKeyState is a valid oracle, apps see a bare Ctrl
//!   B. Swallow + Raw Input       -> correct regardless, more code
//!   C. Dead key, not swallowed   -> no shortcut consumed
//!
//! METHOD
//! ------
//! Install a real `WH_KEYBOARD_LL` hook, drive a key down/up cycle, and sample
//! `GetAsyncKeyState` / `GetKeyState` throughout the hold. Run the whole thing twice:
//! once with the hook passing keys through, once with it swallowing them. Compare.
//!
//! Default mode synthesizes the keystroke with `SendInput` so the test is reproducible and
//! needs no human. `--manual` waits for a real physical hold, because synthetic input is
//! only *probably* equivalent here and the physical path is what ships.
//!
//! SAFETY
//! ------
//! A stuck modifier is exactly the "machine feels bricked" failure this project is trying
//! to avoid. Every path that presses a key also releases it, including on panic.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{HMODULE, LPARAM, LRESULT, WPARAM};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, GetKeyState, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT,
    KEYBD_EVENT_FLAGS, KEYEVENTF_KEYUP, VIRTUAL_KEY, VK_PAUSE, VK_RCONTROL, VK_SCROLL,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, DispatchMessageW, PostQuitMessage, SetWindowsHookExW,
    TranslateMessage, UnhookWindowsHookEx, HHOOK, KBDLLHOOKSTRUCT, LLKHF_INJECTED, MSG,
    WH_KEYBOARD_LL, WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP,
};

/// Tags our own synthetic input so the hook can tell it apart from a human.
const OUR_MAGIC: usize = 0x5748_5250; // "WHRP"

/// When true the hook returns 1 (swallow) instead of chaining.
static SWALLOW: AtomicBool = AtomicBool::new(false);
/// Virtual-key code currently under test.
static TEST_VK: AtomicU32 = AtomicU32::new(0);

// Counters observed by the hook itself.
static SAW_DOWN: AtomicU32 = AtomicU32::new(0);
static SAW_UP: AtomicU32 = AtomicU32::new(0);
static SAW_INJECTED: AtomicU32 = AtomicU32::new(0);

static mut HOOK: Option<HHOOK> = None;

unsafe extern "system" fn hook_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code >= 0 {
        let kb = &*(lparam.0 as *const KBDLLHOOKSTRUCT);
        let vk = TEST_VK.load(Ordering::Relaxed);

        if kb.vkCode == vk {
            let msg = wparam.0 as u32;
            let is_down = msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN;
            let is_up = msg == WM_KEYUP || msg == WM_SYSKEYUP;

            if kb.flags.contains(LLKHF_INJECTED) {
                SAW_INJECTED.fetch_add(1, Ordering::Relaxed);
            }
            if is_down {
                SAW_DOWN.fetch_add(1, Ordering::Relaxed);
            }
            if is_up {
                SAW_UP.fetch_add(1, Ordering::Relaxed);
            }

            if SWALLOW.load(Ordering::Relaxed) {
                // The whole point: tell Windows this key event stops here.
                return LRESULT(1);
            }
        }
    }
    CallNextHookEx(None, code, wparam, lparam)
}

/// One sample of every state source we might use as an oracle.
#[derive(Debug, Clone, Copy)]
struct Sample {
    at_ms: u128,
    async_down: bool,
    sync_down: bool,
}

fn sample(vk: VIRTUAL_KEY, t0: Instant) -> Sample {
    // GetAsyncKeyState: high bit = currently down.
    let a = unsafe { GetAsyncKeyState(vk.0 as i32) };
    // GetKeyState: reflects the calling thread's message-queue view of the key.
    let s = unsafe { GetKeyState(vk.0 as i32) };
    Sample {
        at_ms: t0.elapsed().as_millis(),
        async_down: (a as u16 & 0x8000) != 0,
        sync_down: (s as u16 & 0x8000) != 0,
    }
}

/// Press or release a key via SendInput, tagged with OUR_MAGIC.
fn send_key(vk: VIRTUAL_KEY, up: bool) {
    let flags = if up {
        KEYEVENTF_KEYUP
    } else {
        KEYBD_EVENT_FLAGS(0)
    };
    let input = INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: 0,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: OUR_MAGIC,
            },
        },
    };
    unsafe {
        SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
    }
}

/// Guarantees the key goes back up even if something below panics.
struct KeyGuard(VIRTUAL_KEY);
impl Drop for KeyGuard {
    fn drop(&mut self) {
        send_key(self.0, true);
    }
}

/// Pump pending messages so the hook actually gets called.
fn pump_briefly(ms: u64) {
    let deadline = Instant::now() + Duration::from_millis(ms);
    while Instant::now() < deadline {
        let mut msg = MSG::default();
        // PeekMessage-style drain via GetMessage would block; use a short sleep + peek loop.
        unsafe {
            while windows::Win32::UI::WindowsAndMessaging::PeekMessageW(
                &mut msg,
                None,
                0,
                0,
                windows::Win32::UI::WindowsAndMessaging::PM_REMOVE,
            )
            .as_bool()
            {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

struct TrialResult {
    label: String,
    vk_name: String,
    swallow: bool,
    hook_saw_down: u32,
    hook_saw_up: u32,
    hook_saw_injected: u32,
    samples: Vec<Sample>,
}

impl TrialResult {
    fn async_ever_down(&self) -> bool {
        self.samples.iter().any(|s| s.async_down)
    }
    fn sync_ever_down(&self) -> bool {
        self.samples.iter().any(|s| s.sync_down)
    }
}

fn run_trial(vk: VIRTUAL_KEY, vk_name: &str, swallow: bool, hold_ms: u64) -> TrialResult {
    SWALLOW.store(swallow, Ordering::Relaxed);
    TEST_VK.store(vk.0 as u32, Ordering::Relaxed);
    SAW_DOWN.store(0, Ordering::Relaxed);
    SAW_UP.store(0, Ordering::Relaxed);
    SAW_INJECTED.store(0, Ordering::Relaxed);

    let t0 = Instant::now();
    let mut samples = Vec::new();

    {
        send_key(vk, false);
        let _guard = KeyGuard(vk); // key comes back up no matter what

        let deadline = Instant::now() + Duration::from_millis(hold_ms);
        while Instant::now() < deadline {
            pump_briefly(20);
            samples.push(sample(vk, t0));
        }
    } // guard drops -> key up

    pump_briefly(60);
    samples.push(sample(vk, t0));

    TrialResult {
        label: if swallow { "SWALLOW" } else { "PASSTHROUGH" }.to_string(),
        vk_name: vk_name.to_string(),
        swallow,
        hook_saw_down: SAW_DOWN.load(Ordering::Relaxed),
        hook_saw_up: SAW_UP.load(Ordering::Relaxed),
        hook_saw_injected: SAW_INJECTED.load(Ordering::Relaxed),
        samples,
    }
}

fn run_manual(vk: VIRTUAL_KEY, vk_name: &str, swallow: bool) -> TrialResult {
    SWALLOW.store(swallow, Ordering::Relaxed);
    TEST_VK.store(vk.0 as u32, Ordering::Relaxed);
    SAW_DOWN.store(0, Ordering::Relaxed);
    SAW_UP.store(0, Ordering::Relaxed);
    SAW_INJECTED.store(0, Ordering::Relaxed);

    println!(
        "\n  >>> HOLD {} down for ~3 seconds, then release. Mode: {}",
        vk_name,
        if swallow { "SWALLOW" } else { "PASSTHROUGH" }
    );
    println!("      (waiting up to 15s for a key-down...)");

    let t0 = Instant::now();
    let mut samples = Vec::new();
    let wait_deadline = Instant::now() + Duration::from_secs(15);

    // Wait for the hook to observe a physical key-down.
    while SAW_DOWN.load(Ordering::Relaxed) == 0 && Instant::now() < wait_deadline {
        pump_briefly(20);
    }
    if SAW_DOWN.load(Ordering::Relaxed) == 0 {
        println!("      no key-down observed; skipping this trial.");
    } else {
        println!("      key-down seen, sampling...");
        while SAW_UP.load(Ordering::Relaxed) == 0 && t0.elapsed() < Duration::from_secs(10) {
            pump_briefly(20);
            samples.push(sample(vk, t0));
        }
        println!("      key-up seen after {} ms.", t0.elapsed().as_millis());
    }

    TrialResult {
        label: if swallow { "SWALLOW" } else { "PASSTHROUGH" }.to_string(),
        vk_name: vk_name.to_string(),
        swallow,
        hook_saw_down: SAW_DOWN.load(Ordering::Relaxed),
        hook_saw_up: SAW_UP.load(Ordering::Relaxed),
        hook_saw_injected: SAW_INJECTED.load(Ordering::Relaxed),
        samples,
    }
}

fn report(results: &[TrialResult]) {
    println!("\n================ RESULTS ================\n");
    println!(
        "{:<14} {:<12} {:>5} {:>5} {:>4} {:>12} {:>11}",
        "KEY", "MODE", "DOWN", "UP", "INJ", "ASYNC_DOWN?", "SYNC_DOWN?"
    );
    println!("{}", "-".repeat(72));
    for r in results {
        println!(
            "{:<14} {:<12} {:>5} {:>5} {:>4} {:>12} {:>11}",
            r.vk_name,
            r.label,
            r.hook_saw_down,
            r.hook_saw_up,
            r.hook_saw_injected,
            if r.async_ever_down() { "YES" } else { "NO" },
            if r.sync_ever_down() { "YES" } else { "NO" },
        );
    }

    println!("\n---------------- VERDICT ----------------\n");

    let swallowed: Vec<_> = results.iter().filter(|r| r.swallow).collect();
    let passthrough: Vec<_> = results.iter().filter(|r| !r.swallow).collect();

    let swallow_blinds_async = swallowed
        .iter()
        .any(|r| r.hook_saw_down > 0 && !r.async_ever_down());
    let passthrough_async_ok = passthrough.iter().any(|r| r.async_ever_down());

    if swallow_blinds_async {
        println!("  CONFIRMED: swallowing the key BLINDS GetAsyncKeyState.");
        println!("  The hook observed key-down, but GetAsyncKeyState never reported it down.");
        println!("  => PLAN.md 0.2 is correct. Watchdog B as specified would kill every capture.");
        println!("  => Choose option A (do not swallow) or B (Raw Input oracle).");
    } else if passthrough_async_ok
        && swallowed
            .iter()
            .all(|r| r.hook_saw_down == 0 || r.async_ever_down())
    {
        println!("  REFUTED: GetAsyncKeyState reported the key DOWN even while swallowed.");
        println!("  => Watchdog B is viable as originally specified.");
    } else {
        println!("  INCONCLUSIVE - see the table above.");
        println!("  (If DOWN==0 everywhere, the hook never fired: check for a blocking");
        println!("   message pump, or an elevated foreground window eating the input.)");
    }

    println!("\n  Sample timelines (first 6 per trial):");
    for r in results {
        let head: Vec<String> = r
            .samples
            .iter()
            .take(6)
            .map(|s| {
                format!(
                    "{}ms:{}{}",
                    s.at_ms,
                    if s.async_down { "A" } else { "-" },
                    if s.sync_down { "S" } else { "-" }
                )
            })
            .collect();
        println!("    {:<14} {:<12} {}", r.vk_name, r.label, head.join(" "));
    }
    println!();
}

fn main() {
    let manual = std::env::args().any(|a| a == "--manual");

    println!("PTT oracle spike - PLAN.md 0.2");
    println!("Installing WH_KEYBOARD_LL hook...");

    unsafe {
        match SetWindowsHookExW(
            WH_KEYBOARD_LL,
            Some(hook_proc),
            Some(HMODULE::default().into()),
            0,
        ) {
            Ok(h) => HOOK = Some(h),
            Err(e) => {
                eprintln!("FATAL: SetWindowsHookExW failed: {e}");
                std::process::exit(2);
            }
        }
    }
    println!("Hook installed.\n");

    let mut results = Vec::new();

    if manual {
        results.push(run_manual(VK_RCONTROL, "VK_RCONTROL", false));
        results.push(run_manual(VK_RCONTROL, "VK_RCONTROL", true));
    } else {
        println!("Synthetic mode (SendInput). Use --manual for a physical-key run.\n");
        for (vk, name) in [
            (VK_RCONTROL, "VK_RCONTROL"),
            (VK_SCROLL, "VK_SCROLL"),
            (VK_PAUSE, "VK_PAUSE"),
        ] {
            for swallow in [false, true] {
                println!("  trial: {name} swallow={swallow}");
                results.push(run_trial(vk, name, swallow, 400));
                std::thread::sleep(Duration::from_millis(150));
            }
        }
    }

    unsafe {
        if let Some(h) = HOOK {
            let _ = UnhookWindowsHookEx(h);
        }
        PostQuitMessage(0);
    }

    report(&results);
}
