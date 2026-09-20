//! The low-level keyboard hook.
//!
//! This is the most dangerous code in the program, for three reasons:
//!
//! 1. **It runs on every keystroke the user types, system-wide.** If it is slow, the whole
//!    machine feels slow. Windows silently unregisters a `WH_KEYBOARD_LL` hook whose
//!    procedure exceeds `LowLevelHooksTimeout` (<= 1000 ms) — with no notification, no
//!    error, nothing. The app simply stops responding to the hotkey forever.
//!
//! 2. **It can make the machine feel broken.** A hook that swallows keys and then wedges
//!    takes the user's keyboard with it. Hence [`HEALTHY`]: if the worker stops heart-
//!    beating, the hook goes fully transparent.
//!
//! 3. **It sees every keystroke, including passwords.** This module therefore looks at
//!    exactly one virtual-key code and never stores, logs or forwards anything else.
//!    There is no buffer here for a reason.
//!
//! ## The rule
//!
//! The hook procedure does no allocation, no logging, no locking and no syscalls beyond
//! `CallNextHookEx`. It reads two atomics and does a non-blocking channel send. Everything
//! slow happens on the worker thread.
//!
//! ## I-13 — never swallow
//!
//! Measured in Phase 0 (`docs/SPIKE-PTT-ORACLE.md`): returning 1 from this procedure stops
//! the key reaching the key-state tables, blinding both `GetAsyncKeyState` and
//! `GetKeyState`. The stuck-key watchdog depends on those, so swallowing would make every
//! capture die ~50 ms in. We always chain.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crossbeam_channel::Sender;
use windows::Win32::Foundation::{HMODULE, LPARAM, LRESULT, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, SetWindowsHookExW, UnhookWindowsHookEx, HHOOK, KBDLLHOOKSTRUCT,
    LLKHF_INJECTED, WH_KEYBOARD_LL, WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP,
};

use crate::policy;

/// What the hook tells the worker. Deliberately tiny and `Copy` — nothing that needs
/// allocation crosses this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PttEvent {
    Down,
    Up,
    /// The kill chord fired: PTT tapped `KILL_CHORD_TAPS` times inside the window.
    KillChord,
    /// Watchdog A's liveness probe was observed, proving the hook is still installed.
    LivenessPong,
}

// ---------------------------------------------------------------------------------------
// Hook-visible state. All atomics: the hook procedure must never block.
// ---------------------------------------------------------------------------------------

/// When false the hook becomes fully transparent and reports nothing.
///
/// Set false when the worker heartbeat goes stale. This is the promise that a sick daemon
/// can never make the user's keyboard feel broken.
pub static HEALTHY: AtomicBool = AtomicBool::new(true);

/// Virtual-key code of the PTT binding.
static PTT_VK: AtomicU32 = AtomicU32::new(policy::DEFAULT_PTT_VK as u32);

/// True while we believe the PTT key is held, used to squash autorepeat.
static HELD: AtomicBool = AtomicBool::new(false);

/// Monotonic counter of key-downs; lets the worker detect missed events.
static DOWN_COUNT: AtomicU64 = AtomicU64::new(0);

/// Set by Watchdog A before sending its probe, cleared when the hook sees it.
static LIVENESS_PENDING: AtomicBool = AtomicBool::new(false);

/// Sender to the worker. Written once at install time.
static mut TX: Option<Sender<PttEvent>> = None;
static mut HOOK: Option<HHOOK> = None;

/// Kill-chord tap timestamps, as millis since an arbitrary epoch. Fixed-size ring so the
/// hook never allocates.
static TAP_TIMES: [AtomicU64; policy::KILL_CHORD_TAPS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static TAP_IDX: AtomicU32 = AtomicU32::new(0);

/// Millisecond clock for the hook. `GetTickCount64` is a plain read of a shared page —
/// no syscall transition, which is what we need on this path.
fn now_ms() -> u64 {
    unsafe { windows::Win32::System::SystemInformation::GetTickCount64() }
}

/// Record a tap and report whether the kill chord just completed.
fn record_tap_and_check() -> bool {
    let now = now_ms();
    let idx = (TAP_IDX.fetch_add(1, Ordering::Relaxed) as usize) % policy::KILL_CHORD_TAPS;
    TAP_TIMES[idx].store(now, Ordering::Relaxed);

    let window = policy::KILL_CHORD_WINDOW.as_millis() as u64;
    let recent = TAP_TIMES
        .iter()
        .filter(|t| {
            let v = t.load(Ordering::Relaxed);
            v != 0 && now.saturating_sub(v) <= window
        })
        .count();

    recent >= policy::KILL_CHORD_TAPS
}

/// The hook procedure.
///
/// # Safety
/// Called by Windows on the thread that installed the hook. Everything here must be
/// non-blocking and allocation-free.
unsafe extern "system" fn hook_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    // Negative code means "do not process, just chain" per the Win32 contract.
    if code < 0 {
        return CallNextHookEx(None, code, wparam, lparam);
    }

    // Degraded mode: be completely transparent. Checked FIRST so a sick daemon costs the
    // user nothing but a branch.
    if !HEALTHY.load(Ordering::Relaxed) {
        return CallNextHookEx(None, code, wparam, lparam);
    }

    let kb = &*(lparam.0 as *const KBDLLHOOKSTRUCT);
    let vk = PTT_VK.load(Ordering::Relaxed);

    // Watchdog A's liveness pong. Checked BEFORE the PTT comparison because the probe
    // deliberately uses an inert key, not the PTT key - pressing the real PTT key to
    // prove the hook is alive would fabricate a dictation.
    if kb.flags.contains(LLKHF_INJECTED)
        && kb.dwExtraInfo == policy::OUR_MAGIC
        && LIVENESS_PENDING.swap(false, Ordering::Relaxed)
    {
        if let Some(tx) = &*std::ptr::addr_of!(TX) {
            let _ = tx.try_send(PttEvent::LivenessPong);
        }
        return CallNextHookEx(None, code, wparam, lparam);
    }

    if kb.vkCode == vk {
        let msg = wparam.0 as u32;
        let is_down = msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN;
        let is_up = msg == WM_KEYUP || msg == WM_SYSKEYUP;

        // I-7: ignore our own synthetic input, and any other process's synthetic input,
        // so nobody can drive the PTT remotely.
        let injected = kb.flags.contains(LLKHF_INJECTED);
        if injected {
            // I-7: never treat synthetic input as a real PTT press, so no other process
            // can trigger a dictation.
            return CallNextHookEx(None, code, wparam, lparam);
        }

        if is_down {
            // Autorepeat: holding a key delivers dozens of WM_KEYDOWN. Only the first is
            // a press.
            if !HELD.swap(true, Ordering::Relaxed) {
                DOWN_COUNT.fetch_add(1, Ordering::Relaxed);
                if let Some(tx) = &*std::ptr::addr_of!(TX) {
                    let _ = tx.try_send(PttEvent::Down);
                }
            }
        } else if is_up {
            if HELD.swap(false, Ordering::Relaxed) {
                if let Some(tx) = &*std::ptr::addr_of!(TX) {
                    let _ = tx.try_send(PttEvent::Up);
                }
                if record_tap_and_check() {
                    // Clear the ring, or every subsequent key-up still sees a full
                    // window of recent taps and re-fires the chord forever.
                    for t in TAP_TIMES.iter() {
                        t.store(0, Ordering::Relaxed);
                    }
                    if let Some(tx) = &*std::ptr::addr_of!(TX) {
                        let _ = tx.try_send(PttEvent::KillChord);
                    }
                }
            }
        }

        // I-13: ALWAYS chain. Swallowing here blinds GetAsyncKeyState and breaks the
        // stuck-key watchdog. See docs/SPIKE-PTT-ORACLE.md.
        debug_assert!(!policy::SWALLOW_PTT_KEY, "I-13 violated");
    }

    CallNextHookEx(None, code, wparam, lparam)
}

/// Install the hook on the calling thread.
///
/// The calling thread must run a message pump, or the procedure is never invoked.
pub fn install(tx: Sender<PttEvent>, ptt_vk: u16) -> Result<(), String> {
    if policy::is_forbidden_ptt_vk(ptt_vk) {
        // I-12: binding one of these would take Ctrl+C/V/Z or Escape with it.
        return Err(format!(
            "vk {ptt_vk:#04x} is a forbidden PTT binding (policy::FORBIDDEN_PTT_VKS)"
        ));
    }

    unsafe {
        if HOOK.is_some() {
            return Err("hook already installed".into());
        }
        TX = Some(tx);
        PTT_VK.store(ptt_vk as u32, Ordering::Relaxed);
        HELD.store(false, Ordering::Relaxed);

        match SetWindowsHookExW(
            WH_KEYBOARD_LL,
            Some(hook_proc),
            Some(HMODULE::default().into()),
            0,
        ) {
            Ok(h) => {
                HOOK = Some(h);
                Ok(())
            }
            Err(e) => Err(format!("SetWindowsHookExW failed: {e}")),
        }
    }
}

pub fn uninstall() {
    unsafe {
        if let Some(h) = HOOK.take() {
            let _ = UnhookWindowsHookEx(h);
        }
        TX = None;
        HELD.store(false, Ordering::Relaxed);
    }
}

/// Re-install after a suspected silent unhook (Watchdog A).
pub fn reinstall(ptt_vk: u16) -> Result<(), String> {
    unsafe {
        let tx = (*std::ptr::addr_of!(TX)).clone();
        let Some(tx) = tx else {
            return Err("cannot reinstall: no sender".into());
        };
        if let Some(h) = HOOK.take() {
            let _ = UnhookWindowsHookEx(h);
        }
        install(tx, ptt_vk)
    }
}

/// Send Watchdog A's liveness probe and mark it in flight.
///
/// Windows unregisters a `WH_KEYBOARD_LL` hook whose procedure is too slow, with no
/// notification whatsoever. The only way to know we are still installed is to push an
/// event through the hook and see it come back.
///
/// The probe is a **key-UP for `VK_NONAME` (0xFC)**, an unassigned virtual key. A key-up
/// for a key that was never down is inert: no application acts on it, nothing is typed.
/// It is deliberately NOT the PTT key - synthesizing that to prove liveness would
/// fabricate a dictation - and it is tagged with `OUR_MAGIC` so the hook can recognize it.
pub fn send_liveness_probe() {
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, VIRTUAL_KEY,
    };
    const VK_NONAME: u16 = 0xFC;

    LIVENESS_PENDING.store(true, Ordering::Relaxed);

    let input = INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(VK_NONAME),
                wScan: 0,
                dwFlags: KEYEVENTF_KEYUP,
                time: 0,
                dwExtraInfo: policy::OUR_MAGIC,
            },
        },
    };
    unsafe {
        SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
    }
}

/// The virtual-key code currently bound to PTT.
pub fn ptt_vk() -> u16 {
    PTT_VK.load(Ordering::Relaxed) as u16
}

/// True if the probe has not come back yet.
pub fn liveness_probe_outstanding() -> bool {
    LIVENESS_PENDING.load(Ordering::Relaxed)
}

/// Is the PTT key physically down right now?
///
/// Valid ONLY because we never swallow (I-13). Phase 0 measured that a swallowed key
/// reads as UP here for the entire hold.
pub fn ptt_physically_down() -> bool {
    use windows::Win32::UI::Input::KeyboardAndMouse::GetAsyncKeyState;
    let vk = PTT_VK.load(Ordering::Relaxed) as i32;
    unsafe { (GetAsyncKeyState(vk) as u16 & 0x8000) != 0 }
}

/// Worker heartbeat. If this stops being called, the hook goes transparent.
pub struct Heartbeat {
    last: AtomicU64,
}

impl Heartbeat {
    pub const fn new() -> Self {
        Self { last: AtomicU64::new(0) }
    }
    pub fn beat(&self) {
        self.last.store(now_ms(), Ordering::Relaxed);
    }
    pub fn is_stale(&self) -> bool {
        let last = self.last.load(Ordering::Relaxed);
        if last == 0 {
            return false; // not started yet
        }
        now_ms().saturating_sub(last) > policy::WORKER_HEARTBEAT_STALE.as_millis() as u64
    }
    /// Update [`HEALTHY`] from the heartbeat. Called from the main thread's timer.
    pub fn refresh_health(&self) {
        let healthy = !self.is_stale();
        let was = HEALTHY.swap(healthy, Ordering::Relaxed);
        if was != healthy {
            if healthy {
                tracing::info!("worker recovered; hook active again");
            } else {
                tracing::error!(
                    "worker heartbeat stale > {:?}; hook now transparent",
                    policy::WORKER_HEARTBEAT_STALE
                );
            }
        }
    }
}

/// Watchdog B — the stuck-key detector.
///
/// If the PTT key is physically up but we never saw the key-up, synthesize one. The real
/// case this covers: the user presses PTT over Notepad and releases it over an elevated
/// window. UIPI means our hook never sees that key-up, and without this the state machine
/// stays in Capturing forever.
pub struct StuckKeyWatchdog {
    capturing_since: Option<Instant>,
}

impl StuckKeyWatchdog {
    pub fn new() -> Self {
        Self { capturing_since: None }
    }
    pub fn on_capture_start(&mut self) {
        self.capturing_since = Some(Instant::now());
    }
    pub fn on_capture_end(&mut self) {
        self.capturing_since = None;
    }

    /// Returns `Some(reason)` if the capture should be force-ended.
    pub fn poll(&self) -> Option<&'static str> {
        let since = self.capturing_since?;
        if since.elapsed() >= policy::MAX_CAPTURE {
            return Some("max_duration");
        }
        // Give the key a moment to register before trusting the oracle.
        if since.elapsed() > Duration::from_millis(150) && !ptt_physically_down() {
            return Some("stuck_key");
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_bindings_are_refused_at_install() {
        let (tx, _rx) = crossbeam_channel::bounded(4);
        // Left Ctrl would take Ctrl+C / Ctrl+V / Ctrl+Z with it.
        assert!(install(tx, 0xA2).is_err());
    }

    #[test]
    fn heartbeat_starts_healthy_before_first_beat() {
        let hb = Heartbeat::new();
        assert!(!hb.is_stale(), "must not report stale before the worker starts");
    }

    #[test]
    fn heartbeat_is_fresh_after_a_beat() {
        let hb = Heartbeat::new();
        hb.beat();
        assert!(!hb.is_stale());
    }

    #[test]
    fn kill_chord_needs_taps_within_the_window() {
        for t in TAP_TIMES.iter() {
            t.store(0, Ordering::Relaxed);
        }
        TAP_IDX.store(0, Ordering::Relaxed);
        // One tap short of the chord.
        for _ in 0..policy::KILL_CHORD_TAPS - 1 {
            assert!(!record_tap_and_check());
        }
        // The last one completes it.
        assert!(record_tap_and_check());
    }

    #[test]
    fn watchdog_reports_nothing_when_idle() {
        let w = StuckKeyWatchdog::new();
        assert_eq!(w.poll(), None);
    }

    #[test]
    fn liveness_probe_is_actually_sent_not_just_armed() {
        // Regression, observed live: arm_liveness_probe() set the pending flag but nothing
        // ever pushed an event through the hook, so the probe was permanently
        // "unanswered" and Watchdog A tore down and reinstalled the hook every 30s.
        // The log showed "hook liveness probe unanswered; reinstalling" during normal use.
        let src = include_str!("hook.rs");
        let body = src.split("#[cfg(test)]").next().unwrap();
        assert!(
            body.contains("fn send_liveness_probe"),
            "the probe must be sent, not merely armed"
        );
        assert!(
            body.contains("SendInput") && body.contains("LIVENESS_PENDING.store(true"),
            "send_liveness_probe must both arm the flag and emit an event"
        );
    }

    #[test]
    fn kill_chord_ring_is_cleared_after_firing() {
        // Regression: without clearing, every later key-up still saw a full window of
        // recent taps and re-fired the chord.
        let src = include_str!("hook.rs");
        let body = src.split("#[cfg(test)]").next().unwrap();
        let fired = body
            .split("if record_tap_and_check()")
            .nth(1)
            .expect("kill chord branch present");
        let branch = &fired[..fired.len().min(400)];
        assert!(
            branch.contains("t.store(0"),
            "tap ring must be cleared when the chord fires"
        );
    }

    #[test]
    fn i13_is_enforced_in_this_module() {
        // Structural: the hook must never contain a swallow return.
        let src = include_str!("hook.rs");
        let body = src.split("#[cfg(test)]").next().unwrap();
        assert!(
            !body.contains("return LRESULT(1)"),
            "I-13 violated: hook returns 1 somewhere (see docs/SPIKE-PTT-ORACLE.md)"
        );
    }
}
