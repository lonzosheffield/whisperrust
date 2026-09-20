//! The injection decision — invariant I-3.
//!
//! **`preflight()` is the ONLY thing permitted to authorize an injection.** `inject()`
//! takes a [`Clearance`], and the only way to obtain one is from this module. That makes
//! the entire "should this text leave the app" decision a single, ordered, testable
//! function instead of a scatter of `if` statements across the codebase.
//!
//! The checks are ORDERED, and the order matters: the cheapest and most dangerous
//! conditions are evaluated first, and the first failure wins so the recorded reason is
//! the most severe one.
//!
//! Default posture (I-9): **when unsure, do not inject.** Every ambiguous case degrades to
//! clipboard-only or drop, never to "paste anyway".

use std::time::{Duration, Instant};

use crate::policy::{self, InjectMethod};
use crate::target::TargetContext;

/// What preflight decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Safe to inject into the recorded target.
    Inject(Clearance),
    /// Not safe to type, but safe to leave on the clipboard for the user to paste.
    ClipboardOnly(Reason),
    /// Not safe to put anywhere. The text is discarded.
    Drop(Reason),
}

/// Proof that [`preflight`] authorized an injection.
///
/// Deliberately has no public constructor: `inject()` cannot be called without going
/// through preflight. The field is private and only this module can build one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clearance {
    pub method: InjectMethod,
    pub target_hwnd: isize,
    pub exe: String,
    pub char_len: usize,
    _private: (),
}

/// Why injection was refused. Recorded verbatim in the session log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Text was empty after sanitization.
    EmptyText,
    /// Hold was shorter than MIN_HOLD - an accidental tap.
    HoldTooShort,
    /// No foreground window at all.
    NoForegroundWindow,
    /// The user moved to a different window or field while we were transcribing.
    ForegroundChanged,
    /// Target process is elevated; UIPI would silently drop our input (I-1).
    TargetElevated,
    /// Focused control is a masked password field (I-8).
    PasswordField,
    /// Capture did not end with the user's own key-up (I-6).
    SynthesizedEnd,
    /// User is holding modifiers; injecting now would send Ctrl+Shift+V or similar.
    ModifiersHeld,
    /// Daemon is in a degraded state (worker heartbeat stale, kill chord fired).
    DaemonUnhealthy,
    /// Config put this app on the deny list.
    AppDenied,
}

impl Reason {
    /// Text shown to the user in the tray toast.
    pub fn user_message(&self) -> &'static str {
        match self {
            Reason::EmptyText => "Nothing to type",
            Reason::HoldTooShort => "Too short - ignored",
            Reason::NoForegroundWindow => "Copied - no active window",
            Reason::ForegroundChanged => "Copied - window changed",
            Reason::TargetElevated => "Copied - target needs admin",
            Reason::PasswordField => "Discarded - password field",
            Reason::SynthesizedEnd => "Copied - capture ended unexpectedly",
            Reason::ModifiersHeld => "Copied - modifier key held",
            Reason::DaemonUnhealthy => "Copied - daemon degraded",
            Reason::AppDenied => "Copied - app on deny list",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Reason::EmptyText => "empty_text",
            Reason::HoldTooShort => "hold_too_short",
            Reason::NoForegroundWindow => "no_foreground_window",
            Reason::ForegroundChanged => "foreground_changed",
            Reason::TargetElevated => "target_elevated",
            Reason::PasswordField => "password_field",
            Reason::SynthesizedEnd => "synthesized_end",
            Reason::ModifiersHeld => "modifiers_held",
            Reason::DaemonUnhealthy => "daemon_unhealthy",
            Reason::AppDenied => "app_denied",
        }
    }
}

/// How the capture ended. Drives I-6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndCause {
    /// The user released the PTT key. The only cause that permits injection.
    UserKeyUp,
    /// Watchdog B decided the key was physically up but we never saw the key-up.
    StuckKeyWatchdog,
    /// MAX_CAPTURE elapsed.
    MaxDuration,
    /// Daemon shutting down.
    Shutdown,
}

impl EndCause {
    pub fn as_str(&self) -> &'static str {
        match self {
            EndCause::UserKeyUp => "user_key_up",
            EndCause::StuckKeyWatchdog => "stuck_key_watchdog",
            EndCause::MaxDuration => "max_duration",
            EndCause::Shutdown => "shutdown",
        }
    }
}

/// Everything preflight needs. Passing a struct keeps the function pure and testable —
/// no Win32 calls happen inside `preflight` itself.
pub struct Request<'a> {
    pub text: &'a str,
    pub hold: Duration,
    pub end_cause: EndCause,
    /// Target recorded when the capture ended.
    pub target_at_capture: Option<&'a TargetContext>,
    /// Target sampled again immediately before injecting.
    pub target_now: Option<&'a TargetContext>,
    /// Modifier keys physically down right now.
    pub modifiers_held: bool,
    /// Worker heartbeat fresh and kill chord not fired.
    pub healthy: bool,
    /// App is on the configured deny list.
    pub app_denied: bool,
}

/// The single authorization point for injection.
///
/// Pure: no syscalls, no I/O, no clock reads. Everything it needs is in [`Request`], which
/// is what makes the eleven checks exhaustively testable.
pub fn preflight(req: &Request) -> Decision {
    // 1. Nothing to do. Cheapest check first.
    if req.text.trim().is_empty() {
        return Decision::Drop(Reason::EmptyText);
    }

    // 2. Accidental tap. Checked before anything expensive.
    if req.hold < policy::MIN_HOLD {
        return Decision::Drop(Reason::HoldTooShort);
    }

    // 3. Password field => DROP, not clipboard.
    //
    // This is the one refusal that discards text entirely. Putting a password-field
    // transcript on the clipboard would just relocate the exposure (I-8, B-02).
    // Checked against BOTH samples: if either says password, drop.
    let pw_then = req.target_at_capture.map(|t| t.is_password).unwrap_or(false);
    let pw_now = req.target_now.map(|t| t.is_password).unwrap_or(false);
    if pw_then || pw_now {
        return Decision::Drop(Reason::PasswordField);
    }

    // 4. I-6: a capture we ended ourselves never types.
    //
    // If the hook broke, or MAX_CAPTURE elapsed, we do not know the user intended to
    // dictate this. This is the always-on-microphone nightmare with a legitimate cause,
    // so the text goes to the clipboard and the user decides.
    if req.end_cause != EndCause::UserKeyUp {
        return Decision::ClipboardOnly(Reason::SynthesizedEnd);
    }

    // 5. Daemon degraded.
    if !req.healthy {
        return Decision::ClipboardOnly(Reason::DaemonUnhealthy);
    }

    // 6. No foreground window.
    let Some(now) = req.target_now else {
        return Decision::ClipboardOnly(Reason::NoForegroundWindow);
    };

    // 7. Elevated target: UIPI drops our SendInput silently, so "success" would be a lie.
    if now.elevated {
        return Decision::ClipboardOnly(Reason::TargetElevated);
    }

    // 8. Deny-listed app.
    if req.app_denied {
        return Decision::ClipboardOnly(Reason::AppDenied);
    }

    // 9. Focus moved while we were transcribing.
    //
    // Inference takes 0.5-2 s and users alt-tab. This is the check that stops dictation
    // landing in Slack instead of the editor (B-03). Compares the focused CONTROL, not
    // just the window, because Chrome and Outlook are one hwnd over many fields.
    match req.target_at_capture {
        Some(then) if !then.same_destination(now) => {
            return Decision::ClipboardOnly(Reason::ForegroundChanged);
        }
        None => return Decision::ClipboardOnly(Reason::NoForegroundWindow),
        _ => {}
    }

    // 10. Modifiers held: would turn Ctrl+V into Ctrl+Shift+V, or worse.
    if req.modifiers_held {
        return Decision::ClipboardOnly(Reason::ModifiersHeld);
    }

    // 11. Choose the method. Word/Outlook are pinned to unicode regardless of length so
    //     their rich clipboard is never destroyed.
    let char_len = req.text.chars().count();
    let method = policy::choose_method(&now.exe, char_len);

    Decision::Inject(Clearance {
        method,
        target_hwnd: now.hwnd,
        exe: now.exe.clone(),
        char_len,
        _private: (),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(hwnd: isize, exe: &str) -> TargetContext {
        TargetContext {
            hwnd,
            focus_hwnd: Some(hwnd * 100),
            exe: exe.into(),
            title: String::new(),
            elevated: false,
            is_password: false,
            probed_at: Instant::now(),
        }
    }

    fn ok_req<'a>(text: &'a str, t: &'a TargetContext) -> Request<'a> {
        Request {
            text,
            hold: Duration::from_millis(1000),
            end_cause: EndCause::UserKeyUp,
            target_at_capture: Some(t),
            target_now: Some(t),
            modifiers_held: false,
            healthy: true,
            app_denied: false,
        }
    }

    #[test]
    fn happy_path_injects() {
        let t = target(1, "notepad.exe");
        assert!(matches!(preflight(&ok_req("hello", &t)), Decision::Inject(_)));
    }

    #[test]
    fn password_field_drops_and_does_not_reach_clipboard() {
        // B-02: relocating the exposure to the clipboard is not a fix.
        let mut t = target(1, "chrome.exe");
        t.is_password = true;
        assert_eq!(
            preflight(&ok_req("hunter2", &t)),
            Decision::Drop(Reason::PasswordField)
        );
    }

    #[test]
    fn password_field_at_capture_time_also_drops() {
        let pw = {
            let mut t = target(1, "chrome.exe");
            t.is_password = true;
            t
        };
        let clean = target(1, "chrome.exe");
        let req = Request {
            target_at_capture: Some(&pw),
            target_now: Some(&clean),
            ..ok_req("secret", &clean)
        };
        assert_eq!(preflight(&req), Decision::Drop(Reason::PasswordField));
    }

    #[test]
    fn watchdog_ended_capture_never_types() {
        // I-6.
        let t = target(1, "notepad.exe");
        for cause in [
            EndCause::StuckKeyWatchdog,
            EndCause::MaxDuration,
            EndCause::Shutdown,
        ] {
            let req = Request { end_cause: cause, ..ok_req("hello", &t) };
            assert_eq!(
                preflight(&req),
                Decision::ClipboardOnly(Reason::SynthesizedEnd),
                "{cause:?} must not inject"
            );
        }
    }

    #[test]
    fn window_change_blocks_injection() {
        let a = target(1, "code.exe");
        let b = target(2, "slack.exe");
        let req = Request {
            target_at_capture: Some(&a),
            target_now: Some(&b),
            ..ok_req("hello", &a)
        };
        assert_eq!(
            preflight(&req),
            Decision::ClipboardOnly(Reason::ForegroundChanged)
        );
    }

    #[test]
    fn same_window_different_field_blocks_injection() {
        // B-03: the Chrome omnibox / Outlook To: line case.
        let body = target(1, "outlook.exe");
        let mut to_line = target(1, "outlook.exe");
        to_line.focus_hwnd = Some(999);
        let req = Request {
            target_at_capture: Some(&body),
            target_now: Some(&to_line),
            ..ok_req("a long paragraph", &body)
        };
        assert_eq!(
            preflight(&req),
            Decision::ClipboardOnly(Reason::ForegroundChanged)
        );
    }

    #[test]
    fn elevated_target_falls_back() {
        let mut t = target(1, "cmd.exe");
        t.elevated = true;
        assert_eq!(
            preflight(&ok_req("hello", &t)),
            Decision::ClipboardOnly(Reason::TargetElevated)
        );
    }

    #[test]
    fn modifiers_held_falls_back() {
        let t = target(1, "notepad.exe");
        let req = Request { modifiers_held: true, ..ok_req("hello", &t) };
        assert_eq!(preflight(&req), Decision::ClipboardOnly(Reason::ModifiersHeld));
    }

    #[test]
    fn unhealthy_daemon_falls_back() {
        let t = target(1, "notepad.exe");
        let req = Request { healthy: false, ..ok_req("hello", &t) };
        assert_eq!(preflight(&req), Decision::ClipboardOnly(Reason::DaemonUnhealthy));
    }

    #[test]
    fn short_tap_is_dropped() {
        let t = target(1, "notepad.exe");
        let req = Request { hold: Duration::from_millis(100), ..ok_req("hello", &t) };
        assert_eq!(preflight(&req), Decision::Drop(Reason::HoldTooShort));
    }

    #[test]
    fn empty_text_is_dropped() {
        let t = target(1, "notepad.exe");
        assert_eq!(preflight(&ok_req("   ", &t)), Decision::Drop(Reason::EmptyText));
    }

    #[test]
    fn word_uses_unicode_even_for_long_text() {
        // Protects the rich clipboard.
        let t = target(1, "winword.exe");
        let long = "x".repeat(5000);
        match preflight(&ok_req(&long, &t)) {
            Decision::Inject(c) => assert_eq!(c.method, InjectMethod::Unicode),
            other => panic!("expected inject, got {other:?}"),
        }
    }

    #[test]
    fn long_text_elsewhere_uses_clipboard() {
        let t = target(1, "notepad.exe");
        let long = "x".repeat(1000);
        match preflight(&ok_req(&long, &t)) {
            Decision::Inject(c) => assert_eq!(c.method, InjectMethod::ClipboardPaste),
            other => panic!("expected inject, got {other:?}"),
        }
    }

    #[test]
    fn password_outranks_everything_else() {
        // Ordering check: a password field with several other faults still reports
        // PasswordField, the most severe reason.
        let mut t = target(1, "chrome.exe");
        t.is_password = true;
        t.elevated = true;
        let req = Request {
            end_cause: EndCause::MaxDuration,
            modifiers_held: true,
            healthy: false,
            ..ok_req("secret", &t)
        };
        assert_eq!(preflight(&req), Decision::Drop(Reason::PasswordField));
    }
}
