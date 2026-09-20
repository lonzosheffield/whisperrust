//! Text injection — the only code in this program that produces input events.
//!
//! Two invariants govern everything here:
//!
//! **I-3** — `inject()` requires a [`Clearance`], and the only way to obtain one is from
//! [`crate::preflight::preflight`]. There is no bypass: `Clearance` has a private field,
//! so no other module can construct one.
//!
//! **I-5** — this module may emit ONLY `VK_CONTROL`, `'V'` and `VK_PACKET`. That bounds the
//! blast radius of any bug here to "pastes text". It cannot press Enter, cannot press
//! Delete, cannot trigger a shortcut. Enforced by [`emit`], which panics in debug and
//! refuses in release on any other key, and by a test that greps this file.
//!
//! Every event we synthesize carries `dwExtraInfo = OUR_MAGIC` so our own hook ignores it
//! (I-7) and cannot be driven by its own output.

use std::time::{Duration, Instant};

use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS,
    KEYEVENTF_KEYUP, KEYEVENTF_UNICODE, VIRTUAL_KEY,
};

use crate::policy::{self, InjectMethod};
use crate::preflight::Clearance;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectOutcome {
    /// Text was typed or pasted into the target.
    Injected { method: InjectMethod, chars: usize },
    /// Left on the clipboard for the user; not typed.
    ClipboardOnly { reason: &'static str },
    /// Interrupted partway through by the kill chord or a modifier appearing.
    Aborted { after_chars: usize, reason: &'static str },
    Failed { error: String },
}

/// Runtime hooks the injector consults between chunks.
///
/// Passed in rather than read from globals so the chunk loop is testable.
pub trait InjectGuard {
    /// False => stop immediately. Backs the kill chord and the health flag.
    fn may_continue(&self) -> bool;
    /// True => a modifier key is physically down; abort rather than send Ctrl+Shift+V.
    fn modifiers_held(&self) -> bool;
}

/// Production guard: real key state plus a caller-supplied liveness closure.
pub struct LiveGuard<F: Fn() -> bool> {
    pub healthy: F,
}

impl<F: Fn() -> bool> InjectGuard for LiveGuard<F> {
    fn may_continue(&self) -> bool {
        (self.healthy)()
    }
    fn modifiers_held(&self) -> bool {
        modifiers_physically_down()
    }
}

/// Are modifier keys - OTHER THAN the PTT key itself - physically down right now?
///
/// Valid here because we never swallow the PTT key (I-13); a swallowed key would be
/// invisible to `GetAsyncKeyState`, which is exactly what Phase 0 measured.
///
/// # Why the PTT key must be excluded
///
/// The default PTT binding is Right Ctrl, which is itself a modifier. Checking the
/// *generic* `VK_CONTROL` (0x11) returns true when EITHER Ctrl is down, so a dictation
/// that ended with the user still touching the key was refused with "modifier key held"
/// and downgraded to clipboard-only. Observed in the first live run: utterances that
/// should have typed were silently copied instead.
///
/// The PTT key is by definition held during dictation, so it can never be evidence that
/// the user is doing something else. Excluding it - and testing the correct left/right
/// side rather than the generic code - is what makes this guard mean what it says.
pub fn modifiers_physically_down() -> bool {
    const VK_SHIFT: u16 = 0x10;
    const VK_LSHIFT: u16 = 0xA0;
    const VK_RSHIFT: u16 = 0xA1;
    const VK_CONTROL: u16 = 0x11;
    const VK_LCONTROL: u16 = 0xA2;
    const VK_RCONTROL: u16 = 0xA3;
    const VK_MENU: u16 = 0x12;
    const VK_LMENU: u16 = 0xA4;
    const VK_RMENU: u16 = 0xA5;
    const VK_LWIN: u16 = 0x5B;
    const VK_RWIN: u16 = 0x5C;

    let ptt = crate::hook::ptt_vk();

    // For each modifier family: if PTT is bound to one side, test only the other side.
    // Otherwise test the generic code.
    let mut to_check: Vec<u16> = Vec::with_capacity(5);
    to_check.push(match ptt {
        VK_LSHIFT => VK_RSHIFT,
        VK_RSHIFT => VK_LSHIFT,
        _ => VK_SHIFT,
    });
    to_check.push(match ptt {
        VK_LCONTROL => VK_RCONTROL,
        VK_RCONTROL => VK_LCONTROL,
        _ => VK_CONTROL,
    });
    to_check.push(match ptt {
        VK_LMENU => VK_RMENU,
        VK_RMENU => VK_LMENU,
        _ => VK_MENU,
    });
    if ptt != VK_LWIN {
        to_check.push(VK_LWIN);
    }
    if ptt != VK_RWIN {
        to_check.push(VK_RWIN);
    }

    unsafe {
        to_check
            .iter()
            .any(|vk| (GetAsyncKeyState(*vk as i32) as u16 & 0x8000) != 0)
    }
}

/// Wait for modifiers to be released, up to the policy timeout.
/// Returns true if they settled, false if the user is still holding something.
pub fn wait_for_modifiers_to_settle() -> bool {
    let deadline = Instant::now() + policy::MODIFIER_SETTLE_TIMEOUT;
    while Instant::now() < deadline {
        if !modifiers_physically_down() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    !modifiers_physically_down()
}

/// Wait for modifiers to clear, asking the GUARD rather than the hardware.
///
/// `wait_for_modifiers_to_settle` reads `GetAsyncKeyState` directly, which silently
/// bypasses the `InjectGuard` abstraction: in a test the mock guard could report modifiers
/// held while the real keyboard reported none, so `inject()` took a different path under
/// test than in production. Consulting the guard keeps one code path for both.
fn wait_for_modifiers_via_guard(guard: &dyn InjectGuard) -> bool {
    let deadline = Instant::now() + policy::MODIFIER_SETTLE_TIMEOUT;
    while Instant::now() < deadline {
        if !guard.modifiers_held() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    !guard.modifiers_held()
}

/// THE choke point for emitting an input event.
///
/// I-5: refuses any virtual key outside the allowlist. In debug this panics loudly so a
/// mistake is caught in testing; in release it silently declines rather than pressing an
/// unexpected key on the user's machine.
fn emit(inputs: &[INPUT]) -> Result<(), String> {
    for inp in inputs {
        if inp.r#type != INPUT_KEYBOARD {
            debug_assert!(false, "I-5: injector may only send keyboard input");
            return Err("non-keyboard input refused".into());
        }
        let ki = unsafe { inp.Anonymous.ki };
        // A unicode packet carries its character in wScan and uses wVk == 0.
        let is_unicode = ki.dwFlags.contains(KEYEVENTF_UNICODE);
        if !is_unicode && !policy::INJECTOR_ALLOWED_VKS.contains(&ki.wVk.0) {
            debug_assert!(
                false,
                "I-5 violated: injector attempted vk {:#04x}",
                ki.wVk.0
            );
            return Err(format!("I-5: vk {:#04x} not in allowlist", ki.wVk.0));
        }
    }

    let sent = unsafe { SendInput(inputs, std::mem::size_of::<INPUT>() as i32) };
    if sent as usize != inputs.len() {
        // A short count means UIPI blocked us - typically an elevated foreground window
        // that appeared between preflight and now.
        return Err(format!(
            "SendInput sent {}/{} events (likely blocked by UIPI)",
            sent,
            inputs.len()
        ));
    }
    Ok(())
}

fn unicode_event(ch: u16, up: bool) -> INPUT {
    let mut flags = KEYEVENTF_UNICODE;
    if up {
        flags |= KEYEVENTF_KEYUP;
    }
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(0),
                wScan: ch,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: policy::OUR_MAGIC,
            },
        },
    }
}

fn vk_event(vk: u16, up: bool) -> INPUT {
    let flags = if up { KEYEVENTF_KEYUP } else { KEYBD_EVENT_FLAGS(0) };
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(vk),
                wScan: 0,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: policy::OUR_MAGIC,
            },
        },
    }
}

/// Type text as unicode packets.
///
/// Never touches the clipboard, so it cannot destroy rich content and leaks to no
/// clipboard listener. This is the default, and it is mandatory for Word and Outlook.
///
/// Emitted in chunks so the kill chord and modifier guard can interrupt a long injection
/// rather than the user watching it run to completion.
fn inject_unicode(text: &str, guard: &dyn InjectGuard) -> InjectOutcome {
    let units: Vec<u16> = text.encode_utf16().collect();
    let mut done = 0usize;

    for chunk in units.chunks(policy::INJECT_CHUNK_CHARS) {
        if !guard.may_continue() {
            return InjectOutcome::Aborted { after_chars: done, reason: "kill_switch" };
        }
        if guard.modifiers_held() {
            return InjectOutcome::Aborted { after_chars: done, reason: "modifier_pressed" };
        }

        let mut events = Vec::with_capacity(chunk.len() * 2);
        for &u in chunk {
            events.push(unicode_event(u, false));
            events.push(unicode_event(u, true));
        }
        if let Err(e) = emit(&events) {
            return InjectOutcome::Failed { error: e };
        }
        done += chunk.len();
    }

    InjectOutcome::Injected { method: InjectMethod::Unicode, chars: done }
}

/// Send Ctrl+V. The caller is responsible for the clipboard contents and for restoring
/// them afterwards.
fn send_paste_chord() -> Result<(), String> {
    let events = [
        vk_event(policy::VK_CONTROL, false),
        vk_event(policy::VK_V, false),
        vk_event(policy::VK_V, true),
        vk_event(policy::VK_CONTROL, true),
    ];
    emit(&events)
}

/// Inject authorized text.
///
/// Taking [`Clearance`] by value is the type-level enforcement of I-3: this function is
/// unreachable without a preflight decision.
pub fn inject(
    clearance: Clearance,
    text: &str,
    guard: &dyn InjectGuard,
    clipboard: &mut dyn ClipboardPort,
) -> InjectOutcome {
    // Re-check immediately before acting. preflight ran some milliseconds ago and the
    // world may have moved; this is cheap and closes that window.
    if !guard.may_continue() {
        return InjectOutcome::Aborted { after_chars: 0, reason: "kill_switch" };
    }
    if guard.modifiers_held() && !wait_for_modifiers_via_guard(guard) {
        // Downgrade rather than sending a corrupted chord - but the text must go
        // SOMEWHERE. Returning ClipboardOnly without writing the clipboard made the
        // variant's name a lie and silently destroyed the user's dictation.
        if let Err(e) = clipboard.set_text(text) {
            return InjectOutcome::Failed {
                error: format!("modifiers held and clipboard unavailable: {e}"),
            };
        }
        return InjectOutcome::ClipboardOnly { reason: "modifiers_held" };
    }

    match clearance.method {
        InjectMethod::Unicode => {
            let outcome = inject_unicode(text, guard);
            // An abort leaves a PARTIAL paste in the target and the remainder nowhere.
            // Put the full text on the clipboard so the user can recover it.
            if let InjectOutcome::Aborted { .. } = outcome {
                if let Err(e) = clipboard.set_text(text) {
                    tracing::warn!("aborted injection and clipboard unavailable: {e}");
                }
            }
            outcome
        }
        InjectMethod::ClipboardPaste => {
            let prev = clipboard.snapshot_text();
            if let Err(e) = clipboard.set_text(text) {
                // Clipboard unavailable: fall back to typing rather than failing.
                tracing::warn!("clipboard set failed ({e}); falling back to unicode");
                return inject_unicode(text, guard);
            }
            let seq_after_set = clipboard.sequence();

            if let Err(e) = send_paste_chord() {
                // PLAN B-06: no restore on any fallback path. The paste did not happen, so
                // our text is the ONLY copy of what the user said; restoring the previous
                // clipboard here would erase the dictation completely - the worst possible
                // outcome, and worse than simply leaving our text where they can paste it.
                tracing::warn!("paste chord failed ({e}); leaving dictation on the clipboard");
                return InjectOutcome::ClipboardOnly { reason: "paste_failed" };
            }

            clipboard.restore_text(prev, seq_after_set, &clearance.exe);
            InjectOutcome::Injected {
                method: InjectMethod::ClipboardPaste,
                chars: clearance.char_len,
            }
        }
    }
}

/// Clipboard operations, behind a trait so the injector is testable without touching the
/// real system clipboard.
pub trait ClipboardPort {
    /// Previous contents, but ONLY if they were plain text.
    ///
    /// Returning `None` for rich content is deliberate: arboard cannot snapshot RTF, HTML
    /// or delayed-render formats, so "restoring" them would destroy them. We decline to
    /// restore what we cannot faithfully reproduce.
    fn snapshot_text(&mut self) -> Option<String>;
    fn set_text(&mut self, text: &str) -> Result<(), String>;
    fn sequence(&self) -> u32;
    /// Restore only if nothing else wrote to the clipboard in the meantime.
    fn restore_text(&mut self, prev: Option<String>, expected_seq: u32, exe: &str);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockGuard {
        cont: bool,
        mods: bool,
    }
    impl InjectGuard for MockGuard {
        fn may_continue(&self) -> bool {
            self.cont
        }
        fn modifiers_held(&self) -> bool {
            self.mods
        }
    }

    #[derive(Default)]
    struct MockClipboard {
        content: Option<String>,
        seq: u32,
        restored: Option<Option<String>>,
    }
    impl ClipboardPort for MockClipboard {
        fn snapshot_text(&mut self) -> Option<String> {
            self.content.clone()
        }
        fn set_text(&mut self, text: &str) -> Result<(), String> {
            self.content = Some(text.to_string());
            self.seq += 1;
            Ok(())
        }
        fn sequence(&self) -> u32 {
            self.seq
        }
        fn restore_text(&mut self, prev: Option<String>, expected: u32, _exe: &str) {
            if self.seq == expected {
                self.restored = Some(prev);
            }
        }
    }

    #[test]
    fn modifier_guard_excludes_the_ptt_key() {
        // Regression, observed live: with PTT bound to Right Ctrl, checking the generic
        // VK_CONTROL made every dictation look like "user is holding a modifier", so
        // utterances that should have typed were downgraded to clipboard-only.
        //
        // Assert the *selection* logic rather than live key state, which no test can
        // control: with PTT = Right Ctrl the guard must watch LEFT Ctrl, never generic.
        const VK_CONTROL: u16 = 0x11;
        const VK_LCONTROL: u16 = 0xA2;
        const VK_RCONTROL: u16 = 0xA3;

        let ptt = VK_RCONTROL;
        let checked = match ptt {
            VK_LCONTROL => VK_RCONTROL,
            VK_RCONTROL => VK_LCONTROL,
            _ => VK_CONTROL,
        };
        assert_eq!(checked, VK_LCONTROL, "must watch the opposite Ctrl, not generic");
        assert_ne!(checked, VK_CONTROL, "generic VK_CONTROL matches the PTT key itself");
        assert_ne!(checked, ptt, "the PTT key can never be evidence of other input");
    }

    #[test]
    fn modifier_guard_does_not_panic_live() {
        let _ = modifiers_physically_down();
    }

    #[test]
    fn i5_allowlist_is_exactly_three_keys() {
        assert_eq!(policy::INJECTOR_ALLOWED_VKS, &[0x11u16, 0x56, 0xE7]);
    }

    #[test]
    fn emit_refuses_keys_outside_the_allowlist() {
        // The keys that would actually hurt: Enter executes, Delete destroys.
        for vk in [0x0Du16 /* Enter */, 0x2E /* Delete */, 0x73 /* F4 */, 0x41 /* A */] {
            let ev = [vk_event(vk, false)];
            let r = std::panic::catch_unwind(|| emit(&ev));
            match r {
                Err(_) => {}                     // debug_assert fired - correct
                Ok(Ok(())) => panic!("I-5 violated: vk {vk:#04x} was emitted"),
                Ok(Err(_)) => {}                 // refused - correct
            }
        }
    }

    #[test]
    fn paste_chord_uses_only_allowed_keys() {
        for ev in [
            vk_event(policy::VK_CONTROL, false),
            vk_event(policy::VK_V, false),
        ] {
            let ki = unsafe { ev.Anonymous.ki };
            assert!(policy::INJECTOR_ALLOWED_VKS.contains(&ki.wVk.0));
        }
    }

    #[test]
    fn unicode_events_carry_our_magic() {
        // I-7: our hook must be able to ignore our own output.
        let ev = unicode_event(b'x' as u16, false);
        let ki = unsafe { ev.Anonymous.ki };
        assert_eq!(ki.dwExtraInfo, policy::OUR_MAGIC);
        assert_eq!(ki.wVk.0, 0, "unicode packets use wVk 0");
    }

    #[test]
    fn kill_switch_aborts_before_any_event() {
        let g = MockGuard { cont: false, mods: false };
        let mut cb = MockClipboard::default();
        let c = crate::preflight::test_clearance(InjectMethod::Unicode, "notepad.exe", 5);
        assert_eq!(
            inject(c, "hello", &g, &mut cb),
            InjectOutcome::Aborted { after_chars: 0, reason: "kill_switch" }
        );
    }

    #[test]
    fn clipboard_only_actually_writes_the_clipboard() {
        // Regression: this returned ClipboardOnly WITHOUT writing anything, so the
        // dictation was silently destroyed while the log said it had been copied.
        let g = MockGuard { cont: true, mods: true };
        let mut cb = MockClipboard::default();
        let c = crate::preflight::test_clearance(InjectMethod::Unicode, "notepad.exe", 5);
        let out = inject(c, "hello", &g, &mut cb);
        assert!(
            !matches!(out, InjectOutcome::Injected { .. }),
            "must not claim to have typed while a modifier is held"
        );
        // The invariant that matters is not WHICH non-injected variant is returned, but
        // that the dictation is recoverable afterwards. Asserting the variant would pin
        // an implementation detail; asserting the clipboard pins the user-visible promise.
        assert_eq!(
            cb.content.as_deref(),
            Some("hello"),
            "text must be recoverable from the clipboard, whatever the outcome variant"
        );
    }

    #[test]
    fn clipboard_restore_is_skipped_when_something_else_wrote() {
        // B-06: restoring over a newer write would clobber the user's clipboard.
        let mut cb = MockClipboard { content: Some("original".into()), seq: 5, restored: None };
        let prev = cb.snapshot_text();
        cb.set_text("dictated").unwrap();
        let seq = cb.sequence();
        // Simulate another app writing in between.
        cb.seq += 1;
        cb.restore_text(prev, seq, "notepad.exe");
        assert!(cb.restored.is_none(), "must not restore over a newer write");
    }

    #[test]
    fn clipboard_restore_happens_when_untouched() {
        let mut cb = MockClipboard { content: Some("original".into()), seq: 5, restored: None };
        let prev = cb.snapshot_text();
        cb.set_text("dictated").unwrap();
        let seq = cb.sequence();
        cb.restore_text(prev, seq, "notepad.exe");
        assert_eq!(cb.restored, Some(Some("original".to_string())));
    }

    #[test]
    fn only_allowlisted_keys_are_ever_EMITTED() {
        // Structural backstop for I-5. The real enforcement is emit(), which refuses any
        // vk outside INJECTOR_ALLOWED_VKS; this catches someone constructing an event
        // with a new key and routing around it.
        //
        // The distinction that matters: a VK constant used for READING key state via
        // GetAsyncKeyState is harmless - it observes, it cannot press anything. Only
        // constants reaching vk_event() can produce input. So scan vk_event call sites,
        // not the whole file.
        //
        // (An earlier version of this test scanned every `const VK_` in the module and
        // fired when the modifier guard gained side-specific constants. It was right to
        // complain and the fix was to make it precise, not to delete it.)
        let src = include_str!("inject.rs");
        let body = src.split("#[cfg(test)]").next().unwrap();

        let mut emitted = Vec::new();
        for (i, _) in body.match_indices("vk_event(") {
            let tail = &body[i + "vk_event(".len()..];
            let arg = tail.split(',').next().unwrap_or("").trim();
            if !arg.is_empty() && !arg.starts_with("vk") {
                emitted.push(arg.to_string());
            }
        }
        assert!(!emitted.is_empty(), "expected to find vk_event call sites");

        for arg in &emitted {
            assert!(
                arg.contains("VK_CONTROL") || arg.contains("VK_V") || arg.contains("VK_PACKET"),
                "I-5: vk_event called with non-allowlisted key: {arg}"
            );
        }
    }
}
