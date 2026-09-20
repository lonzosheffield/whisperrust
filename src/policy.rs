//! Security policy constants.
//!
//! GOVERNED FILE. Per PLAN.md §8 (G-2) this file is part of the trust boundary. Changing
//! any constant here requires an `AMEND-nnn.md` approved by the owner in writing. An
//! autonomous agent must never weaken a value in this file to make a test pass — that is
//! an explicit hard-stop condition.
//!
//! Every constant traces to an invariant (I-n) or a red-team finding (B-n / S-n) in
//! PLAN.md and REDTEAM.md.

use std::time::Duration;

// ---------------------------------------------------------------------------------------
// I-13 — the PTT key is never swallowed
// ---------------------------------------------------------------------------------------
//
// MEASURED, NOT ASSUMED (Phase 0, docs/SPIKE-PTT-ORACLE.md): a WH_KEYBOARD_LL hook that
// returns 1 prevents the key from reaching the key-state tables, blinding BOTH
// GetAsyncKeyState and GetKeyState. Watchdog B would then fire ~50 ms into every capture
// and kill every dictation.
//
// If anyone ever sets this true, the stuck-key watchdog breaks silently.
pub const SWALLOW_PTT_KEY: bool = false;

// ---------------------------------------------------------------------------------------
// I-12 — forbidden PTT bindings
// ---------------------------------------------------------------------------------------
//
// A wedged app holding one of these would break the machine for the user. Left Ctrl in
// particular would take Ctrl+C / Ctrl+V / Ctrl+Z with it.
pub const FORBIDDEN_PTT_VKS: &[u16] = &[
    0x11, // VK_CONTROL  (generic)
    0xA2, // VK_LCONTROL
    0x10, // VK_SHIFT
    0xA0, // VK_LSHIFT
    0xA1, // VK_RSHIFT
    0x12, // VK_MENU (Alt)
    0xA4, // VK_LMENU
    0xA5, // VK_RMENU
    0x5B, // VK_LWIN
    0x5C, // VK_RWIN
    0x14, // VK_CAPITAL
    0x1B, // VK_ESCAPE
    0x0D, // VK_RETURN
    0x20, // VK_SPACE
    0x09, // VK_TAB
    0x08, // VK_BACK
    0x2E, // VK_DELETE
];

/// Alphanumerics are forbidden as a range rather than enumerated.
pub fn is_forbidden_ptt_vk(vk: u16) -> bool {
    if FORBIDDEN_PTT_VKS.contains(&vk) {
        return true;
    }
    // 0-9 and A-Z
    (0x30..=0x39).contains(&vk) || (0x41..=0x5A).contains(&vk)
}

/// Default PTT binding: Right Ctrl. Not swallowed, so applications see a bare Ctrl press,
/// which is a no-op in essentially every application. Phase 1a verifies that empirically.
pub const DEFAULT_PTT_VK: u16 = 0xA3; // VK_RCONTROL

// ---------------------------------------------------------------------------------------
// I-5 — the injector may emit ONLY these virtual keys
// ---------------------------------------------------------------------------------------
//
// Bounds the blast radius of any injector bug to "pastes text". Enforced by test.
pub const VK_CONTROL: u16 = 0x11;
pub const VK_V: u16 = 0x56;
pub const VK_PACKET: u16 = 0xE7;
pub const INJECTOR_ALLOWED_VKS: &[u16] = &[VK_CONTROL, VK_V, VK_PACKET];

// ---------------------------------------------------------------------------------------
// I-4 — output sanitization
// ---------------------------------------------------------------------------------------
//
// B-01: a newline injected into a terminal is Enter, and Enter executes.
pub const MAX_INJECT_CHARS: usize = 2000;
/// Collapse a repeated n-gram after this many consecutive repeats (Whisper loop guard).
pub const MAX_NGRAM_REPEATS: usize = 3;

// ---------------------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------------------

/// Holds shorter than this are treated as an accidental tap and ignored entirely,
/// before any inference cost is paid.
pub const MIN_HOLD: Duration = Duration::from_millis(250);

/// Hard cap on a single capture. Anything longer finalizes automatically — and because it
/// did not end with the user's key-up, I-6 forces clipboard-only.
pub const MAX_CAPTURE: Duration = Duration::from_secs(60);

/// Grace period after key-up before finalizing. People release the key slightly early, and
/// this catches the last syllable.
pub const POST_RELEASE_GRACE: Duration = Duration::from_millis(100);

/// Rolling preroll retained ahead of PTT-down.
///
/// NOT 1.5 s. A long preroll records speech from *before* the key was pressed, which VAD
/// will not strip because it is speech — it would paste the tail of a sentence the user
/// said to someone else. 400 ms is human reaction time.
pub const PREROLL: Duration = Duration::from_millis(400);

/// Watchdog B: poll interval for detecting a physically-released key whose key-up we missed
/// (for example because an elevated window was foreground when it was released).
pub const STUCK_KEY_POLL: Duration = Duration::from_millis(50);

/// Watchdog A: how often to prove the hook is still installed and being called.
pub const HOOK_LIVENESS_INTERVAL: Duration = Duration::from_secs(30);
/// How long to wait for the liveness probe to come back before re-installing the hook.
pub const HOOK_LIVENESS_TIMEOUT: Duration = Duration::from_millis(200);

/// If the worker heartbeat goes staler than this, the hook enters pass-through-everything
/// mode so a sick daemon can never make the machine feel broken.
pub const WORKER_HEARTBEAT_STALE: Duration = Duration::from_secs(3);

/// Maximum time to wait for the user to release modifier keys before falling back from
/// Ctrl+V to unicode injection. Prevents sending Ctrl+Shift+V.
pub const MODIFIER_SETTLE_TIMEOUT: Duration = Duration::from_millis(300);

// ---------------------------------------------------------------------------------------
// B-06 — clipboard restore
// ---------------------------------------------------------------------------------------

/// Default delay before restoring the previous clipboard. Electron apps can take 200 ms+
/// to process WM_PASTE; restoring too early pastes the user's OLD clipboard.
pub const CLIPBOARD_RESTORE_DELAY: Duration = Duration::from_millis(750);

/// Apps that need longer. Measured in Phase 1a.
pub const SLOW_PASTE_APPS: &[(&str, u64)] = &[
    ("slack.exe", 1500),
    ("discord.exe", 1500),
    ("teams.exe", 1500),
    ("ms-teams.exe", 1500),
    ("code.exe", 1500),
];

// ---------------------------------------------------------------------------------------
// §10.4 — per-app injection method
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectMethod {
    /// KEYEVENTF_UNICODE typing. Never touches the clipboard, so it leaks to no clipboard
    /// listener and cannot destroy rich content.
    Unicode,
    /// Clipboard + Ctrl+V. Faster for long text, but writes the clipboard.
    ClipboardPaste,
}

/// Above this length, prefer the clipboard unless the app is pinned to unicode.
pub const UNICODE_MAX_CHARS: usize = 300;

/// Apps pinned to unicode REGARDLESS of length.
///
/// Word and Outlook keep RTF/HTML on the clipboard. Our paste path must write the
/// clipboard first, which destroys that rich content, and the restore cannot bring it back
/// because arboard can only snapshot plain text. "Copy a table in Word, dictate, table
/// gone." Unicode injection sidesteps this entirely.
pub const FORCE_UNICODE_APPS: &[&str] = &[
    "winword.exe",
    "outlook.exe",
    "olk.exe", // new Outlook
    "excel.exe",
    "powerpnt.exe",
    "onenote.exe",
    "mstsc.exe", // RDP: synthetic paste is unreliable
    "vim.exe",
    "gvim.exe",
    "nvim.exe",
];

/// Apps where Ctrl+V is known-good and preferred for long text.
pub const PREFER_PASTE_APPS: &[&str] = &["windowsterminal.exe", "notepad.exe", "conhost.exe"];

/// Apps where a stray newline executes a command. I-4 applies everywhere, but these get an
/// extra assertion in tests.
pub const TERMINAL_APPS: &[&str] = &[
    "windowsterminal.exe",
    "conhost.exe",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wt.exe",
];

pub fn choose_method(exe_lower: &str, char_len: usize) -> InjectMethod {
    if FORCE_UNICODE_APPS.contains(&exe_lower) {
        return InjectMethod::Unicode;
    }
    if char_len > UNICODE_MAX_CHARS {
        return InjectMethod::ClipboardPaste;
    }
    InjectMethod::Unicode
}

pub fn restore_delay_ms(exe_lower: &str) -> u64 {
    SLOW_PASTE_APPS
        .iter()
        .find(|(a, _)| *a == exe_lower)
        .map(|(_, ms)| *ms)
        .unwrap_or(CLIPBOARD_RESTORE_DELAY.as_millis() as u64)
}

pub fn is_terminal(exe_lower: &str) -> bool {
    TERMINAL_APPS.contains(&exe_lower)
}

// ---------------------------------------------------------------------------------------
// Emergency stop
// ---------------------------------------------------------------------------------------

/// Kill chord: tap the PTT key this many times within the window to disable the daemon.
/// Checked between injection chunks so a runaway injection can be interrupted.
pub const KILL_CHORD_TAPS: usize = 5;
pub const KILL_CHORD_WINDOW: Duration = Duration::from_millis(1000);

/// Injection is emitted in chunks this size so the kill chord and modifier guard get a
/// chance to interrupt a long paste.
pub const INJECT_CHUNK_CHARS: usize = 64;

/// Admin off-switch. If this file exists the daemon refuses to install the hook at all.
pub const DISABLE_SENTINEL: &str = r"C:\ProgramData\WhisperRust\disabled";

/// Tags our own synthetic input so the hook can distinguish it from a human (I-7).
pub const OUR_MAGIC: usize = 0x5748_5250; // "WHRP"

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ptt_key_is_never_swallowed() {
        // I-13. If this fails, Watchdog B is silently broken and every capture dies.
        assert!(!SWALLOW_PTT_KEY, "I-13 violated: see docs/SPIKE-PTT-ORACLE.md");
    }

    #[test]
    fn default_ptt_binding_is_allowed() {
        assert!(!is_forbidden_ptt_vk(DEFAULT_PTT_VK));
    }

    #[test]
    fn dangerous_bindings_are_rejected() {
        for vk in [0xA2u16, 0x11, 0x14, 0x0D, 0x20, 0x41, 0x30] {
            assert!(is_forbidden_ptt_vk(vk), "vk {vk:#04x} must be forbidden");
        }
    }

    #[test]
    fn injector_allowlist_is_minimal() {
        // I-5. Growing this list expands what a bug can do to the user's machine.
        assert_eq!(INJECTOR_ALLOWED_VKS.len(), 3);
    }

    #[test]
    fn office_apps_never_use_the_clipboard() {
        // Long text must STILL be unicode for Word/Outlook, or rich clipboard is destroyed.
        for app in ["winword.exe", "outlook.exe"] {
            assert_eq!(choose_method(app, 5000), InjectMethod::Unicode, "{app}");
        }
    }

    #[test]
    fn preroll_is_short_enough_to_be_safe() {
        // A long preroll captures speech from before the key was pressed.
        assert!(PREROLL <= Duration::from_millis(600));
    }
}
