//! Foreground-window probe.
//!
//! SEAM S-2 (PLAN.md §7A.5). This returns a [`TargetContext`] struct rather than a
//! boolean. Today only the security fields are consumed (elevated, password field, exe).
//! Phase 6 context conditioning reuses the *same* probe for its accuracy work — the
//! window title and focused-field text are the highest-value `initial_prompt` material
//! available, and they come from calls we already make for safety reasons.
//!
//! Getting the shape right now costs a struct. Getting it wrong costs a rewrite of the
//! security path later.

use std::time::Instant;

use crate::uia::{self, PasswordState};

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND, MAX_PATH};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, GetGUIThreadInfo, GetWindowTextW, GetWindowThreadProcessId, GUITHREADINFO,
};

/// Everything we know about where text would land.
#[derive(Debug, Clone)]
pub struct TargetContext {
    /// Foreground window at probe time.
    pub hwnd: isize,
    /// Focused control within that window, if we could determine it.
    ///
    /// This matters because Chrome, Electron and Outlook are a SINGLE hwnd covering many
    /// fields (REDTEAM.md B-03). An hwnd-level guard passes while focus sits in the
    /// omnibox or the To: line.
    pub focus_hwnd: Option<isize>,
    /// Lowercased executable name, e.g. `"code.exe"`.
    pub exe: String,
    /// Window title. Unused by the security path; Phase 6 uses it for context.
    pub title: String,
    /// Whether the target process is elevated. Access-denied is treated as elevated,
    /// because that is itself evidence we cannot interact with it (I-1, REDTEAM S-01).
    pub elevated: bool,
    /// Whether the focused control is a password field (I-8).
    ///
    /// Three-state on purpose. `Unknown` means UIA could not answer in time, which is NOT
    /// the same as "not a password" - collapsing the two would silently reintroduce
    /// REDTEAM B-02 on exactly the slow, busy applications most likely to time out.
    pub password: PasswordState,
    /// When this probe was taken, for staleness comparison at inject time.
    pub probed_at: Instant,
}

impl TargetContext {
    /// True if `other` appears to be the same destination as `self`.
    ///
    /// Compares the focused control when both have one, not just the window. Without this,
    /// tabbing from the Outlook message body to the To: line looks like "no change".
    pub fn same_destination(&self, other: &TargetContext) -> bool {
        if self.hwnd != other.hwnd {
            return false;
        }
        match (self.focus_hwnd, other.focus_hwnd) {
            (Some(a), Some(b)) => a == b,
            // If either probe could not resolve focus, fall back to window identity and
            // let the caller decide. We do not invent certainty we do not have.
            _ => true,
        }
    }
}

/// Probe the current foreground window.
///
/// Returns `None` only when there is no foreground window at all (for example during a
/// desktop switch). Callers must treat `None` as "do not inject".
pub fn probe() -> Option<TargetContext> {
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.0.is_null() {
            return None;
        }

        // ---- owning process ----
        let mut pid: u32 = 0;
        let tid = GetWindowThreadProcessId(hwnd, Some(&mut pid));
        if pid == 0 {
            return None;
        }

        let (exe, elevated) = process_info(pid);

        // ---- window title ----
        let mut buf = [0u16; 512];
        let n = GetWindowTextW(hwnd, &mut buf);
        let title = if n > 0 {
            String::from_utf16_lossy(&buf[..n as usize])
        } else {
            String::new()
        };

        // ---- focused control within the foreground thread ----
        let mut gui = GUITHREADINFO {
            cbSize: std::mem::size_of::<GUITHREADINFO>() as u32,
            ..Default::default()
        };
        let focus_hwnd = if GetGUIThreadInfo(tid, &mut gui).is_ok() && !gui.hwndFocus.0.is_null() {
            Some(gui.hwndFocus.0 as isize)
        } else {
            None
        };

        // Cheap, in-process Win32 check first: if the classic style bit is set we are
        // certain, and we avoid a cross-process UIA round trip entirely.
        let win32_says_password = focus_hwnd
            .map(|h| is_password_field(HWND(h as *mut _)))
            .unwrap_or(false);

        let password = if win32_says_password {
            PasswordState::Yes
        } else {
            // Browser and Electron password fields are not Win32 controls and have no
            // style bits, so the style check above cannot see them. UIA is the only
            // general mechanism. Bounded-time; never blocks this thread for long.
            uia::focused_is_password()
        };

        Some(TargetContext {
            hwnd: hwnd.0 as isize,
            focus_hwnd,
            exe,
            title,
            elevated,
            password,
            probed_at: Instant::now(),
        })
    }
}

/// Executable name (lowercased) and elevation state for a pid.
///
/// Failure to open the process is itself informative: on a normal desktop it means the
/// target is running at a higher integrity level than we are, so we report it as elevated
/// rather than guessing it is safe.
unsafe fn process_info(pid: u32) -> (String, bool) {
    let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
        Ok(h) => h,
        // Cannot open => assume elevated. Fail closed.
        Err(_) => return (String::new(), true),
    };

    let guard = HandleGuard(handle);

    // ---- image name ----
    let mut buf = [0u16; MAX_PATH as usize];
    let mut len = buf.len() as u32;
    let exe = if QueryFullProcessImageNameW(
        guard.0,
        PROCESS_NAME_FORMAT(0),
        PWSTR(buf.as_mut_ptr()),
        &mut len,
    )
    .is_ok()
    {
        let full = String::from_utf16_lossy(&buf[..len as usize]);
        full.rsplit('\\').next().unwrap_or("").to_ascii_lowercase()
    } else {
        String::new()
    };

    // ---- elevation ----
    let mut token = HANDLE::default();
    let elevated = if OpenProcessToken(guard.0, TOKEN_QUERY, &mut token).is_ok() {
        let tguard = HandleGuard(token);
        let mut elev = TOKEN_ELEVATION::default();
        let mut ret = 0u32;
        if GetTokenInformation(
            tguard.0,
            TokenElevation,
            Some(&mut elev as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        )
        .is_ok()
        {
            elev.TokenIsElevated != 0
        } else {
            true // could not determine => fail closed
        }
    } else {
        true // could not open token => fail closed
    };

    (exe, elevated)
}

/// Detect a masked password field.
///
/// I-8 / REDTEAM B-02: dictation into a masked field is invisible to the user until they
/// press Enter and send their transcript to an auth endpoint. Such text is DROPPED — not
/// even placed on the clipboard.
///
/// This covers classic Win32 edit controls via `ES_PASSWORD`. Browser and Electron password
/// fields are not Win32 controls and need UI Automation; that is wired in alongside the
/// Phase 6 context work, which needs UIA anyway. Until then the browser case is handled
/// conservatively by the caller.
unsafe fn is_password_field(focus: HWND) -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{GetWindowLongW, GWL_STYLE};
    const ES_PASSWORD: i32 = 0x0020;

    let style = GetWindowLongW(focus, GWL_STYLE);
    if style == 0 {
        return false;
    }
    (style & ES_PASSWORD) != 0
}

/// Closes a handle on drop. These probes run on every dictation; a leak here would be a
/// slow resource drain in a long-running daemon.
struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(hwnd: isize, focus: Option<isize>) -> TargetContext {
        TargetContext {
            hwnd,
            focus_hwnd: focus,
            exe: "test.exe".into(),
            title: String::new(),
            elevated: false,
            password: PasswordState::No,
            probed_at: Instant::now(),
        }
    }

    #[test]
    fn different_window_is_a_different_destination() {
        assert!(!ctx(1, None).same_destination(&ctx(2, None)));
    }

    #[test]
    fn same_window_different_field_is_a_different_destination() {
        // B-03: Chrome/Outlook are one hwnd across many fields.
        assert!(!ctx(1, Some(10)).same_destination(&ctx(1, Some(11))));
    }

    #[test]
    fn same_window_same_field_matches() {
        assert!(ctx(1, Some(10)).same_destination(&ctx(1, Some(10))));
    }

    #[test]
    fn probe_runs_without_panicking() {
        // Headless CI may have no foreground window; either outcome is acceptable.
        let _ = probe();
    }
}
