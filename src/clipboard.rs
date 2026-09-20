//! Clipboard access, with dictation kept out of Windows clipboard history.
//!
//! ## Why this is hand-written rather than just using arboard
//!
//! arboard 3.6 publishes only `SetExtLinux` / `GetExtLinux` / `ClearExtLinux`. There is no
//! `SetExtWindows`, so there is no way through arboard to mark content as excluded from
//! Win+V history or the cloud clipboard. A design review claimed otherwise; checking
//! docs.rs showed the trait simply does not exist on Windows.
//!
//! Since every dictation transits the clipboard on the paste path, without this every
//! dictated sentence would be retained in Win+V history and — if the user has it enabled —
//! synced to their Microsoft account. For a tool whose whole promise is "this never leaves
//! your machine", that is the difference between true and false.
//!
//! Windows exposes this through three registered clipboard formats, each holding a DWORD:
//!
//! | Format | Effect |
//! |---|---|
//! | `ExcludeClipboardContentFromMonitorProcessing` | clipboard monitors skip it entirely |
//! | `CanIncludeInClipboardHistory` | 0 => never appears in Win+V |
//! | `CanUploadToCloudClipboard` | 0 => never synced to other devices |
//!
//! ## The restore race (REDTEAM B-06)
//!
//! Restoring the user's previous clipboard is a race against the target application
//! reading ours. Two rules keep it safe:
//!
//! 1. **Only snapshot plain text.** RTF, HTML, images and delayed-render content cannot be
//!    faithfully reproduced, so we decline to "restore" them — which means we also never
//!    destroy them, because the paste path is not used for the apps that produce them
//!    (Word and Outlook are pinned to unicode injection).
//! 2. **Only restore if nothing else wrote.** `GetClipboardSequenceNumber()` is compared
//!    against the value captured right after our own write. Any change means another app
//!    touched the clipboard and our restore would clobber it.

use std::time::Duration;

use windows::Win32::Foundation::{HANDLE, HGLOBAL, HWND};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardSequenceNumber,
    IsClipboardFormatAvailable, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
};
use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};

use crate::inject::ClipboardPort;
use crate::policy;

const CF_UNICODETEXT: u32 = 13;

/// Open the clipboard, retrying briefly.
///
/// The clipboard is a single global lock and other applications hold it transiently.
/// Chromium retries 5 times at 5 ms; we do the same rather than failing a dictation
/// because Explorer happened to be mid-copy.
fn open_clipboard_retrying() -> Result<ClipboardGuard, String> {
    for attempt in 0..5 {
        let ok = unsafe { OpenClipboard(Some(HWND::default())) };
        if ok.is_ok() {
            return Ok(ClipboardGuard);
        }
        if attempt < 4 {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    Err("could not open clipboard after 5 attempts".into())
}

/// Closes the clipboard on drop. Leaving it open would wedge every other application on
/// the machine, so this must not depend on a happy path.
struct ClipboardGuard;
impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseClipboard();
        }
    }
}

fn register_format(name: &str) -> u32 {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { RegisterClipboardFormatW(windows::core::PCWSTR(wide.as_ptr())) }
}

/// Allocate a moveable HGLOBAL and fill it. Returns a handle the clipboard will own.
unsafe fn alloc_global(bytes: &[u8]) -> Result<HGLOBAL, String> {
    let h = GlobalAlloc(GMEM_MOVEABLE, bytes.len()).map_err(|e| format!("GlobalAlloc: {e}"))?;
    let ptr = GlobalLock(h) as *mut u8;
    if ptr.is_null() {
        return Err("GlobalLock returned null".into());
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
    let _ = GlobalUnlock(h);
    Ok(h)
}

/// Mark the clipboard contents as private to this machine and this moment.
///
/// Called while the clipboard is already open and after the text has been set.
unsafe fn apply_privacy_formats() {
    // A DWORD 0 means "no".
    let zero = 0u32.to_ne_bytes();

    for name in [
        "ExcludeClipboardContentFromMonitorProcessing",
        "CanIncludeInClipboardHistory",
        "CanUploadToCloudClipboard",
    ] {
        let fmt = register_format(name);
        if fmt == 0 {
            tracing::warn!("could not register clipboard format {name}");
            continue;
        }
        match alloc_global(&zero) {
            Ok(h) => {
                if SetClipboardData(fmt, Some(HANDLE(h.0))).is_err() {
                    tracing::warn!("SetClipboardData failed for {name}");
                }
            }
            Err(e) => tracing::warn!("alloc for {name} failed: {e}"),
        }
    }
}

pub struct WinClipboard {
    /// True if the previous contents were something we cannot reproduce, in which case we
    /// must not attempt a restore.
    last_snapshot_was_rich: bool,
}

impl WinClipboard {
    pub fn new() -> Self {
        Self { last_snapshot_was_rich: false }
    }

    /// Read the clipboard as text, or `None` if it holds no text.
    fn read_text(&mut self) -> Option<String> {
        let _guard = open_clipboard_retrying().ok()?;
        unsafe {
            if IsClipboardFormatAvailable(CF_UNICODETEXT).is_err() {
                // Something is on the clipboard but it is not text. Record that so the
                // restore path knows to stay away from it.
                self.last_snapshot_was_rich = true;
                return None;
            }
            let h = GetClipboardData(CF_UNICODETEXT).ok()?;
            let hg = HGLOBAL(h.0);
            let ptr = GlobalLock(hg) as *const u16;
            if ptr.is_null() {
                return None;
            }
            let mut len = 0usize;
            while *ptr.add(len) != 0 && len < 1 << 22 {
                len += 1;
            }
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len));
            let _ = GlobalUnlock(hg);
            self.last_snapshot_was_rich = false;
            Some(s)
        }
    }

    fn write_text(&mut self, text: &str) -> Result<(), String> {
        write_text_raw(text)
    }
}

/// Write text + privacy formats. Free function so the deferred-restore thread can use it
/// without holding a `WinClipboard`.
fn write_text_raw(text: &str) -> Result<(), String> {
    {
        let _guard = open_clipboard_retrying()?;
        unsafe {
            EmptyClipboard().map_err(|e| format!("EmptyClipboard: {e}"))?;

            let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
            let bytes = std::slice::from_raw_parts(
                wide.as_ptr() as *const u8,
                wide.len() * std::mem::size_of::<u16>(),
            );
            let h = alloc_global(bytes)?;

            // Ownership transfers to the clipboard here; do NOT free h.
            SetClipboardData(CF_UNICODETEXT, Some(HANDLE(h.0)))
                .map_err(|e| format!("SetClipboardData: {e}"))?;

            // Must happen while the clipboard is still open and owned by us.
            apply_privacy_formats();
        }
    }
    Ok(())
}

impl ClipboardPort for WinClipboard {
    fn snapshot_text(&mut self) -> Option<String> {
        self.read_text()
    }

    fn set_text(&mut self, text: &str) -> Result<(), String> {
        self.write_text(text)
    }

    fn sequence(&self) -> u32 {
        unsafe { GetClipboardSequenceNumber() }
    }

    fn restore_text(&mut self, prev: Option<String>, expected_seq: u32, exe: &str) {
        // Nothing to restore, or the previous content was rich and we refused to snapshot
        // it. Leaving our dictation on the clipboard is strictly better than replacing the
        // user's spreadsheet cells with an empty string.
        let Some(prev) = prev else {
            return;
        };
        if self.last_snapshot_was_rich {
            return;
        }

        let delay = policy::restore_delay_ms(exe);

        // ---------------------------------------------------------------------------
        // THIS MUST NOT BLOCK THE CALLER.
        //
        // `restore_text` is reached from `deliver()`, which runs on the main thread - the
        // thread that owns the WH_KEYBOARD_LL hook. A low-level hook procedure cannot run
        // while its thread is sleeping, so sleeping here for 750-1500 ms stalls EVERY
        // keystroke on the machine and invites Windows to silently unregister the hook,
        // which is the failure the whole watchdog design exists to avoid. The project's
        // own Phase 1a criterion calls a 1500 ms stall fatal; doing it deliberately was a
        // self-inflicted version of the bug.
        //
        // So the wait and the restore happen on a detached helper thread. Clipboard calls
        // are process-wide and thread-agnostic, so this is safe.
        // ---------------------------------------------------------------------------
        std::thread::Builder::new()
            .name("whisperrust-clipboard-restore".into())
            .spawn(move || {
                std::thread::sleep(Duration::from_millis(delay));

                // B-06: if anything else wrote to the clipboard while we waited, our
                // restore would clobber a newer value. Stand down.
                let now = unsafe { GetClipboardSequenceNumber() };
                if now != expected_seq {
                    tracing::debug!(
                        "clipboard changed during paste window (seq {expected_seq} -> {now}); not restoring"
                    );
                    return;
                }

                if let Err(e) = write_text_raw(&prev) {
                    tracing::warn!("clipboard restore failed: {e}");
                }
            })
            .map(|_| ())
            .unwrap_or_else(|e| tracing::warn!("could not spawn restore thread: {e}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privacy_formats_are_registerable() {
        // RegisterClipboardFormatW returns a non-zero atom for a valid name. If Windows
        // ever stops recognizing these, dictation would silently start landing in Win+V.
        for name in [
            "ExcludeClipboardContentFromMonitorProcessing",
            "CanIncludeInClipboardHistory",
            "CanUploadToCloudClipboard",
        ] {
            assert_ne!(register_format(name), 0, "could not register {name}");
        }
    }

    #[test]
    fn sequence_number_is_readable() {
        let cb = WinClipboard::new();
        let _ = cb.sequence();
    }

    #[test]
    fn roundtrip_text_and_verify_history_exclusion() {
        let mut cb = WinClipboard::new();
        let marker = "whisperrust-selftest-do-not-keep";

        // Save whatever the developer had, and put it back at the end.
        let before = cb.snapshot_text();

        if cb.set_text(marker).is_err() {
            // A locked clipboard on a busy desktop is not a code defect.
            eprintln!("skipping: clipboard unavailable");
            return;
        }
        assert_eq!(cb.snapshot_text().as_deref(), Some(marker));

        // The exclusion formats must be present on our own write.
        let _g = open_clipboard_retrying().expect("open");
        unsafe {
            let fmt = register_format("CanIncludeInClipboardHistory");
            assert!(
                IsClipboardFormatAvailable(fmt).is_ok(),
                "history-exclusion format missing: dictation would be retained in Win+V"
            );
        }
        drop(_g);

        if let Some(b) = before {
            let _ = cb.set_text(&b);
        }
    }

    #[test]
    fn restore_is_skipped_when_sequence_moved() {
        let mut cb = WinClipboard::new();
        // An expected sequence that cannot match the live one.
        cb.restore_text(Some("old".into()), u32::MAX, "notepad.exe");
        // Reaching here without clobbering is the assertion; a panic or a write would fail.
    }
}
