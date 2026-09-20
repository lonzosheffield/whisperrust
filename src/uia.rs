//! UI Automation password-field detection — the second half of invariant I-8.
//!
//! # Why the Win32 check is not enough
//!
//! `target.rs` checks `GWL_STYLE & ES_PASSWORD`, which is correct and fast for classic
//! Win32 edit controls. It is also blind to the majority of places people actually type
//! passwords: a browser `<input type="password">` is not a Win32 control at all — Chrome,
//! Edge and every Electron app render their entire UI into one `Chrome_RenderWidgetHostHWND`
//! with no per-field window and no style bits.
//!
//! So REDTEAM B-02 (dictation typed into a masked field, invisible to the user until they
//! press Enter and send their transcript to an auth endpoint) was unmitigated in exactly
//! the applications where it is most likely.
//!
//! UI Automation is the only general mechanism Windows offers here, via the
//! `IsPassword` property on the focused element.
//!
//! # Why this runs on its own thread
//!
//! UIA is COM and calls are **cross-process**. `GetFocusedElement()` against a busy Chrome
//! can take tens to hundreds of milliseconds, and against a hung process it can block for
//! far longer.
//!
//! The password check happens inside `deliver()`, which runs on the thread that owns the
//! `WH_KEYBOARD_LL` hook. Calling UIA there directly would stall the hook for the duration
//! — which is exactly the defect (D-4) just fixed in the clipboard path. Repeating it here
//! would trade one keyboard-freezing bug for another.
//!
//! So a dedicated thread owns the COM apartment and the `IUIAutomation` instance, and
//! answers queries over a channel with a hard timeout. The caller never blocks longer than
//! [`UIA_TIMEOUT`], whatever UIA does.
//!
//! # The three-state answer, and why `Unknown` is not `No`
//!
//! A timeout means we genuinely do not know whether the target is a password field.
//! Treating that as "not a password" would silently reintroduce B-02 on exactly the slow,
//! busy applications most likely to time out. Treating it as "password" would discard real
//! dictation whenever UIA hiccups.
//!
//! Neither is acceptable, so `Unknown` is its own state and the caller degrades to
//! clipboard-only — the plan's existing "when unsure, do not inject" posture (I-9). The
//! user still gets their words; they just paste them.

use std::sync::OnceLock;
use std::time::Duration;

use crossbeam_channel::{bounded, Receiver, Sender};

/// Maximum time the caller will wait for UIA.
///
/// Deliberately short. This sits on the latency path of every dictation, and the fallback
/// (clipboard-only) is safe — so waiting longer buys a marginally better outcome at the
/// cost of a worse one for everybody.
pub const UIA_TIMEOUT: Duration = Duration::from_millis(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordState {
    /// Confirmed not a password field.
    No,
    /// Confirmed password field. Text must be dropped entirely.
    Yes,
    /// UIA timed out, errored, or is unavailable. We do not know.
    Unknown,
}

impl PasswordState {
    pub fn as_str(&self) -> &'static str {
        match self {
            PasswordState::No => "no",
            PasswordState::Yes => "yes",
            PasswordState::Unknown => "unknown",
        }
    }
}

struct UiaService {
    tx: Sender<Sender<PasswordState>>,
}

static SERVICE: OnceLock<Option<UiaService>> = OnceLock::new();

/// Ask UIA whether the currently focused element is a password field.
///
/// Never blocks longer than [`UIA_TIMEOUT`]. Returns [`PasswordState::Unknown`] rather
/// than guessing if the service is unavailable or slow.
pub fn focused_is_password() -> PasswordState {
    let Some(svc) = SERVICE.get_or_init(start_service).as_ref() else {
        return PasswordState::Unknown;
    };

    let (reply_tx, reply_rx) = bounded::<PasswordState>(1);
    if svc.tx.try_send(reply_tx).is_err() {
        // Worker is busy with a previous query that has not timed out yet.
        return PasswordState::Unknown;
    }

    match reply_rx.recv_timeout(UIA_TIMEOUT) {
        Ok(state) => state,
        Err(_) => {
            tracing::debug!("UIA password query timed out after {UIA_TIMEOUT:?}");
            PasswordState::Unknown
        }
    }
}

/// Spawn the COM-owning worker. Returns `None` if the thread cannot start.
fn start_service() -> Option<UiaService> {
    let (tx, rx) = bounded::<Sender<PasswordState>>(1);

    let spawned = std::thread::Builder::new()
        .name("whisperrust-uia".into())
        .spawn(move || uia_worker(rx));

    match spawned {
        Ok(_) => Some(UiaService { tx }),
        Err(e) => {
            tracing::warn!("could not start UIA thread: {e}; password detection degraded");
            None
        }
    }
}

fn uia_worker(rx: Receiver<Sender<PasswordState>>) {
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_APARTMENTTHREADED,
    };
    use windows::Win32::UI::Accessibility::{CUIAutomation, IUIAutomation};

    unsafe {
        // UIA clients should be STA. This thread exists solely to own that apartment.
        if CoInitializeEx(None, COINIT_APARTMENTTHREADED).is_err() {
            tracing::warn!("CoInitializeEx failed; UIA password detection unavailable");
            // Still drain, so callers get Unknown promptly instead of timing out.
            while let Ok(reply) = rx.recv() {
                let _ = reply.send(PasswordState::Unknown);
            }
            return;
        }

        let automation: Option<IUIAutomation> =
            match CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER) {
                Ok(a) => Some(a),
                Err(e) => {
                    tracing::warn!("could not create IUIAutomation: {e}");
                    None
                }
            };

        if automation.is_some() {
            tracing::info!("UIA password detection active");
        }

        while let Ok(reply) = rx.recv() {
            let state = match automation.as_ref() {
                None => PasswordState::Unknown,
                Some(a) => match a.GetFocusedElement() {
                    Ok(elem) => match elem.CurrentIsPassword() {
                        Ok(b) => {
                            if b.as_bool() {
                                PasswordState::Yes
                            } else {
                                PasswordState::No
                            }
                        }
                        Err(e) => {
                            tracing::debug!("CurrentIsPassword failed: {e}");
                            PasswordState::Unknown
                        }
                    },
                    Err(e) => {
                        tracing::debug!("GetFocusedElement failed: {e}");
                        PasswordState::Unknown
                    }
                },
            };
            // If the caller already timed out this send fails, which is fine.
            let _ = reply.send(state);
        }

        CoUninitialize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn query_never_blocks_longer_than_the_timeout() {
        // The whole point: this sits on the hook-owning thread's path. If it can block,
        // it can freeze the user's keyboard - the same defect as D-4 in the clipboard.
        let start = Instant::now();
        let _ = focused_is_password();
        let elapsed = start.elapsed();
        assert!(
            elapsed < UIA_TIMEOUT * 3,
            "UIA query took {elapsed:?}, which would stall the hook thread"
        );
    }

    #[test]
    fn repeated_queries_are_stable() {
        // Exercises the worker across several round trips; must not panic or wedge.
        for _ in 0..5 {
            let _ = focused_is_password();
        }
    }

    #[test]
    fn unknown_is_distinct_from_no() {
        // Collapsing Unknown into No would silently reintroduce B-02 on exactly the busy
        // applications most likely to time out.
        assert_ne!(PasswordState::Unknown, PasswordState::No);
        assert_eq!(PasswordState::Unknown.as_str(), "unknown");
    }
}
