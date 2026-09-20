//! Session state machine.
//!
//! Pure logic: no Win32, no clock reads of its own, no I/O. Time arrives as a parameter.
//! That is what makes every transition — including the ones that only happen when the
//! hook breaks — testable without a desktop.
//!
//! The states are deliberately few. Every additional state in a machine that drives
//! synthetic keyboard input is another place for a stuck capture to hide.
//!
//! ```text
//!   Idle ──PttDown──▶ Capturing ──PttUp──▶ Finalizing ──Transcript──▶ Idle
//!     ▲                   │                     │
//!     │                   │ watchdog / max      │ (end_cause != UserKeyUp
//!     │                   ▼                     │  forces clipboard-only)
//!     └───────────── Finalizing ────────────────┘
//! ```

use std::time::{Duration, Instant};

use crate::policy;
use crate::preflight::EndCause;
use crate::target::TargetContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Idle,
    Capturing,
    Finalizing,
    /// Kill chord fired or health lost. Nothing is captured or injected until re-armed.
    Disabled,
}

/// Inputs the machine reacts to.
#[derive(Debug, Clone)]
pub enum Event {
    PttDown { at: Instant },
    PttUp { at: Instant },
    /// Watchdog B or MAX_CAPTURE forced the capture to end.
    ForcedEnd { at: Instant, reason: &'static str },
    /// Transcription finished for the in-flight utterance.
    TranscriptReady { text: String },
    KillChord,
    ReEnable,
}

/// Side effects the caller must perform. Returning these instead of doing them keeps the
/// machine pure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Begin retaining audio, prepending the preroll ring.
    StartCapture { utterance_id: u64 },
    /// Stop retaining and hand the buffer to the transcription worker.
    FinishCapture {
        utterance_id: u64,
        hold: Duration,
        end_cause: EndCause,
    },
    /// Discard the capture without transcribing. Cheaper than inference and it removes
    /// the most common hallucination case for free.
    DiscardCapture { utterance_id: u64, why: &'static str },
    /// Run preflight and then inject or fall back.
    Deliver {
        utterance_id: u64,
        text: String,
        hold: Duration,
        end_cause: EndCause,
    },
    /// Tell the user something.
    Notify(&'static str),
    /// Stop everything.
    Disable,
}

pub struct Fsm {
    state: State,
    /// Monotonic id carried through log, audio ring and injection record (seam S-4).
    next_id: u64,
    current_id: u64,
    started_at: Option<Instant>,
    end_cause: EndCause,
    hold: Duration,
    /// Target sampled when the capture ended, compared against the target at inject time.
    pub target_at_capture: Option<TargetContext>,
}

impl Fsm {
    pub fn new() -> Self {
        Self {
            state: State::Idle,
            next_id: 1,
            current_id: 0,
            started_at: None,
            end_cause: EndCause::UserKeyUp,
            hold: Duration::ZERO,
            target_at_capture: None,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }
    pub fn current_id(&self) -> u64 {
        self.current_id
    }

    /// Feed an event, get back the actions to perform, in order.
    pub fn handle(&mut self, ev: Event) -> Vec<Action> {
        match (self.state, ev) {
            // ---------------- Idle ----------------
            (State::Idle, Event::PttDown { at }) => {
                self.current_id = self.next_id;
                self.next_id += 1;
                self.started_at = Some(at);
                self.state = State::Capturing;
                vec![Action::StartCapture { utterance_id: self.current_id }]
            }

            // ---------------- Capturing ----------------
            (State::Capturing, Event::PttUp { at }) => {
                let hold = self.elapsed(at);
                self.hold = hold;
                self.end_cause = EndCause::UserKeyUp;

                // Accidental tap: drop before paying for inference. This is also the
                // single most common source of hallucinated output, since a 150 ms
                // capture is near-silence and Whisper will confidently invent something.
                if hold < policy::MIN_HOLD {
                    self.state = State::Idle;
                    let id = self.current_id;
                    self.started_at = None;
                    return vec![Action::DiscardCapture { utterance_id: id, why: "hold_too_short" }];
                }

                self.state = State::Finalizing;
                vec![Action::FinishCapture {
                    utterance_id: self.current_id,
                    hold,
                    end_cause: EndCause::UserKeyUp,
                }]
            }

            (State::Capturing, Event::ForcedEnd { at, reason }) => {
                self.hold = self.elapsed(at);
                // I-6: this capture did NOT end with the user's key-up, so whatever comes
                // back may never be typed. preflight enforces that; we just record it
                // truthfully here.
                self.end_cause = match reason {
                    "max_duration" => EndCause::MaxDuration,
                    _ => EndCause::StuckKeyWatchdog,
                };
                self.state = State::Finalizing;
                vec![
                    Action::FinishCapture {
                        utterance_id: self.current_id,
                        hold: self.hold,
                        end_cause: self.end_cause,
                    },
                    Action::Notify("Capture ended unexpectedly - will copy, not type"),
                ]
            }

            // A second key-down while capturing: autorepeat should have been squashed in
            // the hook, so this means we missed a key-up. Treat it as a forced end and
            // immediately start a new capture, rather than silently merging two
            // utterances into one.
            (State::Capturing, Event::PttDown { at }) => {
                self.hold = self.elapsed(at);
                self.end_cause = EndCause::StuckKeyWatchdog;
                let finished = Action::FinishCapture {
                    utterance_id: self.current_id,
                    hold: self.hold,
                    end_cause: self.end_cause,
                };
                self.current_id = self.next_id;
                self.next_id += 1;
                self.started_at = Some(at);
                self.state = State::Capturing;
                vec![finished, Action::StartCapture { utterance_id: self.current_id }]
            }

            // ---------------- Finalizing ----------------
            (State::Finalizing, Event::TranscriptReady { text }) => {
                self.state = State::Idle;
                let id = self.current_id;
                let hold = self.hold;
                let cause = self.end_cause;
                self.started_at = None;
                vec![Action::Deliver { utterance_id: id, text, hold, end_cause: cause }]
            }

            // The user started talking again before the previous transcript landed. Do not
            // drop it; the worker queues.
            (State::Finalizing, Event::PttDown { at }) => {
                self.current_id = self.next_id;
                self.next_id += 1;
                self.started_at = Some(at);
                self.state = State::Capturing;
                vec![Action::StartCapture { utterance_id: self.current_id }]
            }

            // ---------------- Disabled ----------------
            // MUST come before the KillChord catch-all below. Match arms are ordered, and
            // with KillChord first every further tap re-fired Disable - observed in the
            // first live run as eight consecutive "disabled" lines.
            (State::Disabled, Event::ReEnable) => {
                self.state = State::Idle;
                return vec![Action::Notify("WhisperRust re-enabled")];
            }
            (State::Disabled, _) => return vec![],

            // ---------------- Kill chord ----------------
            (_, Event::KillChord) => {
                let mut actions = vec![];
                if self.state == State::Capturing {
                    actions.push(Action::DiscardCapture {
                        utterance_id: self.current_id,
                        why: "kill_chord",
                    });
                }
                self.state = State::Disabled;
                self.started_at = None;
                actions.push(Action::Notify("WhisperRust disabled - kill chord"));
                actions.push(Action::Disable);
                actions
            }

            // Stray key-up with no capture in flight (for example the key-down happened
            // over an elevated window). Harmless; ignore it.
            (State::Idle, Event::PttUp { .. }) | (State::Finalizing, Event::PttUp { .. }) => vec![],

            (_, Event::ForcedEnd { .. }) => vec![],
            (_, Event::TranscriptReady { .. }) => vec![],
            (_, Event::ReEnable) => vec![],
        }
    }

    fn elapsed(&self, at: Instant) -> Duration {
        self.started_at
            .map(|s| at.saturating_duration_since(s))
            .unwrap_or(Duration::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(ms: u64) -> Instant {
        // A fixed base so tests are deterministic.
        Instant::now() + Duration::from_millis(ms)
    }

    #[test]
    fn happy_path() {
        let mut f = Fsm::new();
        let start = Instant::now();
        let a = f.handle(Event::PttDown { at: start });
        assert_eq!(a, vec![Action::StartCapture { utterance_id: 1 }]);
        assert_eq!(f.state(), State::Capturing);

        let a = f.handle(Event::PttUp { at: start + Duration::from_millis(900) });
        assert!(matches!(a[0], Action::FinishCapture { end_cause: EndCause::UserKeyUp, .. }));
        assert_eq!(f.state(), State::Finalizing);

        let a = f.handle(Event::TranscriptReady { text: "hello".into() });
        assert!(matches!(a[0], Action::Deliver { .. }));
        assert_eq!(f.state(), State::Idle);
    }

    #[test]
    fn short_tap_is_discarded_without_inference() {
        let mut f = Fsm::new();
        let start = Instant::now();
        f.handle(Event::PttDown { at: start });
        let a = f.handle(Event::PttUp { at: start + Duration::from_millis(100) });
        assert_eq!(
            a,
            vec![Action::DiscardCapture { utterance_id: 1, why: "hold_too_short" }]
        );
        assert_eq!(f.state(), State::Idle);
    }

    #[test]
    fn forced_end_records_a_non_user_cause() {
        // I-6: preflight uses this to force clipboard-only.
        let mut f = Fsm::new();
        let start = Instant::now();
        f.handle(Event::PttDown { at: start });
        let a = f.handle(Event::ForcedEnd {
            at: start + Duration::from_millis(2000),
            reason: "stuck_key",
        });
        match &a[0] {
            Action::FinishCapture { end_cause, .. } => {
                assert_eq!(*end_cause, EndCause::StuckKeyWatchdog)
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn max_duration_is_distinguished_from_stuck_key() {
        let mut f = Fsm::new();
        let start = Instant::now();
        f.handle(Event::PttDown { at: start });
        let a = f.handle(Event::ForcedEnd { at: start + Duration::from_secs(61), reason: "max_duration" });
        match &a[0] {
            Action::FinishCapture { end_cause, .. } => assert_eq!(*end_cause, EndCause::MaxDuration),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn double_down_splits_rather_than_merging_utterances() {
        // A missed key-up must not silently glue two dictations together.
        let mut f = Fsm::new();
        let start = Instant::now();
        f.handle(Event::PttDown { at: start });
        let a = f.handle(Event::PttDown { at: start + Duration::from_millis(1000) });
        assert!(matches!(a[0], Action::FinishCapture { utterance_id: 1, .. }));
        assert_eq!(a[1], Action::StartCapture { utterance_id: 2 });
        assert_eq!(f.state(), State::Capturing);
    }

    #[test]
    fn kill_chord_disables_and_discards_in_flight_capture() {
        let mut f = Fsm::new();
        f.handle(Event::PttDown { at: Instant::now() });
        let a = f.handle(Event::KillChord);
        assert!(a.contains(&Action::DiscardCapture { utterance_id: 1, why: "kill_chord" }));
        assert!(a.contains(&Action::Disable));
        assert_eq!(f.state(), State::Disabled);
    }

    #[test]
    fn kill_chord_fires_once_not_repeatedly() {
        // Regression, observed live: match arms are ordered, and with the KillChord
        // catch-all placed before the Disabled arm every further tap re-ran Disable.
        // The log showed eight consecutive "disabled" lines from one chord.
        let mut f = Fsm::new();
        let first = f.handle(Event::KillChord);
        assert!(first.contains(&Action::Disable));

        for _ in 0..5 {
            let again = f.handle(Event::KillChord);
            assert!(
                again.is_empty(),
                "kill chord re-fired while already disabled: {again:?}"
            );
        }
    }

    #[test]
    fn disabled_ignores_everything_until_re_enabled() {
        let mut f = Fsm::new();
        f.handle(Event::KillChord);
        assert!(f.handle(Event::PttDown { at: Instant::now() }).is_empty());
        assert!(f.handle(Event::PttUp { at: Instant::now() }).is_empty());
        assert_eq!(f.state(), State::Disabled);

        f.handle(Event::ReEnable);
        assert_eq!(f.state(), State::Idle);
        assert!(!f.handle(Event::PttDown { at: Instant::now() }).is_empty());
    }

    #[test]
    fn stray_key_up_is_ignored() {
        // Happens when the key-down landed over an elevated window.
        let mut f = Fsm::new();
        assert!(f.handle(Event::PttUp { at: Instant::now() }).is_empty());
        assert_eq!(f.state(), State::Idle);
    }

    #[test]
    fn utterance_ids_are_unique_and_monotonic() {
        // Seam S-4: corrections must tie back to the right audio.
        let mut f = Fsm::new();
        let mut ids = vec![];
        for i in 0..5u64 {
            let s = Instant::now() + Duration::from_millis(i * 2000);
            f.handle(Event::PttDown { at: s });
            f.handle(Event::PttUp { at: s + Duration::from_millis(900) });
            ids.push(f.current_id());
            f.handle(Event::TranscriptReady { text: "x".into() });
        }
        assert_eq!(ids, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn new_capture_during_finalizing_is_allowed() {
        let mut f = Fsm::new();
        let s = Instant::now();
        f.handle(Event::PttDown { at: s });
        f.handle(Event::PttUp { at: s + Duration::from_millis(900) });
        assert_eq!(f.state(), State::Finalizing);
        let a = f.handle(Event::PttDown { at: s + Duration::from_millis(1000) });
        assert_eq!(a, vec![Action::StartCapture { utterance_id: 2 }]);
        assert_eq!(f.state(), State::Capturing);
    }

    #[test]
    fn unused_time_helper_compiles() {
        let _ = t(0);
    }
}
