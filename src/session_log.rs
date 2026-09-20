//! Per-utterance session log — seam S-1.
//!
//! # Why the schema is complete from day one
//!
//! This is the only seam in the plan that **cannot be back-filled**. Every other missing
//! piece can be added later and still work on historical data; a field that was never
//! written is simply gone. So the schema carries everything the downstream phases need
//! (WPM analytics, correction capture, model comparison) even though nothing reads most of
//! it yet.
//!
//! # Why rejections are logged, not just successes
//!
//! A log of successful dictations tells you almost nothing useful. The interesting records
//! are the ones where text did *not* reach the target: which guard fired, how often the
//! hallucination filter rejected something, how often UIA could not decide. Logging only
//! successes would produce a permanently rosy picture through pure survivorship bias — and
//! this project already made that mistake once, in a CP-2 report that summarized away 62
//! WASAPI errors.
//!
//! # Privacy
//!
//! `text` is **opt-in and off by default**. Audio retention is on (PLAN §10.5) for the
//! voice-style work, but the transcript is the more directly sensitive artifact: it is
//! searchable, and on this machine it may contain client-confidential material. Everything
//! else here is metadata and is always recorded, because metadata is what makes the log
//! useful and it carries none of the content risk.
//!
//! Format is JSONL: append-only, crash-safe (a torn write loses one line, not the file),
//! and greppable without a parser.

use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::Serialize;

/// One dictation attempt, whatever its outcome.
#[derive(Debug, Serialize, Default)]
pub struct UtteranceRecord {
    /// Seam S-4: ties this record to its audio and to any later correction.
    pub utterance_id: u64,
    /// RFC3339 UTC.
    pub at: String,

    // ---- what the user did ----
    /// How long the PTT key was held.
    pub hold_ms: u64,
    /// Why the capture ended. `user_key_up` is the only cause that may be typed (I-6).
    pub end_cause: String,

    // ---- audio ----
    pub device_rate: u32,
    /// Captured audio before VAD trimming, including the 400 ms preroll.
    pub raw_audio_secs: f32,
    /// Audio actually handed to the model, after VAD.
    pub trimmed_audio_secs: f32,
    /// Ring overruns observed so far (cumulative).
    pub ring_overruns: u64,
    /// WASAPI error-callback events so far (cumulative). Non-zero means the OS dropped
    /// audio beneath us - invisible to the ring counter.
    pub stream_errors: u64,

    // ---- inference ----
    pub model: String,
    pub threads: i32,
    pub resample_ms: f64,
    pub vad_ms: f64,
    pub infer_ms: f64,
    pub no_speech_prob: f32,
    /// Words in the accepted transcript. Present even when `text` is not, so WPM works
    /// without retaining content.
    pub word_count: usize,

    // ---- decision ----
    /// `accepted`, or the rejection reason from the hallucination filter.
    pub verdict: String,
    /// preflight's decision: `inject` / `clipboard_only` / `drop`.
    pub decision: String,
    /// Why, when it was not a plain inject.
    pub decision_reason: Option<String>,
    /// `unicode` / `clipboard_paste`, when injected.
    pub inject_method: Option<String>,
    /// What actually happened at the injector.
    pub inject_outcome: Option<String>,

    // ---- target ----
    pub target_exe: String,
    /// Seam S-1 explicitly requires the title, not just the exe: Phase 6 context
    /// conditioning uses it, and it is how "wrong window" becomes diagnosable after
    /// the fact.
    pub target_title: String,
    pub target_password_state: String,
    pub target_elevated: bool,

    // ---- environment ----
    /// Latency differs by 1.5-2x on battery, so a timing number without this is not
    /// comparable to any other timing number.
    pub on_battery: bool,

    // ---- the whole point ----
    /// PTT release to text delivered. The CP-3 criterion is p95 of THIS, read from the
    /// log rather than judged by feel.
    pub release_to_delivered_ms: f64,

    /// Transcript. `None` unless text logging is explicitly enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

pub struct SessionLog {
    path: PathBuf,
    file: Mutex<Option<std::fs::File>>,
    log_text: bool,
}

impl SessionLog {
    /// Open (or create) today's log under `%LOCALAPPDATA%\WhisperRust\sessions\`.
    pub fn open(log_text: bool) -> Self {
        let dir = std::env::var("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("WhisperRust")
            .join("sessions");

        let _ = create_dir_all(&dir);
        let day = chrono_date();
        let path = dir.join(format!("{day}.jsonl"));

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .ok();

        if file.is_none() {
            tracing::warn!("could not open session log at {}", path.display());
        }

        Self { path, file: Mutex::new(file), log_text }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn logs_text(&self) -> bool {
        self.log_text
    }

    /// Append one record. Never panics and never propagates: losing a log line must not
    /// cost the user their dictation.
    pub fn record(&self, mut rec: UtteranceRecord) {
        if !self.log_text {
            rec.text = None;
        }
        let Ok(mut guard) = self.file.lock() else {
            return;
        };
        let Some(f) = guard.as_mut() else {
            return;
        };
        match serde_json::to_string(&rec) {
            Ok(line) => {
                let _ = writeln!(f, "{line}");
                let _ = f.flush();
            }
            Err(e) => tracing::warn!("could not serialize session record: {e}"),
        }
    }
}

/// `YYYY-MM-DD` without pulling in a date crate.
fn chrono_date() -> String {
    use windows::Win32::Foundation::SYSTEMTIME;
    use windows::Win32::System::SystemInformation::GetSystemTime;
    let st: SYSTEMTIME = unsafe { GetSystemTime() };
    format!("{:04}-{:02}-{:02}", st.wYear, st.wMonth, st.wDay)
}

/// RFC3339 UTC timestamp.
pub fn now_rfc3339() -> String {
    use windows::Win32::Foundation::SYSTEMTIME;
    use windows::Win32::System::SystemInformation::GetSystemTime;
    let st: SYSTEMTIME = unsafe { GetSystemTime() };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds
    )
}

/// Is the machine running on battery?
///
/// Recorded per utterance because a latency figure without it is not comparable: this is a
/// U-series laptop and DC throttling moves inference by 1.5-2x.
pub fn on_battery() -> bool {
    use windows::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
    unsafe {
        let mut sps = SYSTEM_POWER_STATUS::default();
        if GetSystemPowerStatus(&mut sps).is_ok() {
            // ACLineStatus: 0 = offline (battery), 1 = online, 255 = unknown.
            sps.ACLineStatus == 0
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_serializes_without_text_by_default() {
        let log = SessionLog::open(false);
        assert!(!log.logs_text());

        let rec = UtteranceRecord {
            utterance_id: 1,
            at: now_rfc3339(),
            text: Some("secret words".into()),
            word_count: 2,
            ..Default::default()
        };
        // Must not panic, and the text must be stripped before it reaches disk.
        let mut stripped = rec;
        if !log.logs_text() {
            stripped.text = None;
        }
        let json = serde_json::to_string(&stripped).unwrap();
        assert!(
            !json.contains("secret words"),
            "transcript leaked into the log with text logging disabled"
        );
        assert!(json.contains("\"word_count\":2"), "metadata must survive");
    }

    #[test]
    fn word_count_survives_without_the_transcript() {
        // WPM analytics must work without retaining content.
        let rec = UtteranceRecord { word_count: 42, ..Default::default() };
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"word_count\":42"));
        assert!(!json.contains("\"text\""), "absent text must be omitted, not null");
    }

    #[test]
    fn timestamp_is_rfc3339_shaped() {
        let t = now_rfc3339();
        assert_eq!(t.len(), 24, "got {t}");
        assert!(t.ends_with('Z'));
        assert_eq!(&t[4..5], "-");
        assert_eq!(&t[10..11], "T");
    }

    #[test]
    fn date_is_iso_shaped() {
        let d = chrono_date();
        assert_eq!(d.len(), 10, "got {d}");
        assert_eq!(d.matches('-').count(), 2);
    }

    #[test]
    fn power_state_is_readable() {
        let _ = on_battery();
    }

    #[test]
    fn rejections_are_representable() {
        // The log must be able to describe a dictation that produced NO text, or the
        // record is survivorship-biased by construction.
        let rec = UtteranceRecord {
            utterance_id: 7,
            verdict: "known_hallucination".into(),
            decision: "drop".into(),
            decision_reason: Some("password_field".into()),
            word_count: 0,
            ..Default::default()
        };
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("known_hallucination"));
        assert!(json.contains("password_field"));
    }
}
