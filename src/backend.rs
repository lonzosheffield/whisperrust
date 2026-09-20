//! Speech-to-text backend.
//!
//! # Why a trait when there is only one implementation
//!
//! `whisper.cpp` via FFI is the permanent answer (PLAN.md 10.1); no second real backend is
//! planned. The trait earns its keep anyway, for two reasons that have nothing to do with
//! swapping engines:
//!
//! 1. **`MockBackend` makes the rest of the daemon testable.** The FSM, preflight and
//!    injector can be exercised without loading a 141 MB model or owning a microphone.
//! 2. It keeps the inference call in one place with one shape, so the pre-FFI validation
//!    below cannot be bypassed by a convenient shortcut somewhere else.
//!
//! # Pre-FFI validation is not optional
//!
//! ggml's assertions call `abort()`. `panic = "unwind"` cannot catch that — the process
//! simply dies, taking the user's in-flight dictation and their daemon with it. Rust's
//! safety guarantees stop at the FFI boundary, so the only defense is refusing to pass
//! anything questionable across it. Hence [`validate_pcm`].

use std::path::Path;
use std::time::{Duration, Instant};

use whisper_rs::{
    FullParams, SamplingStrategy, WhisperContext, WhisperContextParameters, WhisperVadContext,
    WhisperVadContextParams, WhisperVadParams,
};

use crate::resample::TARGET_RATE;

/// Decoding context handed to the backend.
///
/// Seam for PLAN.md 7A.2 (context conditioning): `initial_prompt` and `prev_text` are the
/// mechanism by which the foreground window's content will later bias decoding toward the
/// jargon actually on screen. Nothing populates them yet beyond custom vocabulary.
#[derive(Debug, Clone, Default)]
pub struct Hint {
    pub language: Option<String>,
    /// Custom vocabulary / domain terms.
    pub initial_prompt: Option<String>,
    /// The previous utterance, for continuity across a multi-sentence dictation.
    pub prev_text: Option<String>,
    /// Encoder cost lever. `None` uses the full 1500-frame context.
    pub audio_ctx: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Segment {
    pub text: String,
    pub no_speech_prob: f32,
    pub start_cs: i64,
    pub end_cs: i64,
}

#[derive(Debug, Clone)]
pub struct Transcript {
    pub text: String,
    pub segments: Vec<Segment>,
    /// Worst (highest) no-speech probability across segments. The hallucination filter
    /// keys on this.
    pub max_no_speech: f32,
    pub inference: Duration,
    /// Audio actually fed to the model, after VAD trimming.
    pub audio_secs: f32,
}

#[derive(Debug)]
pub struct BackendInfo {
    pub name: String,
    pub model: String,
    pub threads: i32,
}

#[derive(Debug)]
pub enum BackendError {
    Load(String),
    Invalid(String),
    Inference(String),
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendError::Load(e) => write!(f, "model load failed: {e}"),
            BackendError::Invalid(e) => write!(f, "invalid audio: {e}"),
            BackendError::Inference(e) => write!(f, "inference failed: {e}"),
        }
    }
}

pub trait TranscriptionBackend: Send {
    fn transcribe(&mut self, pcm16k: &[f32], hint: &Hint) -> Result<Transcript, BackendError>;
    /// Run a throwaway inference so the first real one is not ~2x slow.
    fn warm(&mut self) -> Result<(), BackendError>;
    fn info(&self) -> BackendInfo;
    /// VAD access, where the backend has one.
    ///
    /// Exposed on the trait rather than by downcasting so the mock can honestly report
    /// that it has no VAD, instead of tests silently exercising a different code path
    /// from production.
    fn vad_trim(&mut self, _pcm16k: &[f32]) -> Option<Vec<f32>> {
        None
    }
    fn has_vad(&self) -> bool {
        false
    }
}

/// Minimum audio whisper.cpp will accept without misbehaving.
const MIN_SAMPLES: usize = TARGET_RATE as usize; // 1.0 s

/// Reject anything that could make ggml abort, and pad anything too short.
///
/// Returns owned audio because padding may be required.
fn validate_pcm(pcm: &[f32]) -> Result<Vec<f32>, BackendError> {
    if pcm.is_empty() {
        return Err(BackendError::Invalid("empty audio".into()));
    }

    // NaN or infinity propagates into the mel spectrogram and then into an assertion
    // somewhere deep in ggml. Check before crossing the boundary, not after.
    if let Some(pos) = pcm.iter().position(|s| !s.is_finite()) {
        return Err(BackendError::Invalid(format!(
            "non-finite sample at index {pos}"
        )));
    }

    // Clamping rather than rejecting: a slightly hot microphone is the user's problem to
    // hear, not a reason to drop their sentence.
    let needs_clamp = pcm.iter().any(|s| *s < -1.0 || *s > 1.0);

    let mut out: Vec<f32> = if needs_clamp {
        pcm.iter().map(|s| s.clamp(-1.0, 1.0)).collect()
    } else {
        pcm.to_vec()
    };

    // whisper.cpp pads internally to 30 s, but very short buffers have historically been a
    // source of trouble. One second of silence costs nothing and removes the class.
    if out.len() < MIN_SAMPLES {
        out.resize(MIN_SAMPLES, 0.0);
    }

    Ok(out)
}

pub struct WhisperCppBackend {
    ctx: WhisperContext,
    state: whisper_rs::WhisperState,
    vad: Option<WhisperVadContext>,
    model_path: String,
    threads: i32,
    warmed: bool,
}

impl WhisperCppBackend {
    /// `vad_model` is optional: without it the backend still transcribes, it just cannot
    /// trim silence or skip empty captures.
    pub fn new(
        model_path: &str,
        vad_model: Option<&str>,
        threads: i32,
        use_gpu: bool,
    ) -> Result<Self, BackendError> {
        if !Path::new(model_path).exists() {
            return Err(BackendError::Load(format!("no model at {model_path}")));
        }

        let mut params = WhisperContextParameters::default();
        params.use_gpu(use_gpu);
        // flash_attn reduces encoder memory traffic. Harmless on CPU.
        params.flash_attn(true);

        let ctx = WhisperContext::new_with_params(model_path, params)
            .map_err(|e| BackendError::Load(e.to_string()))?;
        let state = ctx
            .create_state()
            .map_err(|e| BackendError::Load(format!("create_state: {e}")))?;

        let vad = match vad_model {
            Some(p) if Path::new(p).exists() => {
                let mut vp = WhisperVadContextParams::new();
                vp.set_n_threads(threads);
                vp.set_use_gpu(false); // VAD is tiny; GPU setup costs more than it saves
                match WhisperVadContext::new(p, vp) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        // Not fatal: transcription without trimming is degraded, not broken.
                        tracing::warn!("VAD unavailable ({e}); continuing without trimming");
                        None
                    }
                }
            }
            Some(p) => {
                tracing::warn!("VAD model not found at {p}; continuing without trimming");
                None
            }
            None => None,
        };

        Ok(Self {
            ctx,
            state,
            vad,
            model_path: model_path.to_string(),
            threads,
            warmed: false,
        })
    }

    pub fn has_vad(&self) -> bool {
        self.vad.is_some()
    }

    /// Trim to the speech region using Silero.
    ///
    /// Returns `None` when there is **no speech at all**, which the caller uses to skip
    /// inference entirely. That is the cheapest possible fix for the most common
    /// hallucination case: Whisper fed near-silence confidently invents "Thank you." or
    /// "Thanks for watching!", and the only way to be sure it will not is to never ask.
    pub fn trim_to_speech(&mut self, pcm: &[f32]) -> Option<Vec<f32>> {
        let vad = self.vad.as_mut()?;

        let mut vp = WhisperVadParams::new();
        vp.set_threshold(0.5);
        vp.set_min_speech_duration(100); // ms
        vp.set_min_silence_duration(200); // ms
        // Keep a little audio either side: clipping a plosive changes the word.
        vp.set_speech_pad(120); // ms
        vp.set_samples_overlap(0.1);

        let segments = match vad.segments_from_samples(vp, pcm) {
            Ok(s) => s,
            Err(e) => {
                // A VAD failure must never lose the user's audio. Fall back to untrimmed.
                tracing::warn!("VAD failed ({e}); using untrimmed audio");
                return Some(pcm.to_vec());
            }
        };

        let n = segments.num_segments();
        if n <= 0 {
            return None; // genuinely no speech
        }

        // Timestamps are in centiseconds.
        let first = segments.get_segment_start_timestamp(0)?;
        let last = segments.get_segment_end_timestamp(n - 1)?;

        let start = ((first / 100.0) * TARGET_RATE as f32).max(0.0) as usize;
        let end = (((last / 100.0) * TARGET_RATE as f32) as usize).min(pcm.len());

        if end <= start {
            return None;
        }
        Some(pcm[start..end].to_vec())
    }
}

impl TranscriptionBackend for WhisperCppBackend {
    fn transcribe(&mut self, pcm16k: &[f32], hint: &Hint) -> Result<Transcript, BackendError> {
        let audio = validate_pcm(pcm16k)?;
        // Measure the REAL audio, not the padded buffer.
        //
        // validate_pcm pads short input up to 1.0 s so whisper.cpp behaves. Computing
        // audio_secs from the padded length meant it was always >= 1.0, which silently
        // killed the postprocess duration check (`audio_secs < 0.3` could never fire) and
        // diluted the words-per-second sanity test 5x. The unit test for that layer built
        // a Transcript by hand and so never noticed the layer was dead in production.
        let audio_secs = pcm16k.len() as f32 / TARGET_RATE as f32;

        let mut params = FullParams::new(SamplingStrategy::Greedy { best_of: 1 });
        params.set_n_threads(self.threads);
        params.set_language(Some(hint.language.as_deref().unwrap_or("en")));
        params.set_print_progress(false);
        params.set_print_special(false);
        params.set_print_realtime(false);
        params.set_print_timestamps(false);
        params.set_no_context(hint.prev_text.is_none());
        // Suppress non-speech tokens: (laughs), [MUSIC], etc. We want dictation, not
        // subtitles.
        params.set_suppress_nst(true);
        if let Some(p) = &hint.initial_prompt {
            params.set_initial_prompt(p);
        }
        if let Some(ac) = hint.audio_ctx {
            params.set_audio_ctx(ac as i32);
        }

        let t0 = Instant::now();
        self.state
            .full(params, &audio)
            .map_err(|e| BackendError::Inference(e.to_string()))?;
        let inference = t0.elapsed();

        let mut segments = Vec::new();
        let mut text = String::new();
        let mut max_no_speech = 0.0f32;

        for seg in self.state.as_iter() {
            let s = seg.to_str_lossy().unwrap_or_default().to_string();
            let p = seg.no_speech_probability();
            if p > max_no_speech {
                max_no_speech = p;
            }
            text.push_str(&s);
            segments.push(Segment {
                text: s,
                no_speech_prob: p,
                start_cs: seg.start_timestamp() as i64,
                end_cs: seg.end_timestamp() as i64,
            });
        }

        Ok(Transcript {
            text: text.trim().to_string(),
            segments,
            max_no_speech,
            inference,
            audio_secs,
        })
    }

    fn warm(&mut self) -> Result<(), BackendError> {
        if self.warmed {
            return Ok(());
        }
        // One second of silence. The first full() after load allocates its compute buffers
        // lazily and runs roughly twice as slow; paying that at startup rather than on the
        // user's first dictation is the entire point.
        let silence = vec![0.0f32; MIN_SAMPLES];
        let hint = Hint { language: Some("en".into()), ..Default::default() };
        let t0 = Instant::now();
        let _ = self.transcribe(&silence, &hint)?;
        tracing::info!("backend warmed in {:?}", t0.elapsed());
        self.warmed = true;
        Ok(())
    }

    fn info(&self) -> BackendInfo {
        BackendInfo {
            name: "whisper.cpp".into(),
            model: self.model_path.clone(),
            threads: self.threads,
        }
    }

    fn vad_trim(&mut self, pcm16k: &[f32]) -> Option<Vec<f32>> {
        if self.vad.is_none() {
            return Some(pcm16k.to_vec());
        }
        self.trim_to_speech(pcm16k)
    }

    fn has_vad(&self) -> bool {
        self.vad.is_some()
    }
}

/// Deterministic stand-in so the daemon can be tested without a model.
pub struct MockBackend {
    pub reply: String,
    pub latency: Duration,
    pub no_speech: f32,
}

impl Default for MockBackend {
    fn default() -> Self {
        Self {
            reply: "the quick brown fox".into(),
            latency: Duration::from_millis(50),
            no_speech: 0.01,
        }
    }
}

impl TranscriptionBackend for MockBackend {
    fn transcribe(&mut self, pcm16k: &[f32], _hint: &Hint) -> Result<Transcript, BackendError> {
        let audio = validate_pcm(pcm16k)?;
        let _ = &audio;
        std::thread::sleep(self.latency);
        Ok(Transcript {
            text: self.reply.clone(),
            segments: vec![Segment {
                text: self.reply.clone(),
                no_speech_prob: self.no_speech,
                start_cs: 0,
                end_cs: 100,
            }],
            max_no_speech: self.no_speech,
            inference: self.latency,
            audio_secs: pcm16k.len() as f32 / TARGET_RATE as f32,
        })
    }
    fn warm(&mut self) -> Result<(), BackendError> {
        Ok(())
    }
    fn info(&self) -> BackendInfo {
        BackendInfo { name: "mock".into(), model: "none".into(), threads: 1 }
    }

    fn vad_trim(&mut self, pcm16k: &[f32]) -> Option<Vec<f32>> {
        Some(pcm16k.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nan_never_reaches_the_ffi_boundary() {
        // ggml asserts call abort(), which panic=unwind cannot catch. If a NaN gets
        // across, the process dies and takes the user's dictation with it.
        let mut pcm = vec![0.1f32; 16_000];
        pcm[5000] = f32::NAN;
        assert!(matches!(validate_pcm(&pcm), Err(BackendError::Invalid(_))));
    }

    #[test]
    fn infinity_is_rejected() {
        let mut pcm = vec![0.1f32; 16_000];
        pcm[10] = f32::INFINITY;
        assert!(matches!(validate_pcm(&pcm), Err(BackendError::Invalid(_))));
    }

    #[test]
    fn empty_is_rejected() {
        assert!(matches!(validate_pcm(&[]), Err(BackendError::Invalid(_))));
    }

    #[test]
    fn short_audio_is_padded_not_rejected() {
        // A 200ms utterance is short, not invalid. Dropping it would lose a real word.
        let out = validate_pcm(&vec![0.1f32; 3200]).unwrap();
        assert_eq!(out.len(), MIN_SAMPLES);
        assert_eq!(out[0], 0.1);
        assert_eq!(out[MIN_SAMPLES - 1], 0.0, "tail should be silence padding");
    }

    #[test]
    fn hot_signal_is_clamped_not_rejected() {
        // A loud speaker should still be transcribed.
        let pcm = vec![2.5f32; 16_000];
        let out = validate_pcm(&pcm).unwrap();
        assert!(out.iter().all(|s| *s <= 1.0 && *s >= -1.0));
    }

    #[test]
    fn normal_audio_passes_through_unchanged() {
        let pcm: Vec<f32> = (0..16_000).map(|i| (i as f32 * 0.001).sin() * 0.5).collect();
        let out = validate_pcm(&pcm).unwrap();
        assert_eq!(out, pcm);
    }

    #[test]
    fn audio_secs_reports_real_audio_not_padding() {
        // Regression: audio_secs was computed from the PADDED buffer, so it was always
        // >= 1.0 and the postprocess duration filter could never fire.
        let mut b = MockBackend::default();
        let short = vec![0.1f32; 3200]; // 200 ms
        let t = b.transcribe(&short, &Hint::default()).unwrap();
        assert!(
            (t.audio_secs - 0.2).abs() < 0.001,
            "expected 0.2s of real audio, got {}",
            t.audio_secs
        );
    }

    #[test]
    fn mock_backend_round_trips() {
        let mut b = MockBackend::default();
        let t = b.transcribe(&vec![0.0f32; 16_000], &Hint::default()).unwrap();
        assert_eq!(t.text, "the quick brown fox");
        assert_eq!(t.audio_secs, 1.0);
    }

    #[test]
    fn mock_backend_also_validates() {
        // The mock must enforce the same contract, or tests would pass on audio the real
        // backend would refuse.
        let mut b = MockBackend::default();
        assert!(b.transcribe(&[], &Hint::default()).is_err());
    }
}
