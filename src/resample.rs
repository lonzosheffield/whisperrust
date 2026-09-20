//! Sample-rate conversion to Whisper's required 16 kHz.
//!
//! # Why this is not in the audio callback
//!
//! The original plan resampled inside the cpal callback. That callback is a real-time
//! thread: it must not allocate, lock, or do unbounded work, and resampling is real DSP
//! with internal buffers. Doing it there is where xruns come from.
//!
//! Instead the callback only downmixes to mono and pushes raw device-rate samples into a
//! lock-free ring. Resampling happens **once, on the worker thread, at finalize** — the
//! whole utterance in one call. For a 5 s utterance at 48 kHz that is a few milliseconds,
//! and it is off the real-time path entirely.
//!
//! A useful side effect: the ring holds unmodified device audio, so a debug WAV is what
//! the microphone actually produced, not something already mangled by our own DSP.
//!
//! # Why a real resampler and not just "take every third sample"
//!
//! 48000 -> 16000 is exactly 3:1, and naive decimation is tempting. It is also wrong:
//! dropping samples without first removing everything above 8 kHz folds that energy back
//! down as aliasing, landing squarely in the speech band. Whisper is trained on properly
//! band-limited audio; feeding it aliased input degrades accuracy in a way that looks like
//! a bad model rather than a bad pipeline.
//!
//! Device rates are also not always 48 kHz. 44100 -> 16000 is 2.75625:1, not an integer,
//! so a general resampler is required regardless.

use audioadapter_buffers::direct::InterleavedSlice;
use rubato::{Fft, FixedSync, Resampler};

/// Whisper's fixed input rate. Not configurable; the model requires it.
pub const TARGET_RATE: u32 = 16_000;

/// Frames per processing chunk. Only affects internal buffering, not output.
const CHUNK: usize = 1024;

#[derive(Debug)]
pub enum ResampleError {
    Construct(String),
    Process(String),
}

impl std::fmt::Display for ResampleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResampleError::Construct(e) => write!(f, "resampler construction failed: {e}"),
            ResampleError::Process(e) => write!(f, "resampling failed: {e}"),
        }
    }
}

/// Convert mono `input` at `in_rate` to mono 16 kHz.
///
/// Returns the input unchanged when it is already at the target rate, which is the common
/// case for a WAV fixture and avoids pointlessly filtering already-correct audio.
pub fn to_16k_mono(input: &[f32], in_rate: u32) -> Result<Vec<f32>, ResampleError> {
    if in_rate == TARGET_RATE {
        return Ok(input.to_vec());
    }
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let mut resampler = Fft::<f32>::new(
        in_rate as usize,
        TARGET_RATE as usize,
        CHUNK,
        1, // mono
        FixedSync::Input,
    )
    .map_err(|e| ResampleError::Construct(e.to_string()))?;

    // rubato 5 takes an `Adapter` describing the sample layout rather than a concrete
    // buffer type. For mono, interleaved and planar are the same thing, so the input
    // slice can be wrapped directly - no copy.
    let adapter = InterleavedSlice::new(input, 1, input.len())
        .map_err(|e| ResampleError::Process(format!("adapter: {e:?}")))?;

    let out = resampler
        .process_all(&adapter, input.len(), None)
        .map_err(|e| ResampleError::Process(e.to_string()))?;

    // Mono, so the interleaved result is already the sample sequence we want.
    //
    // process_all can return a buffer sized to the resampler's maximum rather than the
    // exact output length, so trim to the arithmetically expected count. Without this a
    // short utterance would carry a tail of silence into the model.
    let want = expected_len(input.len(), in_rate);
    let mut data = out.take_data();
    if data.len() > want {
        data.truncate(want);
    }
    Ok(data)
}

/// Average interleaved frames down to mono.
///
/// Deliberately a plain loop over chunks: this is the one operation that DOES run in the
/// audio callback, so it must not allocate or use iterator adapters that might.
#[inline]
pub fn downmix_into(interleaved: &[f32], channels: usize, out: &mut [f32]) -> usize {
    if channels <= 1 {
        let n = interleaved.len().min(out.len());
        out[..n].copy_from_slice(&interleaved[..n]);
        return n;
    }
    let frames = (interleaved.len() / channels).min(out.len());
    let inv = 1.0 / channels as f32;
    for f in 0..frames {
        let base = f * channels;
        let mut sum = 0.0f32;
        for c in 0..channels {
            sum += interleaved[base + c];
        }
        out[f] = sum * inv;
    }
    frames
}

/// Expected output length for a given input length, for sanity checks.
pub fn expected_len(input_len: usize, in_rate: u32) -> usize {
    ((input_len as u64 * TARGET_RATE as u64) / in_rate as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::f32::consts::PI;

    fn tone(freq: f32, rate: u32, secs: f32) -> Vec<f32> {
        let n = (rate as f32 * secs) as usize;
        (0..n)
            .map(|i| (2.0 * PI * freq * i as f32 / rate as f32).sin() * 0.5)
            .collect()
    }

    /// Dominant frequency via a coarse DFT over a few candidate bins.
    fn dominant_freq(samples: &[f32], rate: u32) -> f32 {
        let n = samples.len().min(8192);
        let s = &samples[..n];
        let mut best = (0.0f32, 0.0f32);
        let mut f = 100.0f32;
        while f < (rate as f32 / 2.0) - 100.0 {
            let (mut re, mut im) = (0.0f32, 0.0f32);
            for (i, x) in s.iter().enumerate() {
                let ang = 2.0 * PI * f * i as f32 / rate as f32;
                re += x * ang.cos();
                im -= x * ang.sin();
            }
            let mag = (re * re + im * im).sqrt();
            if mag > best.1 {
                best = (f, mag);
            }
            f += 10.0;
        }
        best.0
    }

    #[test]
    fn passthrough_when_already_16k() {
        let input = tone(440.0, 16_000, 0.1);
        let out = to_16k_mono(&input, 16_000).unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn length_is_correct_for_48k() {
        // The Phase 2 pass criterion is <0.1% sample-count error.
        let input = tone(440.0, 48_000, 3.0);
        let out = to_16k_mono(&input, 48_000).unwrap();
        let expect = expected_len(input.len(), 48_000);
        let err = (out.len() as f64 - expect as f64).abs() / expect as f64;
        assert!(
            err < 0.001,
            "length error {:.4}% (got {}, expected {})",
            err * 100.0,
            out.len(),
            expect
        );
    }

    #[test]
    fn length_is_correct_for_44k1() {
        // Non-integer ratio: 2.75625:1.
        let input = tone(440.0, 44_100, 3.0);
        let out = to_16k_mono(&input, 44_100).unwrap();
        let expect = expected_len(input.len(), 44_100);
        let err = (out.len() as f64 - expect as f64).abs() / expect as f64;
        assert!(err < 0.001, "length error {:.4}%", err * 100.0);
    }

    #[test]
    fn tone_frequency_survives_resampling() {
        // The real test of correctness: a 1 kHz tone must still be 1 kHz afterwards.
        let input = tone(1000.0, 48_000, 0.5);
        let out = to_16k_mono(&input, 48_000).unwrap();
        let f = dominant_freq(&out, TARGET_RATE);
        assert!((f - 1000.0).abs() < 30.0, "expected ~1000 Hz, measured {f} Hz");
    }

    #[test]
    fn high_frequency_is_filtered_not_aliased() {
        // THE reason we do not just take every third sample. A 7 kHz tone is above the
        // 8 kHz Nyquist limit of 16 kHz output... actually just below it, so it should
        // survive. A 10 kHz tone is above it and must be ATTENUATED, not folded back down
        // into the speech band as a phantom ~6 kHz tone.
        let input = tone(10_000.0, 48_000, 0.5);
        let out = to_16k_mono(&input, 48_000).unwrap();

        let energy: f32 = out.iter().map(|x| x * x).sum::<f32>() / out.len() as f32;
        let input_energy: f32 = input.iter().map(|x| x * x).sum::<f32>() / input.len() as f32;

        assert!(
            energy < input_energy * 0.1,
            "10 kHz content was not removed: in {input_energy:.5} out {energy:.5} - \
             naive decimation would alias this into the speech band"
        );
    }

    #[test]
    fn empty_input_is_handled() {
        assert!(to_16k_mono(&[], 48_000).unwrap().is_empty());
    }

    #[test]
    fn downmix_stereo_averages() {
        let interleaved = [1.0, 0.0, 0.5, 0.5, -1.0, 1.0];
        let mut out = [0.0f32; 3];
        let n = downmix_into(&interleaved, 2, &mut out);
        assert_eq!(n, 3);
        assert_eq!(out, [0.5, 0.5, 0.0]);
    }

    #[test]
    fn downmix_mono_is_a_copy() {
        let mono = [0.1, 0.2, 0.3];
        let mut out = [0.0f32; 3];
        let n = downmix_into(&mono, 1, &mut out);
        assert_eq!(n, 3);
        assert_eq!(out, mono);
    }

    #[test]
    fn downmix_respects_output_capacity() {
        // The callback's staging buffer is fixed; overrunning it would be a memory bug on
        // the real-time thread.
        let interleaved = [0.0f32; 100];
        let mut out = [0.0f32; 10];
        let n = downmix_into(&interleaved, 2, &mut out);
        assert_eq!(n, 10);
    }
}
