//! Phase 0 smoke test — does whisper-rs build and transcribe on this machine?
//!
//! CP-0 pass criterion (a): "whisper-rs CPU build transcribes a known WAV."
//!
//! Deliberately minimal. This proves the toolchain (CMake + MSVC + bindgen/libclang) and
//! the FFI boundary work. It is NOT the benchmark — that is Phase 1b, with a proper
//! corpus and a real metric. The timing printed here is one sample on a cold cache and
//! should not be quoted as a latency figure.

use std::path::PathBuf;
use std::time::Instant;

use whisper_rs::{FullParams, SamplingStrategy, WhisperContext, WhisperContextParameters};

fn load_wav_16k_mono(path: &PathBuf) -> Result<Vec<f32>, String> {
    let mut reader = hound::WavReader::open(path).map_err(|e| format!("open wav: {e}"))?;
    let spec = reader.spec();
    println!(
        "  wav: {} Hz, {} ch, {} bits, {:?}",
        spec.sample_rate, spec.channels, spec.bits_per_sample, spec.sample_format
    );

    if spec.sample_rate != 16_000 {
        return Err(format!(
            "expected 16 kHz, got {} Hz - this smoke test does not resample (that is Phase 2)",
            spec.sample_rate
        ));
    }

    let samples: Vec<f32> = match spec.sample_format {
        hound::SampleFormat::Int => reader
            .samples::<i16>()
            .map(|s| s.map(|v| v as f32 / 32768.0))
            .collect::<Result<_, _>>()
            .map_err(|e| format!("read i16: {e}"))?,
        hound::SampleFormat::Float => reader
            .samples::<f32>()
            .collect::<Result<_, _>>()
            .map_err(|e| format!("read f32: {e}"))?,
    };

    // Downmix if needed.
    let mono = if spec.channels > 1 {
        let ch = spec.channels as usize;
        samples.chunks(ch).map(|f| f.iter().sum::<f32>() / ch as f32).collect()
    } else {
        samples
    };

    Ok(mono)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let model = PathBuf::from(
        args.get(1)
            .cloned()
            .unwrap_or_else(|| "models/ggml-tiny.en.bin".to_string()),
    );
    let wav = PathBuf::from(
        args.get(2)
            .cloned()
            .unwrap_or_else(|| "samples/jfk.wav".to_string()),
    );

    println!("whisper-hello - Phase 0 smoke test");
    println!("  model: {}", model.display());
    println!("  wav:   {}", wav.display());

    if !model.exists() {
        eprintln!("\nFATAL: model not found at {}", model.display());
        std::process::exit(2);
    }
    if !wav.exists() {
        eprintln!("\nFATAL: wav not found at {}", wav.display());
        std::process::exit(2);
    }

    let pcm = match load_wav_16k_mono(&wav) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("\nFATAL: {e}");
            std::process::exit(2);
        }
    };
    println!(
        "  audio: {} samples, {:.2} s",
        pcm.len(),
        pcm.len() as f32 / 16_000.0
    );

    println!("\nloading model...");
    let t_load = Instant::now();
    let ctx = match WhisperContext::new_with_params(
        model.to_str().unwrap(),
        WhisperContextParameters::default(),
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("FATAL: load model: {e}");
            std::process::exit(3);
        }
    };
    println!("  loaded in {:?}", t_load.elapsed());

    println!("\nsystem info: {}", whisper_rs::print_system_info());

    let mut state = ctx.create_state().expect("create state");

    let mut params = FullParams::new(SamplingStrategy::Greedy { best_of: 1 });
    params.set_n_threads(std::env::var("THREADS").ok().and_then(|v| v.parse().ok()).unwrap_or(6));
    params.set_language(Some("en"));
    params.set_print_progress(false);
    params.set_print_special(false);
    params.set_print_realtime(false);
    params.set_print_timestamps(false);
    params.set_single_segment(false);
    params.set_no_context(true);
    params.set_suppress_nst(true);

    // Run several passes. The first is always ~2x slow (lazy compute-buffer allocation
    // plus cold caches), which is why the daemon will warm() at startup. Only the warm
    // passes carry any signal.
    let passes: usize = std::env::var("PASSES").ok().and_then(|v| v.parse().ok()).unwrap_or(3);
    println!("\ntranscribing ({passes} passes)...");

    let mut elapsed = std::time::Duration::ZERO;
    let mut timings = Vec::new();
    for p in 0..passes {
        let mut pp = FullParams::new(SamplingStrategy::Greedy { best_of: 1 });
        pp.set_n_threads(std::env::var("THREADS").ok().and_then(|v| v.parse().ok()).unwrap_or(6));
        pp.set_language(Some("en"));
        pp.set_print_progress(false);
        pp.set_print_special(false);
        pp.set_print_realtime(false);
        pp.set_print_timestamps(false);
        pp.set_no_context(true);
        pp.set_suppress_nst(true);

        let t_run = Instant::now();
        if let Err(e) = state.full(pp, &pcm) {
            eprintln!("FATAL: full(): {e}");
            std::process::exit(4);
        }
        let d = t_run.elapsed();
        timings.push(d);
        println!(
            "  pass {}: {:>8.0} ms   RTF {:.3}{}",
            p,
            d.as_secs_f64() * 1000.0,
            d.as_secs_f64() / (pcm.len() as f64 / 16_000.0),
            if p == 0 { "   <- cold, ignore" } else { "" }
        );
        elapsed = d;
    }
    let _ = &params;

    let n = state.full_n_segments();
    let mut text = String::new();
    let mut worst_no_speech = 0.0f32;
    for seg in state.as_iter() {
        match seg.to_str_lossy() {
            Ok(s) => text.push_str(&s),
            Err(e) => eprintln!("  warn: segment decode: {e}"),
        }
        // Same signal the hallucination filter will key on in Phase 3.
        let p = seg.no_speech_probability();
        if p > worst_no_speech {
            worst_no_speech = p;
        }
    }

    println!("\n================ RESULT ================");
    println!("segments : {n}");
    println!("wall     : {:?}  (single cold sample - NOT a benchmark)", elapsed);
    println!("no_speech: {:.4} (max across segments)", worst_no_speech);
    println!("text     : {}", text.trim());
    println!("========================================");

    if text.trim().is_empty() {
        eprintln!("\nFAIL: empty transcription");
        std::process::exit(5);
    }
    println!("\nPASS: whisper-rs built and transcribed on this machine.");
}
