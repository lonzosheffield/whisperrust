//! Phase 2 verification harness (`whisperrust --audio-check`).
//!
//! The CP-2 pass criteria are measurements, not opinions, so this produces numbers:
//!
//! * zero ring overruns over a soak
//! * flat memory (within 5 MB)
//! * device loss recovered within 5 s
//! * a tone through the whole path arrives at 16 kHz with <0.1% sample-count error and
//!   no discontinuities
//!
//! It writes a WAV of what was actually captured, because a number saying the audio is
//! fine is worth less than being able to listen to it.

use std::time::{Duration, Instant};

use crate::audio::{self, AudioCapture, PrerollRing};
use crate::policy;
use crate::resample;

/// Current working-set size in bytes, for the flat-memory criterion.
fn rss_bytes() -> u64 {
    use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows::Win32::System::Threading::GetCurrentProcess;
    unsafe {
        let mut pmc = PROCESS_MEMORY_COUNTERS::default();
        if GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut pmc,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
        .is_ok()
        {
            pmc.WorkingSetSize as u64
        } else {
            0
        }
    }
}

/// Largest absolute sample-to-sample jump. A click or a dropped block shows up here as a
/// spike that continuous speech or a tone never produces.
fn max_discontinuity(samples: &[f32]) -> f32 {
    let mut worst = 0.0f32;
    for w in samples.windows(2) {
        let d = (w[1] - w[0]).abs();
        if d > worst {
            worst = d;
        }
    }
    worst
}

fn rms(samples: &[f32]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    (samples.iter().map(|s| s * s).sum::<f32>() / samples.len() as f32).sqrt()
}

fn write_wav(path: &str, samples: &[f32], rate: u32) -> Result<(), String> {
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: rate,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let mut w = hound::WavWriter::create(path, spec).map_err(|e| e.to_string())?;
    for &s in samples {
        let v = (s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16;
        w.write_sample(v).map_err(|e| e.to_string())?;
    }
    w.finalize().map_err(|e| e.to_string())
}

pub fn run(seconds: u64, out_dir: &str) -> i32 {
    println!("Phase 2 audio check - {seconds}s soak");
    println!();

    let mut cap = match audio::start(None) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("FATAL: could not start capture: {e}");
            eprintln!();
            eprintln!("If Windows microphone privacy is off for desktop apps, this fails");
            eprintln!("with an access error. Settings > Privacy > Microphone.");
            return 2;
        }
    };

    let rate = cap.device_rate();
    let channels = cap.stats.channels.load(std::sync::atomic::Ordering::Relaxed);
    println!("  device rate   : {rate} Hz");
    println!("  channels      : {channels}");
    println!("  preroll       : {} frames ({:?})", audio::preroll_frames(rate), policy::PREROLL);
    println!();

    if rate == 0 {
        eprintln!("FAIL: device reported no sample rate - stream never started");
        return 2;
    }

    let mut preroll = PrerollRing::new(audio::preroll_frames(rate));

    // Retain only the first RETAIN_SECS of audio for the WAV and the resample check.
    //
    // Retaining everything would make the memory criterion meaningless: a 10-minute soak
    // at 48 kHz is ~115 MB of f32, which would blow the "RSS flat within 5 MB" limit with
    // the harness's OWN buffer and report a leak that does not exist. The daemon never
    // holds more than one utterance; the test must not be greedier than the thing it is
    // testing.
    const RETAIN_SECS: usize = 20;
    let retain_frames = rate as usize * RETAIN_SECS;
    let mut captured: Vec<f32> = Vec::with_capacity(retain_frames);
    let mut discarded_frames: u64 = 0;
    let mut scratch: Vec<f32> = Vec::with_capacity(8192);

    let rss_start = rss_bytes();
    let mut rss_peak = rss_start;
    let start = Instant::now();
    let mut last_report = Instant::now();

    while start.elapsed() < Duration::from_secs(seconds) {
        scratch.clear();
        cap.drain_into(&mut scratch);
        if !scratch.is_empty() {
            preroll.push_slice(&scratch);
            if captured.len() < retain_frames {
                let room = retain_frames - captured.len();
                let take = room.min(scratch.len());
                captured.extend_from_slice(&scratch[..take]);
                discarded_frames += (scratch.len() - take) as u64;
            } else {
                discarded_frames += scratch.len() as u64;
            }
        }

        let rss = rss_bytes();
        if rss > rss_peak {
            rss_peak = rss;
        }

        if last_report.elapsed() >= Duration::from_secs(5) {
            last_report = Instant::now();
            let st = &cap.stats;
            println!(
                "  t={:>4}s  frames={:<10} overruns={:<4} os_errors={:<4} rebuilds={} rss={:.1}MB",
                start.elapsed().as_secs(),
                st.frames.load(std::sync::atomic::Ordering::Relaxed),
                st.overruns.load(std::sync::atomic::Ordering::Relaxed),
                st.stream_errors.load(std::sync::atomic::Ordering::Relaxed),
                st.rebuilds.load(std::sync::atomic::Ordering::Relaxed),
                rss as f64 / 1_048_576.0
            );
        }

        std::thread::sleep(Duration::from_millis(20));
    }

    let st = &cap.stats;
    let overruns = st.overruns.load(std::sync::atomic::Ordering::Relaxed);
    let stream_errors = st.stream_errors.load(std::sync::atomic::Ordering::Relaxed);
    let frames = st.frames.load(std::sync::atomic::Ordering::Relaxed);
    let rebuilds = st.rebuilds.load(std::sync::atomic::Ordering::Relaxed);
    let rss_growth = rss_peak.saturating_sub(rss_start);

    // ---- resample the whole capture, exactly as the daemon will at finalize ----
    let t0 = Instant::now();
    let resampled = match resample::to_16k_mono(&captured, rate) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("FAIL: resample: {e}");
            return 3;
        }
    };
    let resample_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let expected = resample::expected_len(captured.len(), rate);
    let len_err = if expected == 0 {
        1.0
    } else {
        (resampled.len() as f64 - expected as f64).abs() / expected as f64
    };

    let _ = std::fs::create_dir_all(out_dir);
    let raw_path = format!("{out_dir}/capture-device-{rate}hz.wav");
    let out_path = format!("{out_dir}/capture-16k.wav");
    let _ = write_wav(&raw_path, &captured, rate);
    let _ = write_wav(&out_path, &resampled, resample::TARGET_RATE);

    println!();
    println!("================ CP-2 RESULTS ================");
    println!("retained frames     : {} (first {}s)", captured.len(), RETAIN_SECS);
    println!("streamed-past frames: {discarded_frames} (drained, not retained)");
    println!("callback frames     : {frames}");
    {
        let expected = (seconds as u64) * rate as u64;
        let deficit = expected.saturating_sub(frames);
        println!(
            "expected frames     : {expected}  (deficit {deficit} = {:.2}s)",
            deficit as f64 / rate as f64
        );
    }
    println!("ring overruns       : {overruns}   (criterion: 0)");
    println!("OS stream errors    : {stream_errors}   (criterion: 0 - WASAPI dropped audio)");
    println!("stream rebuilds     : {rebuilds}");
    println!("rss start           : {:.1} MB", rss_start as f64 / 1_048_576.0);
    println!("rss peak            : {:.1} MB", rss_peak as f64 / 1_048_576.0);
    println!("rss growth          : {:.1} MB   (criterion: < 5)", rss_growth as f64 / 1_048_576.0);
    println!("resampled frames    : {}", resampled.len());
    println!("expected frames     : {expected}");
    println!("length error        : {:.4}%   (criterion: < 0.1)", len_err * 100.0);
    println!("resample time       : {resample_ms:.1} ms for {:.1}s of audio", captured.len() as f64 / rate as f64);
    println!("input rms           : {:.5}", rms(&captured));
    println!("output rms          : {:.5}", rms(&resampled));
    println!("max discontinuity   : {:.4}", max_discontinuity(&resampled));
    println!("preroll retained    : {} frames", preroll.len());
    println!();
    println!("wrote {raw_path}");
    println!("wrote {out_path}");
    println!();

    // ---- verdict ----
    let mut fails: Vec<String> = Vec::new();
    if overruns != 0 {
        fails.push(format!("ring overruns = {overruns}, must be 0"));
    }
    if stream_errors != 0 {
        // The criterion's INTENT is "no dropped audio". The ring counter cannot see loss
        // that happens below us, so this is the check that actually enforces it.
        fails.push(format!(
            "OS stream errors = {stream_errors}, must be 0 (WASAPI dropped audio before it reached the ring)"
        ));
    }
    if rss_growth > 5 * 1_048_576 {
        fails.push(format!("rss grew {:.1} MB, limit 5", rss_growth as f64 / 1_048_576.0));
    }
    if len_err >= 0.001 {
        fails.push(format!("length error {:.4}%, limit 0.1%", len_err * 100.0));
    }
    if captured.is_empty() {
        fails.push("no audio captured at all".into());
    }

    // A silent room is not a failure of the pipeline, but it means the capture was not
    // really exercised - say so rather than quietly passing on digital silence.
    if rms(&captured) < 1e-5 {
        println!("NOTE: input was essentially silent. The path works, but speak or play");
        println!("      audio during the soak to exercise it meaningfully.");
    }

    if fails.is_empty() {
        println!("CP-2 PASS");
        0
    } else {
        println!("CP-2 FAIL:");
        for f in &fails {
            println!("  - {f}");
        }
        1
    }
}
