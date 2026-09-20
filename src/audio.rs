//! Always-on microphone capture with a supervised WASAPI stream.
//!
//! # Why the stream is always running
//!
//! Opening a WASAPI stream costs hundreds of milliseconds. Opening it on PTT-down would
//! clip the first syllable of every dictation. So the stream runs from daemon start and
//! the hotkey only controls whether frames are *retained*.
//!
//! The cost is that the microphone is genuinely open the whole time the daemon runs. That
//! is an honest trade and it is why the tray indicator has to distinguish "listening" from
//! "retaining", and why the OS microphone indicator staying lit is expected rather than a
//! bug.
//!
//! # The preroll ring
//!
//! A rolling 400 ms of audio is always retained. On PTT-down it is prepended to the
//! utterance, which is why the first word is never clipped even though humans start
//! speaking slightly before the key fully registers.
//!
//! **400 ms, not 1.5 s.** A long preroll captures speech from *before* the key was
//! pressed, and VAD will not strip it because it is speech — it would paste the tail of
//! whatever the user was saying to someone else in the room. 400 ms is human reaction
//! time; anything materially longer is a privacy problem wearing a feature's clothes.
//!
//! # Real-time discipline
//!
//! The cpal callback runs on a real-time thread. It does exactly two things: downmix to
//! mono, and push into a lock-free SPSC ring. No allocation, no locks, no logging, no
//! syscalls, no resampling. Everything else happens on the worker.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{SampleFormat, StreamConfig};
use rtrb::{Consumer, Producer, RingBuffer};

use crate::policy;
use crate::resample;

/// Ring capacity in frames. Two seconds at 48 kHz is generous: the worker drains every
/// ~50 ms, so this only has to absorb scheduling hiccups, not sustained backpressure.
const RING_FRAMES: usize = 96_000;

/// Staging buffer inside the callback. Sized for the largest plausible WASAPI period.
const STAGE_FRAMES: usize = 8192;

/// Shared counters. Exposed because "zero ring overruns" is a Phase 2 pass criterion and
/// an unobservable guarantee is not a guarantee.
#[derive(Debug, Default)]
pub struct AudioStats {
    /// Set when a stream build fails, so `start()` can report WHY rather than just
    /// timing out with a bare "no sample rate".
    pub last_error: std::sync::Mutex<Option<String>>,
    /// Frames dropped because the worker could not keep up. Must stay 0.
    pub overruns: AtomicU64,
    /// Total frames captured since start.
    pub frames: AtomicU64,
    /// Milliseconds since the last callback, for the silent-death watchdog.
    pub last_callback_ms: AtomicU64,
    /// How many times the stream had to be rebuilt.
    pub rebuilds: AtomicU64,
    /// Device sample rate currently in use.
    pub rate: AtomicUsize,
    /// Channel count currently in use.
    pub channels: AtomicUsize,
}

fn now_ms() -> u64 {
    unsafe { windows::Win32::System::SystemInformation::GetTickCount64() }
}

/// A rolling buffer of the most recent `capacity` frames, at device rate.
///
/// Plain `VecDeque`-style over a Vec: this lives on the worker, not the callback, so an
/// occasional bounds check costs nothing.
pub struct PrerollRing {
    buf: Vec<f32>,
    head: usize,
    len: usize,
}

impl PrerollRing {
    pub fn new(capacity: usize) -> Self {
        Self { buf: vec![0.0; capacity.max(1)], head: 0, len: 0 }
    }

    pub fn push_slice(&mut self, src: &[f32]) {
        let cap = self.buf.len();
        if src.len() >= cap {
            // Input larger than the ring: keep only the newest `cap` samples.
            self.buf.copy_from_slice(&src[src.len() - cap..]);
            self.head = 0;
            self.len = cap;
            return;
        }
        for &s in src {
            self.buf[self.head] = s;
            self.head = (self.head + 1) % cap;
            if self.len < cap {
                self.len += 1;
            }
        }
    }

    /// Oldest-to-newest copy of the retained audio.
    pub fn snapshot(&self) -> Vec<f32> {
        let cap = self.buf.len();
        let mut out = Vec::with_capacity(self.len);
        let start = (self.head + cap - self.len) % cap;
        for i in 0..self.len {
            out.push(self.buf[(start + i) % cap]);
        }
        out
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Handle to the running capture.
pub struct AudioCapture {
    pub stats: Arc<AudioStats>,
    consumer: Option<Consumer<f32>>,
    /// The supervisor publishes a fresh consumer here whenever it rebuilds the stream.
    ///
    /// An `rtrb` ring is split into a Producer and a Consumer, and the Producer is moved
    /// into the cpal callback closure, which must be `'static`. When the stream dies the
    /// Producer dies with it, so a rebuild necessarily creates a NEW ring - and the old
    /// Consumer is then attached to nothing.
    ///
    /// Handing the new Consumer across a channel keeps the drain path lock-free (this is
    /// polled from the worker, never from the audio callback) while still letting capture
    /// survive a device disappearing, which is a Phase 2 pass criterion.
    new_consumers: crossbeam_channel::Receiver<Consumer<f32>>,
    shutdown: Arc<AtomicBool>,
}

impl Drop for AudioCapture {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

impl AudioCapture {
    /// Drain everything currently available into `out`. Never blocks.
    pub fn drain_into(&mut self, out: &mut Vec<f32>) -> usize {
        // Adopt a rebuilt stream's ring if one is waiting. Taking the newest means audio
        // captured during the outage is dropped rather than replayed out of order - a gap
        // is honest, a scrambled utterance is not.
        while let Ok(c) = self.new_consumers.try_recv() {
            self.consumer = Some(c);
        }

        let Some(consumer) = self.consumer.as_mut() else {
            return 0;
        };
        let mut n = 0;
        while let Ok(s) = consumer.pop() {
            out.push(s);
            n += 1;
        }
        n
    }

    pub fn device_rate(&self) -> u32 {
        self.stats.rate.load(Ordering::Relaxed) as u32
    }

    /// True if the stream has stopped producing callbacks.
    ///
    /// WASAPI can fail *silently*: no error callback, just no more audio. Sleep/resume and
    /// some driver resets present this way, so absence of data is the only signal.
    pub fn is_silent(&self, threshold: Duration) -> bool {
        let last = self.stats.last_callback_ms.load(Ordering::Relaxed);
        if last == 0 {
            return false;
        }
        now_ms().saturating_sub(last) > threshold.as_millis() as u64
    }
}

/// Human-readable device name.
///
/// cpal 0.18 replaced `Device::name()` with `description()`, which returns a richer
/// `DeviceDescription`. Wrapped here so a device that refuses to identify itself degrades
/// to "unknown" rather than taking the supervisor down - a mic that will not describe
/// itself is still a mic we can record from.
fn device_name(d: &cpal::Device) -> Option<String> {
    use cpal::traits::DeviceTrait;
    d.description().ok().map(|desc| desc.name().to_string())
}

fn pick_config(device: &cpal::Device) -> Result<(StreamConfig, SampleFormat), String> {
    let mut configs: Vec<_> = device
        .supported_input_configs()
        .map_err(|e| format!("supported_input_configs: {e}"))?
        .collect();

    if configs.is_empty() {
        return Err("device reports no supported input configs".into());
    }

    // Devices commonly advertise the same rate in several sample formats. The C920 here
    // offers 48 kHz x4 four times over, and the first one happens to be I24 - which is
    // why the first run failed with "unsupported sample format I24" rather than anything
    // to do with rates. So choose the FORMAT deliberately, not just the rate.
    fn format_rank(f: SampleFormat) -> u8 {
        match f {
            SampleFormat::F32 => 0, // no conversion at all
            SampleFormat::I16 => 1, // cheap, lossless to f32
            SampleFormat::I32 => 2,
            SampleFormat::I24 => 3,
            SampleFormat::U16 => 4,
            SampleFormat::U8 => 5,
            SampleFormat::I8 => 6,
            // F64 is deliberately absent: no microphone produces it, and supporting it
            // would force the whole conversion path to f64 for a case that never occurs.
            _ => 200,
        }
    }

    // Prefer 16 kHz if the device truly supports it (then no resampling is needed at
    // all), then 48 kHz (exact 3:1), then 44.1 kHz.
    //
    // NOTE: we never *force* a rate onto the StreamConfig. WASAPI shared mode will not
    // honor an arbitrary rate, and the original plan's `sample_rate: 16000` would simply
    // have failed to open on this hardware.
    let preferred_rates = [16_000u32, 48_000, 44_100];
    let mut best: Option<(u8, u32, cpal::SupportedStreamConfigRange)> = None;

    for (rate_rank, want) in preferred_rates.iter().enumerate() {
        for c in &configs {
            if c.min_sample_rate() <= *want && *want <= c.max_sample_rate() {
                let fr = format_rank(c.sample_format());
                if fr >= 200 {
                    continue; // we cannot convert this one
                }
                let score = (rate_rank as u8) * 10 + fr;
                if best.as_ref().map(|(s, _, _)| score < *s).unwrap_or(true) {
                    best = Some((score, *want, c.clone()));
                }
            }
        }
    }

    if let Some((_, rate, range)) = best {
        let cfg = range.with_sample_rate(rate);
        return Ok((cfg.config(), cfg.sample_format()));
    }

    // Nothing at a preferred rate in a format we handle: take the best format available
    // at any rate and resample from there.
    configs.retain(|c| format_rank(c.sample_format()) < 200);
    if configs.is_empty() {
        return Err("device offers no sample format this build can convert".into());
    }
    configs.sort_by_key(|c| format_rank(c.sample_format()));
    let c = configs.remove(0).with_max_sample_rate();
    Ok((c.config(), c.sample_format()))
}

fn build_stream(
    device: &cpal::Device,
    stats: Arc<AudioStats>,
    mut producer: Producer<f32>,
) -> Result<cpal::Stream, String> {
    let (config, fmt) = pick_config(device)?;
    let channels = config.channels as usize;

    stats.rate.store(config.sample_rate as usize, Ordering::Relaxed);
    stats.channels.store(channels, Ordering::Relaxed);

    let err_stats = Arc::clone(&stats);
    let err_fn = move |e| {
        // Cannot log from the RT thread cheaply; record and let the supervisor react.
        err_stats.last_callback_ms.store(0, Ordering::Relaxed);
        tracing::error!("audio stream error: {e}");
    };

    // The callback. Two operations, no allocation, no locks.
    macro_rules! make {
        ($sample:ty) => {{
            let cb_stats = Arc::clone(&stats);
            let mut stage = vec![0.0f32; STAGE_FRAMES];
            device
                .build_input_stream(
                    config.clone(),
                    move |data: &[$sample], _: &cpal::InputCallbackInfo| {
                        cb_stats.last_callback_ms.store(now_ms(), Ordering::Relaxed);

                        // Convert to f32 in the staging buffer (already allocated).
                        let frames = (data.len() / channels).min(STAGE_FRAMES);
                        for f in 0..frames {
                            let base = f * channels;
                            let mut sum = 0.0f32;
                            for c in 0..channels {
                                sum += <$sample as cpal::Sample>::to_float_sample(data[base + c]);
                            }
                            stage[f] = sum / channels as f32;
                        }

                        cb_stats.frames.fetch_add(frames as u64, Ordering::Relaxed);

                        // Push into the ring. If the consumer has stalled we drop the
                        // OLDEST data implicitly by refusing new - and count it, because
                        // a silent drop is how "it works on my machine" happens.
                        let mut dropped = 0u64;
                        for i in 0..frames {
                            if producer.push(stage[i]).is_err() {
                                dropped += 1;
                            }
                        }
                        if dropped > 0 {
                            cb_stats.overruns.fetch_add(dropped, Ordering::Relaxed);
                        }
                    },
                    err_fn,
                    None,
                )
                .map_err(|e| format!("build_input_stream: {e}"))
        }};
    }

    let stream = match fmt {
        SampleFormat::F32 => make!(f32)?,
        SampleFormat::I16 => make!(i16)?,
        SampleFormat::I32 => make!(i32)?,
        SampleFormat::I24 => make!(cpal::I24)?,
        SampleFormat::U16 => make!(u16)?,
        SampleFormat::U8 => make!(u8)?,
        SampleFormat::I8 => make!(i8)?,
        other => return Err(format!("unsupported sample format {other:?}")),
    };

    stream.play().map_err(|e| format!("stream.play: {e}"))?;
    Ok(stream)
}

/// Start capture with a supervisor that rebuilds the stream when the device goes away.
///
/// The supervisor exists because cpal 0.18 gives no default-device-change notification,
/// and several real failures - USB unplug, sleep/resume, a driver reset, another app
/// grabbing the device in exclusive mode - surface either as an error callback or as
/// nothing at all. "Nothing at all" is the dangerous one: the daemon looks healthy and
/// silently stops hearing the user.
pub fn start(preferred_device: Option<String>) -> Result<AudioCapture, String> {
    let stats = Arc::new(AudioStats::default());
    let shutdown = Arc::new(AtomicBool::new(false));

    // First ring, so the caller has a usable consumer immediately.
    let (producer0, consumer0) = RingBuffer::<f32>::new(RING_FRAMES);
    let (cons_tx, cons_rx) = crossbeam_channel::bounded::<Consumer<f32>>(4);

    let sup_stats = Arc::clone(&stats);
    let sup_shutdown = Arc::clone(&shutdown);

    std::thread::Builder::new()
        .name("whisperrust-audio".into())
        .spawn(move || {
            let mut pending_producer = Some(producer0);
            let mut backoff = Duration::from_millis(250);

            while !sup_shutdown.load(Ordering::Relaxed) {
                let host = cpal::default_host();

                let device = preferred_device
                    .as_ref()
                    .and_then(|name| {
                        host.input_devices().ok().and_then(|mut it| {
                            it.find(|d| device_name(d).as_deref() == Some(name.as_str()))
                        })
                    })
                    .or_else(|| host.default_input_device());

                let Some(device) = device else {
                    tracing::error!("no input device; retrying in {backoff:?}");
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                    continue;
                };

                // Each attempt needs its own Producer, because the previous one was moved
                // into a stream that is now gone.
                let producer = match pending_producer.take() {
                    Some(p) => p,
                    None => {
                        let (p, c) = RingBuffer::<f32>::new(RING_FRAMES);
                        if cons_tx.send(c).is_err() {
                            tracing::info!("capture handle dropped; audio thread exiting");
                            return;
                        }
                        p
                    }
                };

                match build_stream(&device, Arc::clone(&sup_stats), producer) {
                    Ok(stream) => {
                        tracing::info!(
                            device = device_name(&device).unwrap_or_else(|| "<unknown>".into()),
                            rate = sup_stats.rate.load(Ordering::Relaxed),
                            channels = sup_stats.channels.load(Ordering::Relaxed),
                            "capture started"
                        );
                        backoff = Duration::from_millis(250);
                        sup_stats.last_callback_ms.store(now_ms(), Ordering::Relaxed);

                        // Hold the stream and watch for silent death. WASAPI can stop
                        // delivering callbacks with no error at all - sleep/resume and
                        // some driver resets look exactly like this - so absence of data
                        // is the only signal we get.
                        loop {
                            if sup_shutdown.load(Ordering::Relaxed) {
                                return;
                            }
                            std::thread::sleep(Duration::from_millis(200));
                            let last = sup_stats.last_callback_ms.load(Ordering::Relaxed);
                            if last == 0 || now_ms().saturating_sub(last) > SILENCE_REBUILD_MS {
                                tracing::error!(
                                    "no audio callbacks for >{}ms; rebuilding",
                                    SILENCE_REBUILD_MS
                                );
                                sup_stats.rebuilds.fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                        }
                        drop(stream);
                        // Loop around: a fresh ring is created on the next iteration.
                    }
                    Err(e) => {
                        if let Ok(mut slot) = sup_stats.last_error.lock() {
                            *slot = Some(e.clone());
                        }
                        tracing::error!("build stream failed: {e}; retrying in {backoff:?}");
                        std::thread::sleep(backoff);
                        backoff = (backoff * 2).min(Duration::from_secs(5));
                    }
                }
            }
        })
        .map_err(|e| format!("spawn audio thread: {e}"))?;

    // Wait for the stream to actually come up rather than guessing at a fixed sleep.
    // WASAPI device activation is not instant, and a hard-coded delay either wastes time
    // or - as it did on first run here - reports "no sample rate" on a device that was
    // simply still starting.
    let ready_deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < ready_deadline {
        if stats.rate.load(Ordering::Relaxed) != 0 {
            break;
        }
        if let Ok(slot) = stats.last_error.lock() {
            if let Some(err) = slot.as_ref() {
                return Err(err.clone());
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if stats.rate.load(Ordering::Relaxed) == 0 {
        let detail = stats
            .last_error
            .lock()
            .ok()
            .and_then(|s| s.clone())
            .unwrap_or_else(|| "stream did not start within 5s".into());
        return Err(detail);
    }

    Ok(AudioCapture {
        stats,
        consumer: Some(consumer0),
        new_consumers: cons_rx,
        shutdown,
    })
}

/// Silence longer than this triggers a rebuild.
const SILENCE_REBUILD_MS: u64 = 2000;

/// Frames of preroll to retain at a given device rate.
pub fn preroll_frames(rate: u32) -> usize {
    (rate as u128 * policy::PREROLL.as_millis() / 1000) as usize
}

/// Convenience: resample a captured utterance to what Whisper needs.
pub fn finalize(utterance: &[f32], device_rate: u32) -> Result<Vec<f32>, String> {
    resample::to_16k_mono(utterance, device_rate).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preroll_is_400ms_worth() {
        assert_eq!(preroll_frames(48_000), 19_200);
        assert_eq!(preroll_frames(16_000), 6_400);
    }

    #[test]
    fn ring_keeps_only_the_newest_audio() {
        let mut r = PrerollRing::new(5);
        r.push_slice(&[1.0, 2.0, 3.0]);
        assert_eq!(r.snapshot(), vec![1.0, 2.0, 3.0]);
        r.push_slice(&[4.0, 5.0, 6.0]);
        // Capacity 5, so the oldest sample falls off.
        assert_eq!(r.snapshot(), vec![2.0, 3.0, 4.0, 5.0, 6.0]);
    }

    #[test]
    fn ring_handles_input_larger_than_capacity() {
        let mut r = PrerollRing::new(3);
        r.push_slice(&[1.0, 2.0, 3.0, 4.0, 5.0]);
        assert_eq!(r.snapshot(), vec![3.0, 4.0, 5.0]);
    }

    #[test]
    fn ring_clears() {
        let mut r = PrerollRing::new(4);
        r.push_slice(&[1.0, 2.0]);
        r.clear();
        assert!(r.is_empty());
        assert!(r.snapshot().is_empty());
    }

    #[test]
    fn ring_is_empty_initially() {
        let r = PrerollRing::new(10);
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn ring_wraps_repeatedly_without_corruption() {
        // The preroll ring wraps continuously for the life of the daemon, so an off-by-one
        // in the wrap arithmetic would corrupt every dictation after the first few seconds.
        let cap = 7;
        let mut r = PrerollRing::new(cap);
        for round in 0..100u32 {
            let chunk: Vec<f32> = (0..5).map(|i| (round * 5 + i) as f32).collect();
            r.push_slice(&chunk);
        }
        let snap = r.snapshot();
        assert_eq!(snap.len(), cap);
        // Must be the last `cap` values pushed, in order.
        let expected: Vec<f32> = ((500 - cap as u32)..500).map(|v| v as f32).collect();
        assert_eq!(snap, expected);
    }
}
