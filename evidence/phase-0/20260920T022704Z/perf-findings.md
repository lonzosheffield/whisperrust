# Phase 0 performance findings (optimized build)

11 s clip (jfk.wav), AC power, whisper.cpp built with /O2 /Ob2 /DNDEBUG.
Warm pass (pass 1), PASSES=2. Preliminary - Phase 1b does this properly.

| Model | Threads | Warm ms | RTF |
|---|---|---|---|
| tiny.en | 8 | 609 | 0.055 |
| tiny.en | 10 | 1255 | 0.114 |
| base.en | 8 | 1357 | 0.123 |
| base.en | 10 | 1340 | 0.122 |
| small.en-q5_1 | 8 | 4729 | 0.430 |
| small.en-q5_1 | 10 | 4343 | 0.395 |

## Before/after the /O2 fix (tiny.en)

| Threads | Unoptimized | Optimized | Speedup |
|---|---|---|---|
| 2 | 9529 ms | 1104 ms | 8.6x |
| 4 | 6985 ms | 874 ms | 8.0x |
| 6 | 5670 ms | 709 ms | 8.0x |
| 8 | 4715 ms | 634 ms | 7.4x |
| 10 | 4305 ms | 620 ms | 6.9x |
| 12 | 4694 ms | 745 ms | 6.3x |

## Implications for Phase 1b

- The encoder is a fixed 30 s window cost, so a 5 s utterance costs roughly the same
  encoder time as this 11 s clip. Decoder time scales with token count.
- base.en at ~1.35 s here is the leading candidate against the p95 <= 1500 ms target.
- small.en-q5_1 at ~4.3 s is far outside the target on CPU. Vulkan decides whether it
  becomes viable.
- Variance is high (tiny.en at 10 threads measured 620 ms and 1255 ms in separate runs).
  Single samples are meaningless; p50/p95 over repeated runs is mandatory.
