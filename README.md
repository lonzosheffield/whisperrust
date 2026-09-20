# WhisperRust

A local, offline, push-to-talk voice dictation daemon for Windows 11, written in Rust.

Hold a key, speak, release — the transcribed text lands in whatever application has focus.
Everything runs on the machine. No cloud, no account, no network after the model download.

> **Status: working end to end; not yet validated in real use.**
> Start with **[STATUS.md](STATUS.md)** — it says what works, what does not, and what to do next.

## Design

| Layer | Choice |
|---|---|
| Inference | [whisper.cpp](https://github.com/ggml-org/whisper.cpp) via [`whisper-rs`](https://crates.io/crates/whisper-rs) 0.16 |
| VAD | Silero, **built into whisper-rs 0.16** — no separate ONNX runtime |
| Capture | `cpal` (WASAPI), device-native rate → `rubato` → 16 kHz |
| Concurrency | Three OS threads, lock-free SPSC ring. No async runtime. |
| Hotkey | `WH_KEYBOARD_LL` via the `windows` crate |
| Injection | Unicode `SendInput`, or clipboard + Ctrl+V, chosen per target app |

Rust owns the entire pipeline above the matrix math. whisper.cpp is kept behind a
`TranscriptionBackend` trait rather than reimplemented — matching ggml's hand-tuned
quantized AVX2/VNNI kernels is a research project with no user-visible payoff.

## Documentation

| Document | What it covers |
|---|---|
| [`STATUS.md`](STATUS.md) | **Start here.** Current state, what is blocked, exact commands to resume |
| [`docs/PLAN.md`](docs/PLAN.md) | The plan: architecture, security invariants, latency budget, phases, checkpoints, governance |
| [`docs/REDTEAM.md`](docs/REDTEAM.md) | Adversarial review — ~30 findings across security, catastrophic-UX, and process governance |
| [`docs/RECON.md`](docs/RECON.md) | Verified build facts: toolchain versions, model URLs, known landmines |
| [`docs/TOOLING.md`](docs/TOOLING.md) | Traps already hit, and how not to hit them again |

## Security posture

This software installs a global keyboard hook, holds the microphone open, writes the
clipboard, and synthesizes keystrokes. At the Win32 API level that is indistinguishable
from an infostealer, and it is designed accordingly — to be legible and auditable rather
than merely functional:

- **Never runs elevated.** The daemon exits if its own token is elevated.
- **One injection choke point.** A single `preflight()` runs eleven ordered checks; nothing
  else may call `inject()`.
- **Unsure means do not inject.** Wrong window, elevated target, or a password field →
  clipboard-only or dropped, never pasted.
- **The injector can emit exactly three virtual keys**, enforced by test.
- **No network in the daemon.** Model downloading is a separate binary, so "offline" is
  enforceable by firewall rather than promised.
- **Six independent emergency stops.** The machine must never feel bricked.

The full threat model is published in [`docs/REDTEAM.md`](docs/REDTEAM.md). Publishing it
is deliberate: a security-relevant tool should ship its own analysis.

## Building

Not yet buildable. Phase 0 prerequisites are CMake (pinned below 4.x — see
[`docs/TOOLING.md`](docs/TOOLING.md)), LLVM/libclang for bindgen, and VS 2022 Build Tools.

## License

Not yet chosen.
