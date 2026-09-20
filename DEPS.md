# Dependency allowlist

Governance G-2 trust-boundary file. **Adding a dependency that is not listed here is a
MUST-STOP action** requiring the owner's approval, not an agent's judgement.

The bar for this project is deliberately high: it holds a global keyboard hook, an
always-open microphone, the clipboard, and the ability to synthesize input. Every crate
added is code running inside that trust envelope.

## Runtime dependencies

| Crate | Version | Why it is here | Could we drop it? |
|---|---|---|---|
| `whisper-rs` | 0.16 | The inference engine. The entire Part A strategy. | No |
| `cpal` | 0.18 | WASAPI capture | No |
| `rubato` | 5.0 | Anti-aliased resampling 48k->16k | Not without aliasing the speech band |
| `audioadapter-buffers` | 5.1 | rubato 5's buffer abstraction | No, transitive by design |
| `rtrb` | 0.4 | Lock-free SPSC ring for the RT audio callback | Could hand-roll; not worth the risk |
| `hound` | 3.5 | WAV read/write for fixtures and debug capture | Yes, but it is tiny and well-worn |
| `arboard` | 3.6 | Clipboard read/write | Partly - the Windows privacy formats are already hand-written because arboard lacks them |
| `crossbeam-channel` | 0.5 | Bounded channels between the three threads | std::sync::mpsc could do it; crossbeam's try_send and recv_timeout are load-bearing |
| `windows` | 0.62 | Every Win32 call: hook, SendInput, UIA, clipboard, power, tokens | No |
| `serde` / `serde_json` | 1 | Session log JSONL, stats parsing | No |
| `tracing` / `tracing-subscriber` | 0.1 / 0.3 | Structured logging | Could use eprintln; structured fields are worth it |

## Deliberately NOT used

| Crate | Why not |
|---|---|
| `tokio` | There is no async I/O in this program. It is three OS threads and three channels. Cut in plan v2. |
| `enigo` | Was planned; the injector needs precise control over exactly which virtual keys can be emitted (I-5), which a general input library works against. |
| `silero-vad-rust` | whisper-rs 0.16 ships Silero VAD built in. Avoids an ONNX Runtime dependency and a second model format entirely. |
| `chrono` | Two `GetSystemTime` calls replace it. A date crate is a poor trade for a timestamp. |
| `global-hotkey` | `RegisterHotKey` reports press but not release, so it cannot express hold-to-talk. |
| OpenBLAS | Does not apply to the quantized ggml kernels that matter, and is a Windows build tax. |
| `intel-sycl` | Multi-GB oneAPI toolchain for what Vulkan already reaches. |

## Build-time pins

- **CMake 3.31.8**, pinned below 4.x. whisper.cpp declares
  `cmake_minimum_required(VERSION 3.5)`, which sits on the boundary CMake 4 removed.
- **`CMAKE_C/CXX_FLAGS_RELEASE = /MD /O2 /Ob2 /DNDEBUG`** in `.cargo/config.toml`.
  Without this whisper.cpp compiles UNOPTIMIZED and runs ~7x slower, silently. See
  `docs/TOOLING.md` trap #5. This is the single most consequential line in the build.
- **MSVC v142 (VS2019)** is sufficient. VS2022 was assumed necessary and is not.
- **LLVM/libclang is NOT required** — bindgen worked without a separate install.
