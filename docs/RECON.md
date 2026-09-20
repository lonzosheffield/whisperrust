# Verified build facts — recon appendix

Everything here was checked live on 2026-09-19. Folds into PLAN.md v2.

## Phase 0 toolchain — all winget-installable

| Package | winget ID | Version available |
|---|---|---|
| CMake | `Kitware.CMake` | 4.4.3 |
| LLVM (libclang, for bindgen) | `LLVM.LLVM` | 23.1.1 |
| VS 2022 Build Tools | `Microsoft.VisualStudio.2022.BuildTools` | 17.14.41 |
| Ninja | `Ninja-build.Ninja` | 1.13.2 |

## LANDMINE 1 — CMake 4.x vs whisper.cpp

whisper.cpp `CMakeLists.txt` line 1 is literally:

```cmake
cmake_minimum_required(VERSION 3.5) # for add_link_options and implicit target directories.
```

CMake 4.x removed compatibility with pre-3.5 policy behavior and sits exactly on this
boundary. winget's only CMake is **4.4.3**. This is a well-known source of hard build
failures in the ggml ecosystem.

**Mitigations, in order of preference:**
1. Pin CMake 3.31.x (install outside winget) — most predictable.
2. Pass `-DCMAKE_POLICY_VERSION_MINIMUM=3.5` through to the whisper-rs-sys build.
3. Set it via env for the cargo build so it reaches the vendored cmake invocation.

This must be resolved *in Phase 0*, before any code is written. Budget real time for it.

## LANDMINE 2 — the VAD model is in a different repo

The built-in Silero VAD needs its own ggml model, and it is **not** in
`ggerganov/whisper.cpp`. That repo contains no VAD files at all.

Correct source — verified HTTP 200:

```
https://huggingface.co/ggml-org/whisper-vad/resolve/main/ggml-silero-v6.2.0.bin   (~864 KB)
https://huggingface.co/ggml-org/whisper-vad/resolve/main/ggml-silero-v5.1.2.bin
```

Use **v6.2.0**. It is tiny (under 1 MB), so it can be vendored into the repo or
bundled with the installer rather than downloaded at runtime.

whisper.cpp's own VAD knobs, which map to `WhisperVadParams`:
`--vad-threshold`, `--vad-min-speech-duration-ms`, `--vad-min-silence-duration-ms`.

## Whisper model URLs — all verified HTTP 200

Base: `https://huggingface.co/ggerganov/whisper.cpp/resolve/main/`

| Model | Size |
|---|---|
| `ggml-base.en.bin` | 141 MB |
| `ggml-small.en.bin` | 465 MB |
| `ggml-small.en-q5_1.bin` | 181 MB |
| `ggml-large-v3-turbo-q5_0.bin` | 547 MB |

`ggml-small.en-q5_1.bin` at 181 MB is the most interesting latency/accuracy candidate
for this CPU and should be in the Phase 1 benchmark set.
