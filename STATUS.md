# WhisperRust — status and resume map

**Last updated:** 2026-09-20 · **Tests:** 126 passing · **Repo:** https://github.com/lonzosheffield/whisperrust

Read this first if you are picking the project back up. It says what works, what does not,
what is blocked on you, and the exact commands to continue.

---

## TL;DR

A local push-to-talk dictation daemon that works end to end: hold Right Ctrl, speak,
release, text appears. **It has never been used for real dictation.** Everything below the
"blocked on you" line exists to change that.

```powershell
# environment (required - the build fails without it)
$env:PATH = "C:\WhisperRust\.tools\cmake-3.31.8-windows-x86_64\bin;C:\WhisperRust\.tools\ninja;$env:PATH"

cargo build --release
cargo test --release                                    # 126 tests

.\target\release\whisperrust.exe --model models\ggml-base.en.bin   # run it
.\target\release\whisperrust.exe stats                             # analytics
```

---

## Checkpoint status

| Phase | State | What is missing |
|---|---|---|
| **0** Toolchain + spikes | CONDITIONAL | Vulkan parked (deliberate); cert created but not trusted |
| **1a** I/O spine | Code done, **gate FAIL** | The 8-app matrix has never been run |
| **1b** Benchmark | **NOT STARTED** | **Your 20-clip corpus.** Model chosen on one clip of JFK |
| **2** Audio spine | CONDITIONAL | Unplug + sleep/resume untested; OS audio errors are real |
| **3** MVP | Code done, **gate FAIL** | The 50 dictations have never been performed |
| **3.5** LLM cleanup | not started | Phase 3 must pass first |
| **4** Product polish | not started | tray, config file, model download |

**Nothing is falsely green.** Two checkpoints say FAIL because their evidence bundles say
FAIL, not because the code is broken.

---

## What actually works

- Push-to-talk capture with a 400 ms preroll, so the first word is not clipped
- Always-on 48 kHz capture, downmix, anti-aliased resample to 16 kHz
- Silero VAD trimming; no-speech captures skip inference entirely
- whisper.cpp via FFI, warmed at startup (~1.5 s), `base.en` at ~1.35 s for an 11 s clip
- Hallucination filter, two-tier so "Thank you." still types
- Injection via unicode or clipboard, chosen per app
- **Password-field detection in both Win32 and browsers/Electron** (UIA)
- Wrong-window guard, elevated-target guard, modifier guard, kill chord
- Clipboard kept out of Win+V history and cloud sync
- Session log (JSONL) recording every outcome including refusals
- `stats` reporting WPM, effective WPM, time saved, p50/p95 latency

## What is known-broken or unproven

| Thing | Detail |
|---|---|
| **OS audio loss** | 3 WASAPI errors in a 12 s check; 62 and ~1.4 s lost over 600 s. Real and recurring. Suspect the C920's 4-channel I24 over USB. If words go missing, look here first. |
| **Model choice** | `base.en` picked from one 11 s clip. Not evidence about your voice or vocabulary. |
| **Device-loss recovery** | Code exists, never exercised with a real unplug. |
| **Sleep/resume** | Same. |
| **Signature not trusted** | Cert is in the user store only; trusting it needs elevation. |
| **Vulkan** | Parked. Costs the `small.en` benchmark column. See `docs/SPIKE-VULKAN.md`. |

---

## BLOCKED ON YOU — in priority order

### 1. Record the 20-clip corpus (~30 min) — highest value

Unblocks Phase 1b, which picks the model on measurement. Everything downstream rests on it.

- 20 utterances, 3–15 s each, **10 on the C920 and 10 on the Intel array**
- Natural dictation: the things you actually say, with your actual jargon
- Hand-correct each transcript into a text file next to the audio
- Save under `corpus/`

Why it matters: `base.en` vs `small.en` is a real quality difference, and right now the
choice rests on a recording of a 1961 speech.

### 2. The 50 dictations (CP-3)

Now worth doing — the defects that would have surfaced during them are fixed, and the
session log means the effort produces data rather than impressions.

```powershell
.\target\release\whisperrust.exe --model models\ggml-base.en.bin
# ... dictate across VS Code, Terminal, Chrome, Slack, Notepad, Word, Outlook ...
.\target\release\whisperrust.exe stats
```

Add `--log-text` if you want transcripts in the log (off by default).

Watch for: first word surviving, text landing in the right window, and whether a hold with
**no speech** correctly reports `no speech - skipped` rather than inventing something.

### 3. Audio resilience (CP-2, ~3 min)

```powershell
.\target\release\whisperrust.exe --audio-check 120
# unplug the C920 at about t=30s
```
Expect `rebuilds` to increment and `frames` to resume on the Intel array within 5 s.

### 4. Trust the certificate (optional, one elevated command)

```powershell
$c = Get-ChildItem Cert:\CurrentUser\My | ? { $_.Subject -eq 'CN=WhisperRust Development' }
Export-Certificate -Cert $c -FilePath $env:TEMP\whisperrust.cer | Out-Null
Import-Certificate -FilePath $env:TEMP\whisperrust.cer -CertStoreLocation Cert:\LocalMachine\Root
```
Signing quiets SmartScreen. It does **not** stop antivirus flagging a keyboard hook.

### 5. Open decision

**Vulkan.** Unparking needs ~10 min from an admin shell and would tell us whether
`small.en` is reachable on the iGPU. Worth it only if `base.en` quality disappoints.

---

## What an agent can do without you

- Phase 4: tray icon, TOML config, model download with checksums, autostart
- Phase 3.5: local LLM cleanup pass (the verbatim-vs-cleaned gap, `PLAN.md` §7A.4)
- Investigate the WASAPI errors — try 2-channel or I16 instead of 4-channel I24
- `criteria/phase-0.yaml` and `phase-1a.yaml` (only 2 and 3 exist)

---

## Map of the repo

| Path | What it is |
|---|---|
| `docs/PLAN.md` | **The plan.** Architecture, 13 security invariants, phases, governance |
| `docs/REDTEAM.md` | ~30 adversarial findings |
| `docs/QA-CP1a-CP3.md` | Independent QA verdicts and the defects they found |
| `docs/TOOLING.md` | **Traps already hit.** Read before debugging a build |
| `docs/SPIKE-PTT-ORACLE.md` | Why the PTT key is never swallowed |
| `docs/SPIKE-VULKAN.md` | Why Vulkan is parked |
| `criteria/*.yaml` | Machine-readable pass criteria (trust boundary) |
| `DEPS.md` | Dependency allowlist (trust boundary) |
| `evidence/` | Per-checkpoint evidence bundles |
| `LOCAL-ENV.md` | Machine specifics — **gitignored, never publish** |

### Source

| File | Role |
|---|---|
| `policy.rs` | **Governed.** Every security constant. Changing one needs an AMEND. |
| `preflight.rs` | The only thing that can authorize injection (I-3) |
| `inject.rs` | The only thing that emits input (I-5) |
| `hook.rs` | The keyboard hook. Riskiest file. No alloc, no locks, never swallows. |
| `fsm.rs` | Session state machine. Pure; time is a parameter. |
| `audio.rs` | Always-on capture, preroll ring, WASAPI supervisor |
| `resample.rs` | Anti-aliased 48k→16k |
| `backend.rs` | whisper.cpp FFI + pre-FFI validation |
| `postprocess.rs` | Hallucination filter, sentence joining |
| `target.rs` / `uia.rs` | Foreground probe; password detection |
| `clipboard.rs` | Clipboard + Win+V exclusion |
| `session_log.rs` / `stats.rs` | Per-utterance log and analytics |

---

## Three things that will bite you if you forget them

1. **`/O2`.** whisper.cpp silently builds unoptimized and runs **7× slower** unless
   `.cargo/config.toml` is in effect. Nothing fails if it regresses — it just goes slow.
   Verify: `grep CMAKE_CXX_FLAGS_RELEASE target/release/build/whisper-rs-sys-*/out/build/CMakeCache.txt`
2. **Never swallow the PTT key.** It blinds `GetAsyncKeyState` and breaks the stuck-key
   watchdog, killing every capture. Measured, not theorized.
3. **Never sleep the hook-owning thread.** A `WH_KEYBOARD_LL` proc cannot run while its
   thread sleeps; Windows silently unregisters the hook and the keyboard stalls
   system-wide. This bit us once in the clipboard path.

## Governance, briefly

Each phase ends in a checkpoint with **fresh-context Fable QA** that re-runs criteria
rather than reading claims. Evidence bundles carry captured values, not booleans. A
narrative that something passed is not evidence.

This was skipped for four phases and QA then found seven real defects, including one where
a report marked a criterion PASS while its own log showed the failure. **Run the gate per
phase.**
