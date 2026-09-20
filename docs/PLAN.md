# WhisperRust — Plan v4 (decisions locked)

Local, offline, push-to-talk voice→text daemon for Windows 11. A Wispr Flow replacement
that runs entirely on this machine.

**Lineage:** v1 Opus draft → v2 after Opus↔Fable design review → v3 after Fable
red/purple/white team → **v4 with the user's scope decisions locked in (§10.1)**. Full
adversarial detail lives in `REDTEAM.md` (804 lines, ~30 findings); this document carries
the decisions and the plan.

**Scope as of v4:** whisper.cpp via FFI, push-to-talk only, never elevated.
Phases 0 → 1a/1b → 2 → 3 → 3.5 → 4. No hotword. No second inference backend.

---

## ⚠ 0. Read this before approving

### 0.1 This is a corporate-managed device

`dsregcmd` confirms this is an **Entra-ID-joined, MDM-managed device running third-party
endpoint protection alongside Windows Defender**. Tenant, enrolled UPN, device ID and the
specific security products are recorded in `LOCAL-ENV.md`, which is gitignored and not
published.

What we are building installs a global low-level keyboard hook, holds the microphone open
continuously, writes the clipboard, and synthesizes keystrokes into other applications. At
the Win32 API level that is **indistinguishable from an infostealer**. Third-party AV is
typically aggressive about keyboard hooks, and MDM may enforce policy independently.

This is not a technical risk to engineer around. It is a **policy question on a
managed corporate tenant**, and it was answered by accepting the risk knowingly.

Two operational rules follow, and they are not optional:

- **Never respond to a detection by adding an AV exclusion.** That is a
  hard stop requiring your explicit decision — an exclusion on a managed corporate device
  is exactly the wrong reflex, and it is precisely the shortcut an autonomous agent would
  otherwise take at 2am to make a red light go green.
- **Expect quarantine of unsigned builds.** Note that signing does *not* solve this:
  behavioral detection of a keyboard hook is indifferent to who signed the binary (§10.2).
  Signing addresses SmartScreen and tamper-evidence, nothing more.

**STATUS: ACCEPTED BY USER (2026-09-19).** The user has knowingly accepted this risk. The
operational rules stand regardless: no AV exclusions without an explicit, recorded decision;
any EDR detection is a hard stop that surfaces to the user rather than being worked around.

### 0.2 RESOLVED — the PTT key is never swallowed

v2 specified a hook that *swallows* the PTT key, plus a Watchdog B that polls
`GetAsyncKeyState` to detect a stuck key. The red team argued these are incompatible.

**Measured 2026-09-20: they are.** A swallowed key never reaches the key-state tables, so
both `GetAsyncKeyState` and `GetKeyState` read UP for the entire hold. Watchdog B would
have fired ~50 ms into every capture and killed every dictation before it started.
Confirmed across `VK_RCONTROL`, `VK_SCROLL` and `VK_PAUSE`, two runs.

**Decision: Option A — do not swallow.** The hook chains via `CallNextHookEx`
unconditionally, which restores `GetAsyncKeyState` as a valid oracle and keeps the hook
procedure trivial — and the hook proc is the one place where being slow gets us silently
unregistered by Windows.

The cost is that applications see a bare Right-Ctrl press, which is a no-op in essentially
every application. Phase 1a verifies that empirically across all eight target apps rather
than assuming it.

Full result and consequences: [`SPIKE-PTT-ORACLE.md`](SPIKE-PTT-ORACLE.md).
Evidence: `evidence/phase-0/20260920T022704Z/`.

---

## 1. Verified environment

| Fact | Value | Consequence |
|---|---|---|
| CPU | Intel Core Ultra 7 165U (Meteor Lake-U), 12C/14T | AVX2/VNNI, **no AVX-512**. Hybrid P/E cores → more threads ≠ faster. |
| GPU | Intel Arc iGPU | No CUDA/Metal. **Vulkan confirmed working** (API 1.4.348, driver 101.8826, ICD `igvk64.json`). |
| NPU | Intel AI Boost | whisper-rs exposes no OpenVINO feature. Out of scope. |
| RAM | 31.4 GB | Not a constraint. |
| **Power** | **Laptop, battery, Balanced plan** | Benchmarks must cover **AC and DC** (~1.5–2× difference). |
| **Management** | **Entra-joined, MDM-managed, third-party AV + Defender** | See §0.1 and `LOCAL-ENV.md`. |
| CMake | ABSENT (winget: 4.4.3) | Blocker + version landmine (§5). |
| LLVM/libclang | ABSENT | Blocker (bindgen). |
| MSVC | VS Build Tools **2019** | Upgrade to 2022. |
| Mics | Logitech C920 + Intel Smart Sound array | 44.1/48 kHz → resampling mandatory. Smart Sound's AGC/NS changes WER. |

## 2. Corrections to the originally pasted plans

| Pasted claim | Reality |
|---|---|
| `whisper-rs = "0.11"` | **0.16.0** |
| `cpal = "0.15"` / `enigo = "0.2"` | **0.18.2** / **0.6.1** (`enigo` now dropped entirely) |
| `silero-vad-rust = "0.1"` | Crate is at **6.2.2**; version invented |
| `load_silero_vad()` / `forward_chunk()` / `prob[[0,0]]` | **Fabricated — matches no published API, will not compile** |
| Separate ONNX VAD needed | whisper-rs 0.16 has **built-in Silero VAD** → **ONNX Runtime deleted** |
| `StreamConfig { sample_rate: 16000 }` | WASAPI shared mode won't honor it; C920 is 48 kHz. **Fails on this machine.** |
| `data.to_vec()` in the audio callback | Heap alloc in an RT callback → xruns |
| unbounded mic channel | Unbounded growth on consumer stall |
| `panic = "abort"` | Daemon should survive a mic unplug |
| "100–250 MB, 200–400 ms" | Unverified; replaced by measurement |
| "race conditions impossible" | Rust prevents *data races*, not races or deadlocks |

---

## 3. Architecture

### 3.1 Strategy: Rust owns everything above the matrix math

Rewriting ggml's quantized AVX2/VNNI kernels is a research project with negative user
value. whisper.cpp stays, behind a trait:

```rust
pub struct Hint {
    pub language: Option<&'static str>,
    pub initial_prompt: Option<String>,  // custom vocabulary
    pub prev_text: Option<String>,       // continuity
    pub audio_ctx: Option<u32>,          // biggest encoder-cost lever
}

pub trait TranscriptionBackend: Send {
    fn transcribe(&mut self, pcm16k: &[f32], hint: &Hint) -> Result<Transcript>;
    fn warm(&mut self) -> Result<()>;
    fn info(&self) -> BackendInfo;
}
```

### 3.2 Three OS threads, no async runtime

tokio is cut — there is no async I/O in this program.

| Thread | Owns | Rule |
|---|---|---|
| **main** | Win32 pump, keyboard hook, tray, injector | **Nothing over ~10 ms.** Exceeding `LowLevelHooksTimeout` (≤1000 ms) gets the hook silently removed. |
| **audio** | cpal callback + supervisor | No alloc, no lock, no logging in the callback. |
| **worker** | FSM, resample, VAD, inference, post-processing | Everything slow. |

Channels: `rtrb` SPSC audio→worker; bounded `crossbeam_channel` hook→worker (`try_send`).
worker→main is a **doorbell only** — `PostMessageW(WM_APP)` with **no payload**, then main
drains a channel. (Never post a boxed pointer: any process can post `WM_APP` junk and
corrupt main.)

### 3.3 Pipeline

```
[main] hook ──try_send──▶                    tray ◀── state
                                             injector ◀── doorbell + channel
[audio] cpal callback: downmix to mono ONLY, native 48 kHz → rtrb   (no alloc)
[worker] drain ring → 400 ms preroll ring (native rate)
         PTT-down: prepend preroll, start appending
         PTT-up + 100 ms grace:
           resample ONCE 48k→16k (rubato FftFixedIn)
           → Silero VAD → zero speech? SKIP inference
           → whisper full() on warmed, reused state
           → sanitize · hallucination filter · vocab · text joining
           → preflight() → inject | clipboard-only | drop
```

**Preroll is 400 ms, not 1.5 s.** A 1.5 s preroll records speech from *before* you pressed
the key; VAD won't strip it because it is speech. It would paste the tail of whatever you
were saying to someone else.

---

## 4. Security invariants

These are non-negotiable and belong in `src/policy.rs`, which is a governed file (§8).

| # | Invariant | Why |
|---|---|---|
| I-1 | **The daemon refuses to run elevated** — checks its own token at startup and exits | Config + model dir are user-writable; ggml model loading is a hand-written binary deserializer. Elevated daemon + attacker-controlled model path = privilege escalation with mic, hook and SendInput already in hand. |
| I-2 | **Model hashes compiled into the binary**; re-hashed on **every load**, not just at download; quarantine on mismatch. VAD model `include_bytes!`'d (it's <1 MB) | Download-time-only verification from the same server, into a user-writable dir, protects nothing afterward. |
| I-3 | **`preflight()` is the only caller of `inject()`** — 11 ordered, reason-coded checks | One choke point that can be audited and fuzzed. |
| I-4 | **`sanitize()` on all output**: strip CR/LF/TAB/C0/C1, cap 2000 chars, collapse 3-gram repetition | A `\n` in a terminal is **Enter** — it executes. |
| I-5 | **Injector may only ever emit `VK_CONTROL`, `'V'`, `VK_PACKET`** — enforced by test + grep | Bounds the blast radius of any bug to "pastes text". |
| I-6 | **`end_cause != UserKeyUp` ⇒ clipboard-only, never inject** | A capture ended by a watchdog or the 60 s cap is the always-on-mic nightmare with a legitimate cause. |
| I-7 | **Hook honors `LLKHF_INJECTED`** and ignores its own `dwExtraInfo` magic | Otherwise any process can drive PTT synthetically. |
| I-8 | **Password-field detection** → drop entirely, not even to clipboard | `ES_PASSWORD` on `GetGUIThreadInfo().hwndFocus`, or UIA `CurrentIsPassword`. |
| I-9 | **Unsure ⇒ clipboard-only + toast.** `Mode {Normal, ClipboardOnly, Disabled}` | The default on any doubt is never "inject anyway". |
| I-10 | **Redacting `Debug`** on `Inject`/`Transcript`/`ClipboardSnapshot`; panic hook logs type, not payload; no full minidumps | Crash artifacts otherwise carry audio, transcripts, and the user's *previous clipboard* — which may be a password. |
| I-11 | **Downloader split into a separate `whisperrust-fetch.exe`**; the daemon links no HTTP client and is firewall-blocked | Makes "no network" OS-enforceable rather than a promise. |
| I-12 | **Forbidden PTT bindings**: L-Ctrl/L-Shift/L-Alt/Win/CapsLock/alphanumerics/Esc/Enter/Space/Tab | A sick app that keeps swallowing L-Ctrl kills Ctrl+C/V/Z system-wide — the machine feels bricked. |
| I-13 | **The PTT key is never swallowed** — the hook always chains via `CallNextHookEx` | Measured: swallowing blinds both `GetAsyncKeyState` and `GetKeyState`, which breaks Watchdog B and kills every capture. See SPIKE-PTT-ORACLE.md. |

**Emergency stop, six independent layers:** Esc cancels an in-flight capture · kill chord
(PTT ×5 in 1 s, checked between 64-char inject chunks) · tray menu · `--stop` named event ·
the OS's own hook timeout · `%ProgramData%\WhisperRust\disabled` as an admin off-switch.
Plus a `HEALTHY` atomic: **the hook passes everything through when the worker heartbeat is
>3 s stale.** The machine must never feel broken.

### 4.1 The catastrophic-UX findings that drove these

| ID | Scenario | Answer |
|---|---|---|
| B-01 | Control chars in output execute in a terminal | I-4, I-5 |
| B-02 | Dictation into a masked password field; user can't see it, presses Enter | I-8 |
| B-03 | Chrome/Electron are **one HWND** — focus moves to the omnibox, the foreground guard passes, text goes to Google | Field-level check, not just HWND+exe |
| B-04 | A capture ended by a broken hook is still transcribed and injected | I-6 |
| B-06 | 300 ms clipboard restore races Electron's 200+ ms paste → the **previous** clipboard is pasted | `restore_delay_ms` 750 (1500 for Slack/Discord/Teams/Code); **no restore on any fallback path**; `GetClipboardSequenceNumber()` guard |
| B-07 | Stuck swallowed key + a Watchdog B that cannot work | §0.2 spike |

**Clipboard-history exclusion is manual work.** arboard 3.6.1 publishes only `SetExtLinux`
— there is no `SetExtWindows`, contrary to the review's claim. Keeping dictation out of
Win+V and cloud clipboard means registering `ExcludeClipboardContentFromMonitorProcessing`,
`CanIncludeInClipboardHistory` and `CanUploadToCloudClipboard` via the `windows` crate.

**Default injection method: `unicode` for ≤300 chars, `ctrl-v` above.** Unicode typing
never touches the clipboard, so it leaks to no clipboard listener. Phase 1a measures both
per app.

---

## 5. Latency budget

Key-release → text on screen, 5 s utterance, CPU, AC. Encoder/decoder figures are
**estimates to be replaced by Phase 1b**; the *shape* is not an estimate.

| Stage | Estimate |
|---|---|
| Key-up → hook → worker | 2–6 ms |
| Post-release grace + last WASAPI buffer | 100 ms + 10–20 ms |
| Resample 48k→16k (once) | 2–5 ms |
| Silero VAD | 20–60 ms |
| Mel | 5–15 ms |
| **Encoder — fixed 30 s window cost** | base.en 250–450 ms · small.en 800–1500 ms · turbo **4–8 s** |
| Decoder (~15 tokens) | base 50–100 · small 150–300 ms |
| Clipboard set / SendInput → render | 20–125 ms (Electron under load 200+) |
| **Total** | **base.en ≈ 0.45–0.8 s · small.en ≈ 1.2–2.2 s · turbo CPU ≈ 5–9 s** |

**Targets:** p95 ≤1.0 s instant · ≤2.0 s tolerable · >3.0 s failed.

The encoder costs the same regardless of utterance length — a fixed 30 s window. That is
why **RTF is the wrong metric**, why `large-v3-turbo` is likely dead on arrival here, and
why `audio_ctx` reduction is the biggest CPU lever available. Vulkan on the iGPU is what
might make `small.en` viable.

**Streaming inference: premature.** The encoder isn't incremental; for ≤10 s utterances it
buys nothing and splits words at chunk boundaries. Deferred behind a measured trigger
(session log shows p50 >10 s). The design merely must not preclude it.

---

## 6. Phase and checkpoint map

Five phases, six checkpoints. Every checkpoint is the same three-step gate:

```
   agent work  ──▶  EVIDENCE BUNDLE  ──▶  FABLE QA (fresh context)  ──▶  [USER GATE]  ──▶  next phase
                    captured values         re-runs, does not re-read     only where marked
```

**"Fresh context" means the reviewing Fable did not build the thing.** It gets the plan, the
criteria file, and the evidence bundle — never the building agent's conversation. An agent
cannot vouch for its own work, and a reviewer that watched the work happen inherits its
assumptions.

| CP | Ends | Fable QA focus | User gate? | Why the user is needed |
|---|---|---|---|---|
| **CP-0** | Phase 0 — toolchain + spikes | Does the build reproduce from clean? Is the PTT-oracle result real or asserted? | **No** | — |
| **CP-1a** | Phase 1a — I/O spike | Re-run 2 random injection criteria live; confirm the wrong-window and password-field guards actually refuse | **Yes** | Must open the live-GUI-test window; the 8-app matrix is hand-observed |
| **CP-1b** | Phase 1b — benchmark | Re-run 2 random benchmark cells; identical numbers across runs = canned-report flag | **Yes** | Must record the 20-clip corpus; must approve the model choice |
| **CP-2** | Phase 2 — audio spine | Re-run the soak; confirm the unplug and sleep/resume tests were really executed | **No** | — |
| **CP-3** | Phase 3 — **MVP** | Full security-invariant sweep; read the session log, not the summary | **Yes** | The 50 dictations are yours to perform |
| **CP-4** | Phase 4 — product | Regression of every prior CP; confirm nothing was weakened to pass | **Yes** | 5 days of real use |
| *CP-5* | Phase 5 — analytics (§7A.1) | Reconcile `stats` against a hand count | No | — |
| *CP-6* | Phase 6 — context conditioning (§7A.2) | Re-score the corpus; confirm the privacy default is off | **Yes** | Screen-reading is a separate consent |
| *CP-7* | Phase 7 — style + LLM cleanup (§7A.3–4) | Blind A/B of cleaned vs raw | **Yes** | The preference is yours |

CP-0 through CP-4 are the committed build. CP-5 through CP-7 are the §7A roadmap and are
**not** approved for autonomous execution by this plan — they get their own go-ahead after
you have lived with the MVP.

### 6.1 What blocks on you

Three checkpoints cannot proceed without you, and they are worth scheduling around:

- **Before Phase 1b:** record 20 utterances (3–15 s), ten on each mic, and hand-correct the
  transcripts. This is the ground truth for every model decision. Roughly 30 minutes.
- **During Phase 1a and 3:** live GUI testing touches your real desktop. Agents work in a
  Windows Sandbox by default (G-3); the live matrix needs a window you open explicitly.
- **At CP-3 and CP-4:** the 50-dictation and 5-day criteria are lived, not measured.

### 6.2 What a checkpoint produces

`evidence/phase-N/<timestamp>/` containing `report.json` with **captured values, not
booleans** (`p95_ms: 1340`, never `latency_ok: true`), the `criteria.sha256` matching the
hash pinned in this plan, the git SHA, and raw artifacts — logs, WAVs, benchmark CSVs.

An agent's narrative that a phase passed is **not** evidence and Fable QA rejects it.

### 6.3 Where it stops dead

Any of these halts the pipeline and comes to you rather than being resolved by an agent:
a benchmark target that would need renegotiating · a previously-green security test going
red · a dependency not in `DEPS.md` · a criteria or `policy.rs` hash mismatch · text landing
in a non-target window on your live session · an EDR detection · any
proposal to run elevated, add an AV exclusion, or "temporarily" weaken a guard.

---

## 7. Phases with binary pass/fail

### Phase 0 — Toolchain, clearances, and two spikes (blocking)
winget: `Kitware.CMake`, `LLVM.LLVM`, `Microsoft.VisualStudio.2022.BuildTools`,
`Ninja-build.Ninja`, `KhronosGroup.VulkanSDK`.

⚠ **CMake landmine:** whisper.cpp declares `cmake_minimum_required(VERSION 3.5)`; winget
ships **4.4.3**, which sits on the removed-compatibility boundary. Pin CMake 3.31.x or pass
`-DCMAKE_POLICY_VERSION_MINIMUM=3.5`. Resolve here, not later.

**PASS:** (a) whisper-rs CPU build transcribes a known WAV; (b) `cargo build --features vulkan`
links (2 h time-box; on failure record "Vulkan parked" and pass on CPU); (c) **PTT oracle
spike settled** with evidence — which of the three §0.2 options actually works on this
hardware, demonstrated by a throwaway binary that logs key-down/key-up timing across a 3 s
hold; (d) self-signed cert generated and installed into `Trusted Root` + `Trusted Publishers`.

§0.1 is satisfied (risk accepted, §10.1).

### Phase 1a — I/O spike (no audio, no model, canned text)
**PASS (all binary):** hold/release pastes canned text into all **eight §10.4 apps**, 20/20 each ·
alt-tab during an artificial 1 s delay → **no paste**, clipboard + toast · focus moved to
the Chrome omnibox → **no paste** (B-03) · password field → **dropped entirely** · elevated
terminal → recovers, no stuck FSM · 900 ms main-thread stall → hook survives; 1500 ms →
watchdog re-hooks · copy a file in Explorer, dictate → non-text clipboard **untouched** ·
dictated text **absent from Win+V** · kill chord stops injection mid-stream · injected text
containing `\n` never reaches a terminal.

### Phase 1b — Benchmark (parallel)
Corpus: 20 clips **recorded by you on the real mics** (10 each), native rate, hand-corrected
references. Matrix: model {base.en q8, small.en q5_0, small.en q8, large-v3-turbo q5_0} ×
backend {CPU, Vulkan} × threads {4, 6, 8, 12} × `audio_ctx` {0, 768, 512} × power {AC, DC}.
Fixed: greedy, `single_segment`, `no_context`, `suppress_nst`, `flash_attn`, VAD on.
Metric: **wall-clock ms for a 5 s utterance, p50/p95** — not RTF.

**PASS:** full table exists; a model is chosen with **p95 ≤1500 ms on AC** and WER-proxy
≤8% on clean speech. If no CPU cell passes, Vulkan becomes mandatory **or the target is
renegotiated with you explicitly** — agents may not quietly lower it.

### Phase 2 — Audio spine
**PASS:** 10-min soak, zero ring overruns (counter exposed) · RSS flat within 5 MB · C920
unplugged mid-soak → rebuilt on fallback within 5 s, no restart · sleep/resume → capture
resumes within 5 s · 3 s tone through the full path → 16 kHz WAV, <0.1% sample-count error,
no discontinuities.

### Phase 3 — MVP integration
**PASS:** 50 consecutive real dictations spread across the **eight §10.4 apps** with **zero** wrong-window
pastes, **zero** clipboard losses, **zero** hallucinated strings on 10 deliberate silent
holds, p95 within Phase 1b's number +300 ms — **measured from the session log, not by feel**.

### Phase 3.5 — LLM cleanup pass (committed, per decision #8)
Small local instruct model (1-3B, llama.cpp) as a `TextStage` after transcription: strip
disfluencies, resolve self-corrections, apply structure, honor the style profile, format
per target app. Raw output always retained alongside cleaned.
**PASS:** blind A/B over 30 messy real utterances prefers cleaned to raw; p95 added latency
<=300 ms; `--raw` flag and per-app disable both work; terminal targets receive NO
reformatting (I-4 still absolute).

### Phase 4 — Product
Tray, model download + hash, config, autostart, toggle mode, custom vocab, debug audio ring,
correction menu. Signing stays self-signed unless something here forces the issue (§10.2).
**PASS:** 5 working days of daily use · zero crashes in the crash-marker log · zero
unexplained hook re-installs · fresh Windows profile → first dictation with only the
installer · **any EDR detection surfaced to the user, never worked around**.

---

## 7A. Post-MVP roadmap — analytics, context, and style

Added 2026-09-19 at the user's request. **None of this lands before CP-3.** What matters
now is that Phases 0–4 leave the right *seams*, so this is additive later rather than a
rewrite. The four seams are listed in §7A.5 and cost almost nothing to include.

### 7A.1 Phase 5 — Analytics and WPM

**Status: 80% already in the plan.** The session log already records timestamps, hold
duration, post-VAD audio duration, the transcript, per-stage ms, injection outcome and
foreground exe. WPM is a derived field, not new instrumentation.

Derived metrics, all from existing log fields:

| Metric | Definition |
|---|---|
| **Speaking WPM** | words ÷ (post-VAD audio seconds ÷ 60) — your natural rate, typically 120–160 |
| **Effective WPM** | words ÷ (PTT-down → injected seconds ÷ 60) — the honest throughput, latency included |
| **Time saved** | (words ÷ typing_wpm) − (words ÷ effective_wpm), against a configured typing baseline |
| Volume | words/day, /week, /app |
| Quality | hallucination-filter hits, clipboard-only fallbacks, drops, VAD skips |
| Performance | encoder/decoder p50/p95 drift over time; AC vs DC |
| Vocabulary | most frequent terms — **feeds §7A.3** |

Surface: `whisperrust stats [--since 30d] [--by-app] [--json]`, plus a tray tooltip line.
No new storage, no network — it reads the JSONL that already exists.

The headline number is *time saved*. "47,000 words this month at 142 effective WPM; at your
65 WPM typing speed that is 7.9 hours" is the metric that tells you whether this was worth
building.

**PASS (CP-5):** `stats` output reconciles to a hand-counted 20-utterance sample within 2%.

### 7A.2 Phase 6 — Context conditioning ← the hidden gem

**This is the highest accuracy-per-effort item in the entire plan, and it is nearly free
because we are already building both halves of it for unrelated reasons.**

Two things the MVP already collects, purely for *security*:

1. The **foreground window** — captured at PTT-up for the wrong-window guard (B-03).
2. **UI Automation on the focused element** — added for password-field detection (I-8).

The same two calls also yield the window title, the control type, and *the text content of
the field you are dictating into*. And `Hint` already carries `initial_prompt` and
`prev_text`, which is exactly how Whisper accepts decoding context.

So the accuracy lever is already 90% built. What is missing is wiring the output of the
security probes into the input of the decoder:

| Dictating into | Context fed as `initial_prompt` | Effect |
|---|---|---|
| Windows Terminal | recent commands, cwd, git branch | command and flag syntax stops being mangled |
| VS Code | identifiers from the open file | `WhisperVadContext`, not "whisper vad context" |
| Outlook reply | subject + the quoted message | names, acronyms and thread jargon land correctly |
| Word | the surrounding paragraph | terminology stays consistent within a document |
| Chrome | page title, field label | domain vocabulary |

Whisper's weakest point is domain jargon, identifiers, names and acronyms — precisely the
words that cost the most to fix by hand. Conditioning the decoder on what is already on
screen targets exactly those. Cost: one extra UIA call and a string.

**Privacy is a real expansion here and must be explicit.** This reads on-screen content,
including the email you are replying to. Default **off**, per-app opt-in, never logged, and
on a managed corporate device it deserves its own decision rather than riding in on a
feature flag.

**PASS (CP-6):** on the Phase-1b corpus re-scored with conditioning enabled, WER on jargon
terms improves measurably against the CP-1b baseline, with no latency regression beyond 30 ms.

### 7A.3 Phase 7 — Correction capture, style profile, LLM cleanup

One feature wearing three hats. This is the answer to "learn my voice style".

**(a) Correction capture — the compounding asset.** Today, when a transcription is wrong,
you fix it by hand and the system learns nothing. A correction hotkey that captures "what I
actually meant was…" turns every fix into a durable `(audio, raw, corrected)` triple. That
is simultaneously:

- training data for fine-tuning,
- a growing **personal regression suite** — and the benchmark CLI from Phase 1b is already
  the harness for it, so evaluating any future model against *your own voice* becomes a
  single command,
- the raw material for (b).

This requires audio retention, which is opt-in and defaults off. That tension is real and
yours to resolve.

**(b) Style profile.** Distill the corrected corpus into a short, human-readable profile:
characteristic vocabulary, sentence length, punctuation habits, domain terms, and the
corrections you make repeatedly. Stored as plain text you can read and edit, never an opaque
blob. Two consumers: the `initial_prompt` for Whisper, and a portable system prompt you can
paste into any LLM — which is what you asked for.

**(c) LLM cleanup pass — see §7A.4.** The style profile becomes its system prompt, which is
why these are one phase and not three.

**PASS (CP-7):** 50 captured corrections produce a style profile that measurably reduces the
repeat-correction rate on the same class of error.

### 7A.4 The gap nobody caught — verbatim vs. cleaned

Three reviews missed this, and it is the most important finding in this section.

**Our plan ships raw Whisper output. Wispr Flow does not.** Whisper transcribes what you
*said*: filler words, false starts, self-corrections ("the meeting is Tuesday — no, sorry,
Wednesday"), run-on structure. Wispr Flow's perceived magic is substantially a second pass
that turns speech into *writing*.

If we ship verbatim output, the honest expectation is that it will feel **worse than what
you use today**, even with a better model and lower latency. That is a product gap, not a
model-quality gap, and no amount of model tuning closes it.

The fix is a small local instruct model (~1–3B via llama.cpp — the same ggml toolchain
already in the build) running one cleanup pass:

- strip disfluencies, resolve self-corrections,
- apply sentence and paragraph structure,
- honor the §7A.3 style profile,
- format per target app (bullets in Slack, prose in Word, nothing in a terminal).

Budget: roughly 100–250 ms for a 1B model over ~50 tokens on this CPU — inside the existing
latency envelope. Strictly opt-in, strictly local, with raw output always available as a
fallback.

**This also retroactively justifies killing the command grammar.** "Scratch that" and "new
line" were cut as brittle and ambiguous with literal dictation. An LLM pass handles both
natively with no keyword collision, because it reads intent rather than matching strings.
The cut was right; this is what replaces it.

**PASS (CP-7b):** on 30 messy real utterances, cleaned output is preferred to raw in a blind
A/B, with p95 added latency ≤300 ms.

### 7A.5 The four seams the MVP must leave

These are the only things Phases 0–4 must do differently. All are cheap. Skipping them means
a rewrite later.

| # | Seam | Cost now | Cost if skipped |
|---|---|---|---|
| S-1 | Session log carries the **full schema** from day 1 — word count, all stage timings, foreground exe **and window title** | a few extra struct fields | back-fill is impossible; analytics start from zero |
| S-2 | Foreground probe returns a **`TargetContext` struct** (hwnd, exe, title, control type, is_password), not a bool | a struct instead of a bool | §7A.2 has to rewrite the security probe |
| S-3 | Post-processing is an **ordered `Vec<Box<dyn TextStage>>`**, not hardcoded calls | one trait | LLM cleanup cannot slot in without surgery |
| S-4 | Every utterance carries a stable **`utterance_id`** through log, audio ring and injection record | a UUID | corrections cannot be tied back to their audio |

None of these adds a dependency or a security surface. They enter Phases 2–3 as ordinary
design, not as features.

---

## 8. Governance for the autonomous build

This is how the standard is held once execution begins.

**G-1 — No evidence bundle, no done.** Each checkpoint produces
`evidence/phase-N/<ts>/report.json` with **captured values, not booleans**, from a single
commit, with `criteria.sha256` matching the hash pinned here. An agent's narrative claim is
never evidence.

**G-2 — The trust boundary is three files:** `criteria/*.yaml`, `DEPS.md`/`DEPS.lock.txt`,
and `src/policy.rs` (all security constants). Their hashes are pinned per phase. Any change
requires an `AMEND-nnn.md` **you** approve — and loosening a security or latency target
requires you to restate the new target in your own words.

**G-3 — Agents never run the keyboard hook on your live session by default.** Work happens
in a Windows Sandbox rig (`.wsb`, `AudioInput Enable`, `ClipboardRedirection Disable`)
under a Job Object with `KILL_ON_JOB_CLOSE` and a 15-minute cap. Live-session testing needs
a window you open explicitly by creating `.allow-live-gui-tests`; every daemon is stopped
and retention config reverted before checkpoint.

**MUST-STOP actions** (agents surface, never self-approve): installing toolchains ·
downloading models · the **first dev build on this Entra device** · code signing ·
**any AV exclusion** · enabling `keep_audio` or text logging · adding a
dependency or feature not in `DEPS.md` · editing PLAN/criteria/policy · `unsafe` outside
`win32/` · anything elevated · persistence/autostart · deleting user data.

**G-4 — Route by blast radius.** **Opus** for `win32/`, `fsm`, `inject`, `clipboard`,
`policy`, `model_verify`, any `unsafe`, security-tagged criteria, root-cause work,
amendments, and any Sonnet retry. **Sonnet** for config, CLI, WAV I/O, resampler, bench
scripts, logging, tray plumbing, tooling. Never two agents in one module.

**G-5 — QA re-runs, it does not re-read.** At each checkpoint Fable re-executes ≥2 random
`auto` criteria (identical values across runs flags a canned report), inspects `semi`
evidence directly, refuses `manual` items lacking your own signoff line, diffs
`git diff --stat` against the phase's declared file list, greps for
`#[ignore]`/`todo!`/`dbg!`, and confirms no live daemon is running and no retention
artifacts remain.

**Hard stops → human review:** benchmark renegotiation · any previously-green security test
failing · an unlisted dependency · a criteria/policy hash mismatch · a MUST-STOP action
taken without recorded approval · text landing in a non-target window on the live session ·
EDR flagging an artifact · any proposal to run elevated, add an exclusion, or "temporarily"
weaken a guard.

---

## 9. Kill list

**Cut:** tokio · 1.5 s preroll (→400 ms) · `intel-sycl` (multi-GB oneAPI for what Vulkan
already reaches) · OpenBLAS (doesn't apply to the quantized kernels; Windows build tax) ·
`distil-small.en` (trained for 30 s chunks) · TOML hot reload · overlay window (tray + sound
cue instead) · command grammar · `enigo` (unused) · RTF as a metric. Keep one
`large-v3-turbo` CPU benchmark row for the record, then expect to cut it.

**Resolved by the user (2026-09-19) — now also cut:**
- **Hotword / hands-free — CUT.** No wake word, no VAD-driven endpointing as a trigger.
  PTT (plus toggle mode for long dictation) is the whole interaction model. VAD remains,
  but only as a *trimmer* inside an utterance, never as a trigger.
- **Pure-Rust Candle backend — CUT.** whisper.cpp via FFI is the permanent answer.
  `TranscriptionBackend` survives as an internal seam (one file) for testability — a
  `MockBackend` makes the FSM and injector testable without loading a model — but no second
  real backend is planned, and Phase 6 is deleted.

**Consequences of "no elevated windows" (user decision):**
Invariant **I-1 stands unconditionally** — the daemon refuses to run elevated and exits if
its own token is elevated. Admin terminals, Task Manager, UAC prompts and installer windows
are a **documented no-go**: `preflight()` detects an elevated foreground process and falls
back to clipboard-only with a toast. This also retires the S-01 Critical finding entirely,
since the privilege-escalation path required an elevated daemon.

---

## 10. Decisions

### 10.1 Locked (user, 2026-09-19)

| # | Decision | Consequence |
|---|---|---|
| 1 | Managed-device / EDR risk **knowingly accepted** | Phase 0 unblocked. No-AV-exclusion rule still stands as a hard stop. |
| 2 | **Keep whisper.cpp FFI** — permanent | Candle backend and Phase 6 deleted. Trait kept as an internal seam for `MockBackend` testing. |
| 3 | **Cut hotword** | No wake word, no VAD triggering. PTT + toggle only. Phase 5 deleted. |
| 4 | **No elevated windows** | I-1 unconditional; daemon exits if elevated. Admin windows = clipboard-only fallback. Retires S-01. |
| 5 | **Code signing: self-signed for Phases 0–3**, revisit at Phase 4 | $0, ~10 min. See §9.2. |

Phases 5 and 6 are gone. **The plan is now four phases: 0, 1a/1b, 2, 3, plus Phase 4 polish.**

### 10.2 Signing decision detail

Signing buys three things: SmartScreen "unknown publisher" suppression, tamper-evidence,
and attribution. It does **not** stop behavioral detection — a signed keyboard hook is still
a keyboard hook, and AV heuristics do not care who signed it. That is why signing
was never the answer to §0.1.

For a single-user tool on one machine, a **self-signed certificate** placed in
`Trusted Root` + `Trusted Publishers` on this machine gets the full benefit. Cost: $0.

Commercial options, if Phase 4 shows a concrete need (verified 2026-09-19):

| Option | Cost | Notes |
|---|---|---|
| Self-signed | **$0** | Trusted only on machines where you install the cert. Sufficient here. |
| Azure **Artifact Signing** (was Trusted Signing) | **$9.99/mo** Basic, 5k signatures | Managed, no hardware token. Individual validation is US/Canada only and needs an Azure billing account of type *Individual* + government-ID check. Org validation puts your **registered company name** in the certificate subject, meaning the company identity attests to a personal tool. Validation takes 1–20 business days. |
| Traditional OV cert | ~$200–600/yr | Since the 2023 CA/Browser Forum change, private keys must live on FIPS-140-2 L2 hardware — a USB token or cloud HSM. No more downloadable `.pfx`. |
| EV cert | higher | Immediate SmartScreen reputation. Overkill for one machine. |

**Recommendation taken: self-sign now.** Revisit only if Phase 4 produces a real blocker.

### 10.5 Second decision round (user, 2026-09-19)

| # | Decision | Consequence |
|---|---|---|
| 6 | **Audio retention ON** | Required for the correction-capture loop and voice-style profile (§7A.3). Changes the privacy posture — see below. |
| 7 | **Screen-context reading APPROVED** | Context conditioning (§7A.2) moves from opt-in-later to in-scope. Local only, never transmitted. |
| 8 | **LLM cleanup moved INTO the committed build** | The verbatim-vs-cleaned gap (§7A.4) is accepted as real and necessary. Becomes **Phase 3.5**, gated behind CP-3. |
| 9 | **Public repo** at `github.com/lonzosheffield/whisperrust` | Environment specifics sanitized into `LOCAL-ENV.md` (gitignored). See §10.6. |

#### Audio retention is now on — what that obligates

Retention was default-off for real reasons, and turning it on does not make those reasons
go away; it converts them into requirements. Since this machine is managed and its owner
works in compliance, the audio buffer may at times contain client-confidential or
privileged material. The following are now **requirements, not options**:

| # | Requirement |
|---|---|
| A-1 | **Bounded ring, not an archive.** `keep_audio = N` retains the last N utterances (default 200) and the last D days (default 30). Oldest evicted first. Never unbounded. |
| A-2 | **Encrypted at rest.** DPAPI (`CryptProtectData`, per-user) over the WAV and transcript store. A same-user process still reads it — this defends against disk/backup exposure, not local malware. State that limit plainly rather than implying more. |
| A-3 | **Never in the repo.** `audio/`, `evidence/`, `*.wav`, `*.jsonl` are gitignored. A commit hook rejects them. |
| A-4 | **Per-app deny list.** Apps named in `retention.deny_apps` are transcribed but never retained. Default deny: password managers, banking sites, anything flagged `is_password`. |
| A-5 | **Visible state.** The tray icon distinguishes "listening" from "listening + retaining". Retention must never be silently on. |
| A-6 | **One-command purge.** `whisperrust purge --audio --transcripts [--since]`, plus a tray item. Verified by CP-3 evidence. |
| A-7 | **Retention is a governed setting.** Changing the default, the window, or the deny list is an `AMEND` requiring explicit approval (§8, G-2). |

#### Screen-context reading — scope

Approved because it stays local. The boundary still gets written down:

- Reads the focused field, window title, and — in Outlook/Word — surrounding or quoted text,
  **solely** to build Whisper's `initial_prompt`.
- Context is used in-process and discarded. **Never** written to the session log, never
  retained, never sent anywhere. The daemon has no network stack (I-11).
- The same `retention.deny_apps` list suppresses context reading.
- **CP-3 must prove this with evidence**: a test that dictates into a page containing a
  known canary string and then greps every artifact on disk for it. Zero hits, or the
  checkpoint fails.

### 10.6 Publishing posture

The repo is public. `LOCAL-ENV.md` holds tenant, UPN, device ID, and the AV/MDM inventory,
and is gitignored.

The rule: **`docs/` is written to be publishable.** Environment specifics are referenced by
filename, never by value. Before any push, `scripts/check-secrets.ps1` scans tracked files
for the identifier set and fails the commit on a hit.

Worth stating plainly: a public repo makes this project's threat model public too.
`REDTEAM.md` is a detailed analysis of how this software could be abused. That is normal and
healthy for security-relevant software — a published threat model is a feature — but it
should be a decision, not an accident.

### 10.3 Still open — tuning (defaults in bold; say nothing and I'll take them)

| # | Question | Default if you don't care |
|---|---|---|
| 1 | Target apps — **ANSWERED, see §10.4** | — |
| 2 | PTT binding | **Right-Ctrl, unswallowed** (pending the §0.2 spike) |
| 3 | AC or battery, mostly? | Benchmark both; **optimize for battery** |
| 4 | Typical utterance length | **One to three sentences** |
| 5 | English only? | **Yes — `.en` models** (faster and more accurate) |
| 6 | Win+V history or a clipboard manager? | **Assume Win+V is in use** → exclusion work stays in scope |
| 7 | Keep last N audio clips for debugging? | **Off** |
| 8 | Audible cue on capture start/stop? | **Tray icon only, no sound** |
| 9 | Tried Win+H? What's unacceptable about it is the bar this must clear | — |

The only one I'd genuinely like an answer to is **#1**, because those five apps stop being
a preference and become the pass/fail gate for two phases.

### 10.4 Target applications (user-confirmed, 2026-09-19)

These eight are the literal pass/fail gate for Phases 1a and 3. "Works" means 20/20 clean
injections with no wrong-window paste and no clipboard loss.

| # | App | Injection default | Why it is interesting |
|---|---|---|---|
| 1 | VS Code | `unicode` | Electron — slow paste render (B-06 race) |
| 2 | Windows Terminal | `ctrl-v` | A stray `\n` **executes** (I-4 is load-bearing) |
| 3 | Chrome | `unicode` | One HWND for omnibox + page (B-03) |
| 4 | Slack | `unicode` | Electron; 1500 ms restore delay |
| 5 | Notepad | `ctrl-v` | Plain Win32 control — the baseline |
| 6 | **Codex** | inherits host | See note below |
| 7 | **Microsoft Word** | **`unicode` — forced** | Rich clipboard + autoformat (below) |
| 8 | **Outlook** | **`unicode` — forced** | Rich clipboard; To/Subject/Body in one window |

**Word and Outlook change an injection default.** Office keeps RTF/HTML on the clipboard.
Our `ctrl-v` path must first *write* the clipboard, which destroys that rich content — and
the restore policy cannot bring it back, because arboard can only snapshot plain text. So
"copy a table in Word → dictate → your table is gone."

`unicode` injection never touches the clipboard at all, so it sidesteps this entirely.
**Word and Outlook are therefore pinned to `unicode` regardless of length**, overriding the
≤300-character rule. Two consequences to verify in Phase 1a:

- **Autoformat will fight us.** Word/Outlook autocapitalize, convert straight quotes to
  smart quotes, and autocorrect as text arrives. Injected text may not match the transcript
  character-for-character. Phase 1a must record what Word actually produces, and we decide
  then whether to accept it (it is often *desirable* — Whisper's punctuation plus Word's
  capitalization) or suppress it.
- **Outlook is the sharpest case of B-03.** To, Cc, Subject and Body live in one window, so
  an HWND-level foreground guard passes while focus sits in the wrong field. Field-level
  checking is mandatory, not optional — dictating a paragraph into the To: line of a live
  email is a genuinely bad outcome.

**Codex needs one clarification.** It rides on a host we already cover, and the host
determines everything: Codex CLI → Windows Terminal (row 2), Codex in VS Code → row 1,
Codex on the web → Chrome (row 3). Tell me which surface you use and it collapses into that
row rather than being a ninth target. Defaulting to **Codex CLI in Windows Terminal**, which
is also the strictest case, since that is where a stray newline executes.
