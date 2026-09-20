# WhisperRust — Red / Purple / White Team Review of PLAN v2

**Reviewer:** Fable (adversarial pass). **Inputs:** `docs/PLAN.md` v2, `docs/RECON.md`.
**Scope:** the user's own local-only dictation daemon on their own Windows 11 machine.
**Stance:** make the app *legible and provably benign*, never hidden. Nothing here is an
evasion technique; every EDR-related item is about honest false-positive reduction.

Two facts observed during this review that PLAN v2 does not know:

1. **This machine is Entra-ID (AzureAD) joined.** File ownership indicates an Entra-ID-joined account. That means a corporate MDM/EDR (very likely Defender for
   Endpoint) may be present, the device may be subject to an acceptable-use policy, and an
   unsigned binary that hooks the keyboard, holds the mic open and synthesizes input is
   exactly what that tooling is paid to notice. This raises the stakes of R12 from "Med"
   to a phase-blocking question (see S-14, W-2.4).
2. **Watchdog B in §5.1 is built on a false premise.** Microsoft's `LowLevelKeyboardProc`
   documentation states the hook is called *before* the asynchronous key state is
   updated, and a key the hook swallows (`return 1`) never reaches that update. So while
   the app swallows Right-Ctrl, `GetAsyncKeyState(VK_RCONTROL)` reports **up** for the
   whole hold, and Watchdog B will synthesize `Ptt::Up` ~50 ms into every capture.
   This is finding B-07 and it must be settled empirically in Phase 1a before the FSM is
   written.

Severity scale: **Critical** = data leaves the user's control or the machine becomes
unusable; **High** = private data lands somewhere it shouldn't or a real action is taken
in the wrong place; **Med** = recoverable damage / meaningful exposure requiring a
precondition; **Low** = hygiene.

Mitigation status vs PLAN v2: **Mitigated** / **Partial** / **Missed**.

---

# RED TEAM — attack the design

## A. Security & privacy threats

### S-01 · Critical (conditional) · Elevated mode turns a user-writable config into admin code execution
**Precondition:** Open Question 3 answered "yes, run elevated so I can dictate into admin
terminals."
**Scenario:** the app runs as high-integrity at logon. Config lives in `%LOCALAPPDATA%`
(medium-integrity writable). Any same-user process edits `model.path` to point at a
crafted ggml file, or drops a crafted file where the real model lives. ggml model loading
is a hand-written binary deserializer (header → hparams → vocab strings with
attacker-controlled lengths → tensor dims → allocations). The ggml/llama.cpp loader family
has had multiple memory-safety advisories in 2024. A crafted model = code execution
**inside the elevated process** = medium→high privilege escalation, with the mic, the
hook and `SendInput` already in hand.
**PLAN v2:** Missed (Q3 is left open; nothing says elevated mode changes the trust model).
**Verdict:** do not run elevated. Ever. Admin terminals are a documented no-go. If the user
insists, every input the elevated process trusts (config, models, override map) must be
in an admin-write-only location and the plan needs a separate review.

### S-02 · High · Model files are verified once at download, from the same server, in a user-writable directory
**Scenario A (local):** any same-user process overwrites
`%LOCALAPPDATA%\WhisperRust\models\ggml-small.en-q5_1.bin`. Next launch loads it. No
check. See S-01 for what a malicious model buys — even at medium integrity it is code
execution in the one process the user has trained themselves to expect mic/keyboard/
clipboard activity from.
**Scenario B (download):** "SHA256" in §10 is only integrity if the expected hash comes
from the same HuggingFace response. It is authenticity only if the hash is pinned *in the
binary* by a human who verified the artifact once.
**Scenario C (VAD):** `ggml-silero-v6.2.0.bin` is a second ggml deserialization surface
(RECON Landmine 2); PLAN v2 does not say how it is obtained or verified.
**PLAN v2:** Partial (hash at download only; source of truth unspecified; no at-load check).

### S-03 · Med (High if S-01) · `PostMessageW` + `WM_APP` carrying a boxed pointer is an attack surface
**Scenario:** §4: worker→main via `PostMessageW` + `WM_APP` "carrying a boxed
`Inject { text, target_hwnd, target_exe }`". Any process on the desktop can
`PostMessageW(our_hwnd, WM_APP, junk, junk)`. Main thread does `Box::from_raw(junk)` →
arbitrary pointer dereference and free. Crash at minimum; worse if the allocator is
groomed. Also: any process can inject a *fake* `Inject` by finding a valid heap pointer?
No — but they don't need to; the crash is enough to make the app look hostile in a crash
dump, and in elevated mode this is an EoP primitive.
**PLAN v2:** Missed.

### S-04 · Med · Synthetic keystrokes from any process can drive the PTT
**Scenario:** a same-user process calls `SendInput` with `VK_RCONTROL` down. The hook
treats it as real PTT (it only filters `dwExtraInfo == OUR_MAGIC`, i.e. *our own*
input). The app records up to the 60 s cap, transcribes whatever the room says, and puts
the result on the clipboard / into the foreground window, where the same process reads it.
The attacker already had mic access, so this is not a new capability — but it lets them
use *our* expected mic activity and *our* process as cover, and it defeats the mic
indicator's meaning. It also makes the app scriptable by any macro tool, silently.
**PLAN v2:** Missed. Cheap fix: honor `LLKHF_INJECTED` (bit 4) — a documented flag set
on all `SendInput`/`keybd_event` input — and refuse to treat injected keys as PTT unless
`hotkey.accept_injected = true` (off by default; needed only by AutoHotkey-style remaps).

### S-05 · High (when enabled) / Med (default off) · Debug audio ring is plaintext ambient audio with no visible state
**Scenario:** `debug.keep_audio = N` writes WAVs to disk. Each WAV includes the 400 ms
preroll — i.e. audio from *before* the user chose to dictate. Nothing caps `N`, nothing
expires them, nothing encrypts them, and nothing on screen says "audio is being retained."
A one-line config edit (by the user, by a well-meaning agent debugging WER, or by anything
that can write the file) silently turns the app into an audio archive. Same-user processes
read `%LOCALAPPDATA%` freely.
**PLAN v2:** Partial (default 0 only).

### S-06 · Med · Text session log and "last 5 transcripts" are plaintext
**Scenario:** with `log.text = true` every dictation is appended to a JSONL file forever.
Even with text off, `foreground_exe` + timestamps is an activity timeline. "Last 5
transcripts → copy" in the tray must be memory-only; if it persists across restart it is
a second plaintext store.
**PLAN v2:** Partial (text opt-in; no rotation, no cap, no purge, no encryption, tray
history persistence unspecified).

### S-07 · Med · The clipboard route broadcasts every dictation to every clipboard listener
**Scenario:** `ctrl-v` injection means each dictation is placed on the system clipboard.
Every process with `AddClipboardFormatListener` (clipboard managers, Office, PowerToys,
some browsers' native helpers, RDP client with clipboard redirection, Phone Link) gets
`WM_CLIPBOARDUPDATE` and can read it. The three exclusion formats
(`ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory`,
`CanUploadToCloudClipboard`) stop Win+V and cloud sync — they are **advisory**; a
third-party manager honors them only if it chooses to. Inside an RDP session with
clipboard sharing, the local clipboard is mirrored to the remote host regardless.
**PLAN v2:** Partial (formats covered; the choice of clipboard as the *default* transport
is not examined as a privacy lever; RDP only handled by the `mstsc.exe = unicode` map
entry, which is a default the user can remove).

### S-08 · Med · Supply chain: crates, vendored C++, build scripts, no policy
**Facts:** `whisper-rs-sys` vendors a whisper.cpp snapshot and runs CMake + bindgen from
`build.rs` (arbitrary code at build time, by design). The `windows` crate pulls a large
transitive tree. `enigo` appears in §2's version table although §5.2 uses `SendInput`
directly — every unnecessary crate is unreviewed code with `build.rs` rights.
**What is unverified:** nothing states that `Cargo.lock` is committed, that git
dependencies are forbidden, that `cargo deny`/`cargo audit` run, or which whisper.cpp
commit is actually being compiled. An agent adding a "helpful" crate mid-phase is the
most likely way this project's trust boundary changes without anyone noticing.
**PLAN v2:** Missed.

### S-09 · Med · The daemon links an HTTP client, so "no network" cannot be enforced by the OS
**Scenario:** §10 puts model download in the same binary. Therefore the daemon's import
table and dependency tree contain TLS + HTTP. The user (and the corporate EDR) cannot
distinguish "the daemon downloading a model" from "the daemon exfiltrating." A Windows
Firewall outbound-block rule on the daemon exe — the single most legible "this thing
never talks" control — becomes impossible without breaking the downloader.
**PLAN v2:** Missed.

### S-10 · Med · Per-user install location lets any same-user process replace the trusted binary
**Scenario:** if the exe lives in `%LOCALAPPDATA%` and autostarts from `HKCU\...\Run`,
malware running as the user overwrites the exe in place. The Run key still points at it;
the tray icon still looks right; the signature (if any) is gone but nobody checks. Signing
buys nothing if the file is user-writable.
**PLAN v2:** Missed (install location unspecified; signing treated as a SmartScreen issue).

### S-11 · Med · Crash dumps and panic messages carry audio, transcripts and the user's *previous* clipboard
**Scenario:** WER LocalDumps (or an in-app minidump writer with full memory) captures the
preroll ring, the utterance buffer, `last_injected`, the "last 5 transcripts", and the
clipboard snapshot taken for restore — which may be a password a password manager put
there 10 s ago. Rust panics that `unwrap()` a `Result<String>` print the payload. A
`Debug` derive on `Inject { text, .. }` puts transcripts into any `{:?}` log line.
**PLAN v2:** Missed ("crash-marker log" contents unspecified).

### S-12 · Med · The hook proc sees every keystroke; nothing in the design proves it only *uses* one
**Scenario:** this is the keylogger question. The code in §5.1 is correct, but the
guarantee is one careless `log::trace!("{k:?}")` away from being false, and an autonomous
agent adding debug logging to diagnose a hook problem is a *likely* event.
**PLAN v2:** Missed as an enforced invariant (correct by inspection only).

### S-13 · Low · In-memory audio ring is readable by any same-user process
`OpenProcess(PROCESS_VM_READ)` on a same-user medium-integrity process succeeds. The 400 ms
ring plus the current utterance are in plain memory. A process that can do this can also
just open the mic. Accept; note that the always-open stream keeps the Windows mic-in-use
indicator permanently lit (see B-10 — this is a UX finding with a security consequence:
the user learns to ignore the indicator).
**PLAN v2:** N/A — accepted risk; document it.

### S-14 · Med (phase-blocking on this device) · Legibility to security tooling and to the user
**Scenario:** an unsigned exe, no version resource, LL keyboard hook, WASAPI capture,
`SendInput`, clipboard writes, an HTTP client (S-09), living in `%LOCALAPPDATA%`, started
from a Run key, on an Entra-joined laptop. That is the textbook infostealer profile. Two
outcomes: EDR quarantines it (project dead), or it is allowed and the user has installed
something *indistinguishable from spyware* by their org's tooling — which is a policy
exposure for the user personally.
**PLAN v2:** Partial (R12 acknowledges SmartScreen; nothing about behaviour transparency,
version resources, install hygiene, or the Entra context).

### S-15 · Low · Single-instance mutex squat
A `Local\WhisperRust` mutex pre-created by another process prevents startup. Trivial DoS;
log the owner PID and toast. Accept.

### S-16 · Low · Config parsing surfaces
TOML from a user-writable path: cap file size (64 KB), reject unknown keys under
`--validate-config`, require override-map keys to be bare exe basenames (no path
separators, no wildcards, case-folded), cap `initial_prompt` at 1 KB. `whisperrust
transcribe <wav>` parses untrusted WAVs — use `hound` with explicit length checks; a bad
WAV must produce an error, not reach ggml (§5.5 validation covers the samples, not the
header).

## B. Catastrophic UX failures (ranked)

### B-01 · High · Injected control characters execute in a terminal
**Scenario:** Whisper output normally has no newlines, but multi-segment joins, the
"text joining" step, custom vocab, or a future agent "fix" can introduce `\n`. Into
Windows Terminal via `unicode` typing, `\n` is Enter: the transcribed sentence is executed
by the shell. (Windows Terminal's multi-line paste warning only guards `ctrl-v`, and only
if the user hasn't disabled it.) Also `\t` triggers completion, `\x03` is SIGINT, `\x1b`
starts an escape sequence.
**PLAN v2:** Missed. Nothing sanitizes injected text; nothing constrains which virtual
keys the injector may ever synthesize.

### B-02 · High · Dictation lands in a password field
**Scenario:** the user starts talking with focus in a browser `<input type=password>`,
or a credential prompt (1Password, Git Credential Manager, a browser basic-auth dialog)
steals focus after PTT-down. Text arrives masked; the user cannot see it is wrong; they
press Enter; the transcript is now in a login attempt (and in that site's auth logs). The
reverse case — the user dictating a real password, which then lives on the clipboard and
in the session log if text logging is on — is also real.
**PLAN v2:** Missed.

### B-03 · High · Same window, different field: the foreground guard passes, the text goes to the omnibox
**Scenario:** PTT-down in Chrome's Slack tab compose box; during the 1–2 s inference the
user clicks the address bar (or Cmd-palette in VS Code, or the search box in Teams). HWND
and exe are unchanged → guard passes → dictation is typed into the omnibox → Enter → the
sentence is sent to Google. Everything in Chrome/Electron is one HWND; the guard as
specified cannot see focus moving inside it.
**PLAN v2:** Partial (HWND+exe only).

### B-04 · High · A capture that ended because the hook broke is still transcribed and injected
**Scenario:** §5.1 Watchdog B "synthesizes an Up"; the 60 s hard cap "auto-finalizes." In
both cases the app did *not* observe the user's intent to stop. Whatever was said in that
window — a phone call, a colleague at the desk — is transcribed and pasted into the
foreground app. This is the always-on-mic nightmare with a legitimate-looking cause.
**PLAN v2:** Missed (finalize-and-inject is the default for watchdog-ended captures).

### B-05 · High · Toggle mode has no cap, no cue, no silence stop
**Scenario:** user toggles dictation on for a long paragraph, gets interrupted, walks into
a meeting with the laptop. Everything is transcribed and, on toggle-off (or never), pasted.
**PLAN v2:** Missed (toggle mode is listed in Phase 4 with no constraints).

### B-06 · High · Clipboard restore races the target's paste → the *previous* clipboard is pasted
**Scenario:** we set clipboard → `Ctrl+V` → restore after 300 ms. Electron under load
processes the key message at 200+ ms (the plan's own number) and reads the clipboard
*after* we restored it. The user's previous clipboard content — a URL, a password from a
manager, a chunk of source — is pasted where the dictation should have gone. Because
restore is silent, the user has no idea why.
**PLAN v2:** Partial (sequence-number check protects the *clipboard*, not the *paste*).
Also unspecified: on the "Copied — window changed" fallback, restore must be **disabled**
(otherwise the toast lies — the text is gone 300 ms later).

### B-07 · Med (Critical with a bad binding) · Stuck/swallowed PTT key and a Watchdog B that cannot work
**Scenario 1 (proven, see preamble):** the hook swallows R-Ctrl down; per Microsoft the
swallowed event never updates the async key state; `GetAsyncKeyState(VK_RCONTROL)`
reports up throughout the hold; Watchdog B fires at 50 ms; every dictation is ≤50 ms
long and skipped by the <250 ms rule. The app does nothing and looks broken.
**Scenario 2:** worker hangs but main is alive → hook keeps swallowing → the PTT key is
dead system-wide until the user finds the tray icon. If the user ever binds L-Ctrl, a
mouse button, or Caps Lock, "dead" means Ctrl+C/V/Z/S are gone everywhere: the machine
*feels bricked*.
**Scenario 3 (UIPI):** correctly identified in the plan; but the recovery path relies on
Scenario 1's broken oracle.
**PLAN v2:** Partial (problem identified, mitigation unsound).

### B-08 · Med · Runaway or repeated injection
**Scenario:** FSM re-delivers the same `Inject`; Whisper repetition loop ("Thank you.
Thank you. Thank you…" ×40); a 5-minute toggle capture produces 5 KB and the injector
types it for 20 seconds while the user tries to stop it. No length cap, no rate limit, no
cancel.
**PLAN v2:** Partial (hallucination denylist; no cap/rate/cancel).

### B-09 · Med · Modal editors and terminals treat typed letters as commands
**Scenario:** `vim.exe = "unicode"` in the default map. In Normal mode, typed letters are
commands: "Delete the last…" → `D` (delete to EOL) `e` (word) `l`… Each letter does
something. `ctrl-v` in Normal mode is visual-block, no paste. Neither method is safe.
Same class: tmux prefix mode, Emacs with a pending chord, any REPL in a special mode.
**PLAN v2:** Missed (only two methods exist; both are wrong for modal targets).

### B-10 · Med · Always-open mic desensitizes the user to the OS mic indicator
**Scenario:** Windows 11 shows a mic icon in the tray whenever any app captures. This app
captures 24/7 (for a 400 ms preroll), so the icon is *always on* and the user stops
seeing it — for this app and for every other app. Settings → Privacy → Microphone shows
continuous use, which on a managed device is a conversation with IT.
**PLAN v2:** Missed (always-open is assumed, not justified against on-demand capture).

### B-11 · Low-Med · 400 ms preroll captures the tail of a private sentence
"…the PIN is 4-4-1-[PTT] okay note to self…" → "one, okay note to self". 400 ms is a
syllable or two. Acceptable and the plan already cut it from 1.5 s; make it configurable
to 0 and keep it visible in the privacy statement.
**PLAN v2:** Mitigated (mostly).

### B-12 · Low-Med · Right-Ctrl is permanently consumed; reflex chords break
`return LRESULT(1)` on R-Ctrl means R-Ctrl+C never copies again, system-wide, while the
app runs. A user who holds PTT and reflexively hits `c` types a bare "c" into their
document. Also: confirm this laptop's keyboard *has* a physical Right-Ctrl (many compact
layouts replace it with Fn/Menu).
**PLAN v2:** Partial (acknowledged as "apps never see a bare Ctrl"; cost not stated).

### B-13 · Low · Injection into games / anti-cheat
`SendInput` into a game with kernel anti-cheat can trigger a ban; some anti-cheats also
flag processes holding `WH_KEYBOARD_LL`. Low for this user unless they game.
**PLAN v2:** Missed; cheap to deny-list.

### B-14 · Low · Watchdog A's liveness probe is a visible keystroke
"An unused scancode tagged OUR_MAGIC" every 30 s is still a key event delivered to the
foreground app (and forwarded over RDP). Games and some terminals log unknown keys.
**PLAN v2:** Partial. Use a `KEYEVENTF_KEYUP` of `VK_F24` — a key-up for a key that is
already up is a no-op everywhere but still traverses the hook chain.

---

# PURPLE TEAM — defense, detection, verification

Format per item: **Defense** (what the code does) · **Invariant** (what must always be
true, and where it is asserted) · **Telemetry** (how we know it fired) · **Test** (binary
pass/fail, automation level `auto` / `semi` / `manual`).

## P-1 · Trust model and process boundaries (S-01, S-02, S-03, S-09, S-10)

**Defense**
- Never run elevated. `main()` calls `GetTokenInformation(TokenElevation)` on itself and
  **exits with an error** if elevated. Admin windows are a documented no-go.
- Split into two binaries: `whisperrust.exe` (daemon: hook, mic, inference, injection —
  **no network code linked at all**) and `whisperrust-fetch.exe` (downloader: HTTP + hash
  + atomic rename — no hook, no mic, no clipboard). The daemon spawns the fetcher only on
  an explicit tray click and shows progress from its stdout.
- Expected model hashes are **compiled into the daemon** (`models.rs`: name → SHA-256 →
  size → source URL). Verified once by a human from HuggingFace's LFS pointer
  (`https://huggingface.co/<repo>/raw/main/<file>` shows `oid sha256:…`) and cross-checked
  against a local download. The fetcher refuses to keep a file whose hash is not in the
  table. The daemon **re-hashes every model on every load** (Meteor Lake has SHA-NI;
  `sha2` uses it; 465 MB ≈ 0.3–0.5 s, done on the worker before `warm()`, off the hotkey
  path). Mismatch → the model is not loaded, tray shows "model failed verification", the
  file is renamed `*.quarantined`, and the app runs in Disabled mode.
- The Silero VAD model is `include_bytes!`'d into the binary (864 KB) with its hash
  asserted in a unit test. It is never read from disk.
- Worker→main: `PostMessageW(hwnd, WM_APP_DOORBELL, 0, 0)` carries **nothing**; main drains
  a `crossbeam_channel::Receiver<Inject>` it owns. Any `WM_APP` with non-zero params is
  ignored and counted.
- Install to `%ProgramFiles%\WhisperRust\` via an MSI (admin once). Config and models in
  `%LOCALAPPDATA%\WhisperRust\`. The daemon checks at startup that its own exe path is
  not user-writable (`GetNamedSecurityInfoW` + `AccessCheck` for `FILE_WRITE_DATA` under
  the current token) and toasts a warning if it is.

**Invariants**
- `cargo tree -p whisperrust -e normal` contains none of: `reqwest ureq hyper curl
  rustls native-tls openssl tokio`. Asserted by `tools/check-deps.ps1` in CI and in every
  phase evidence bundle.
- `grep -rn "from_raw" src/main_thread/` is empty.
- No `unsafe` outside `src/win32/` (`#![forbid(unsafe_code)]` on every other module).

**Telemetry:** JSONL event `model_verify {name, sha256_ok: bool, ms}` on every load;
`wm_app_ignored` counter in the tray "diagnostics" dialog.

**Tests**
- `auto` — Flip one byte in a copy of a model; launch daemon with `model.path` pointing at
  it; assert exit state `Disabled`, quarantine file exists, no `WhisperState` created
  (log line absent).
- `auto` — `PostMessageW(hwnd, WM_APP+1, 0xdeadbeef, 0xdeadbeef)` 1000× from a test
  process; daemon still responds to a subsequent IPC ping; `wm_app_ignored == 1000`.
- `auto` — Start daemon under an elevated token (`Start-Process -Verb RunAs` in the test
  runner, which will prompt once): exit code = `EXIT_REFUSED_ELEVATED`.
- `auto` — Windows Firewall rule `WhisperRust daemon: block outbound` created by the
  installer; `Get-NetFirewallRule` shows it; the daemon's 10-min soak produces zero
  `netstat -b` entries for its PID.

## P-2 · Hook integrity and PTT truth source (S-04, S-12, B-07, B-12, B-14)

**Defense**
- Honor `LLKHF_INJECTED`: injected events are never PTT unless `hotkey.accept_injected`.
- **Empirical spike first** (Phase 1a, task 1a.0): with the hook swallowing the PTT key,
  record whether (a) `GetAsyncKeyState`, (b) `GetKeyState`, (c) Raw Input
  (`WM_INPUT`, `RIDEV_INPUTSINK`) observe the physical down/up. Record the truth table in
  RECON.md. The FSM design depends on it. Expected: (a),(b) do not; (c) may.
- **Default binding is a dead key that is not swallowed.** Recommend `VK_F24` via a
  hardware/PowerToys remap, or `Scroll Lock`/`Pause` for keyboards that have them. A
  non-swallowed key means `GetAsyncKeyState` is a valid physical oracle, no application
  loses a shortcut, and B-12 disappears. Modifiers (R-Ctrl/R-Alt/R-Shift) remain
  selectable with a config warning: "stuck-key recovery is time-cap only with this key."
  **Forbidden bindings** (config validation error): L-Ctrl, L-Shift, L-Alt, either Win,
  Caps Lock, any alphanumeric, Esc, Enter, Space, Tab.
- Mouse X-buttons (if the user picks them in Q4) must be swallowed (browsers navigate on
  them) — they get the same time-cap-only recovery warning.
- `HEALTHY: AtomicBool` — worker heartbeats every 1 s; main's timer clears it after 3 s
  stale. **The hook proc passes everything through when `!HEALTHY`** — a sick app eats no
  keys.
- Watchdog A probe = `KEYEVENTF_KEYUP` of `VK_F24`, tagged `OUR_MAGIC`, every 30 s.
- Hook proc file `src/win32/hook.rs`: contains no `log`/`tracing`/`print`/`format`
  macros, references `vkCode` exactly once (comparison against `PTT_VK`), and its only
  outbound side effects are `TX.try_send(Ptt::…)`, `LAST_SEEN.store`, `KILL.store`.
  Enforced by `tools/lint-hook.ps1` (a grep) in CI.

**Telemetry:** `hook_reinstall {reason}`, `ptt_injected_ignored` counter, `healthy=false`
transitions, all in JSONL.

**Tests**
- `auto` — `SendInput(VK_RCONTROL down)` from the test process (no magic): FSM stays
  `Idle`; `ptt_injected_ignored == 1`.
- `auto` — Hang the worker (`--test-fault worker-hang`): within 3 s R-Ctrl reaches Notepad
  (UIA reads a Ctrl+A select-all effect); after unhang, PTT works again.
- `auto` — Hang main 1500 ms (`--test-fault main-stall=1500`): Windows removes the hook;
  Watchdog A logs `hook_reinstall{reason:"probe_missed"}`; next PTT works.
- `auto` — Lint: `tools/lint-hook.ps1` exit 0.
- `semi` — Elevated-foreground stuck case: script opens an elevated `cmd` (one UAC prompt),
  test presses PTT in Notepad, alt-tabs to the elevated window, releases: FSM leaves
  `Capturing` within 200 ms (if Raw Input works) or at the time cap (if not) — and either
  way **no text is injected** (B-04).

## P-3 · Injection preflight — the one function that decides whether text leaves the app (B-01…B-06, B-08, B-09, B-13)

**Defense:** one pure function, in one file, unit-tested against synthetic contexts:

```rust
pub fn preflight(ctx: &InjectCtx, cfg: &Cfg) -> Decision  // Inject{method} | ClipboardOnly{reason} | Drop{reason}
```
Checked **in this order**, first failure wins, reason code is logged:

| # | Check | On failure |
|---|---|---|
| 1 | `mode == Normal` and `!KILL` | Drop |
| 2 | `ctx.end_cause == UserKeyUp` (not `Watchdog`, `TimeCap`, `Silence`) | **ClipboardOnly** "Ended automatically — copied, not pasted" |
| 3 | desktop is `"Default"` (`OpenInputDesktop` + `GetUserObjectInformationW(UOI_NAME)`) | Drop (secure desktop) |
| 4 | foreground HWND == recorded **and** exe == recorded **and** focused element == recorded (`GetGUIThreadInfo().hwndFocus` for Win32; UIA `GetFocusedElement().GetRuntimeId()` for single-HWND apps, resolved at PTT-up and again now, ≤30 ms budget, on the worker) | ClipboardOnly "window changed" |
| 5 | foreground process not elevated (access-denied ⇒ elevated) | ClipboardOnly "elevated window" |
| 6 | focused element is not a password field: UIA `CurrentIsPassword`, or Win32 `ES_PASSWORD` style on `hwndFocus`, or exe in `password_prompt_exes` (`1Password.exe`, `CredentialUIBroker.exe`, `git-credential-manager.exe`, `LogonUI.exe`) | **Drop** + toast "Refused: password field". Not even the clipboard — a password-field context means the user may be about to paste a secret, and we must not replace it. |
| 7 | exe not in `deny_inject` (defaults: games list, `mstsc.exe`, `vmconnect.exe`, `msrdc.exe`) | ClipboardOnly |
| 8 | exe not in `clipboard_only` (defaults: `vim.exe`, `nvim.exe`, `neovide.exe`, `gvim.exe`, `emacs.exe`) | ClipboardOnly |
| 9 | text passed `sanitize()`: NFC-normalized; all `\r\n\t` and C0/C1 controls replaced by a space (or dropped); no `U+2028/2029`; length ≤ `inject.max_chars` (default 2000; toggle mode 5000); repetition filter (any 3-gram repeated >3× consecutively → truncate at the first repeat and flag) | Drop if empty after sanitize; else inject the sanitized text |
| 10 | no injection in flight; ≥250 ms since last injection ended | queue once, then Drop |
| 11 | Shift/Ctrl/Alt/Win physically up within 300 ms | switch to `unicode` |

Injector rules (`src/win32/inject.rs`):
- The only `INPUT` records it can build: `KEYEVENTF_UNICODE` chars, and the fixed chord
  `VK_CONTROL↓ 'V'↓ 'V'↑ VK_CONTROL↑`. A unit test enumerates the produced `INPUT[]` for
  a fuzzed string and asserts no `wVk` outside `{VK_CONTROL, 0x56, 0}`; a grep asserts
  `VK_RETURN|VK_TAB|VK_ESCAPE|VK_MENU|VK_LWIN` do not appear in the file.
- Unicode typing is chunked (64 chars per `SendInput`); `KILL` and `mode` are re-read
  between chunks; a kill mid-string stops within one chunk (~10 ms).
- Default method: `unicode` for ≤ `inject.clipboard_threshold` (default 300 chars), else
  `ctrl-v`. Rationale: `unicode` leaks to nobody but the target (S-07); `ctrl-v` is faster
  for paragraphs. Phase 1a measures both per target app and the table sets the default.
- Clipboard restore: `restore_delay_ms` default **750**, 1500 for a `slow_paste_exes` list
  (`slack.exe discord.exe Teams.exe ms-teams.exe Code.exe`). Restore is skipped entirely on
  any ClipboardOnly outcome and the previous text goes to tray → "Restore previous
  clipboard". The snapshot is a `Zeroizing<String>`, never logged, never in `Debug`.
- On a `ctrl-v` inject, the three exclusion formats are set in the same
  `OpenClipboard` transaction as the text.

**Invariants**
- `preflight()` is the *only* caller of `inject()`; `inject()` is `pub(crate)` and its
  single call site is asserted by grep.
- `Inject` and `Transcript` implement a redacting `Debug` (`"<{n} chars>"`).

**Telemetry:** `inject {outcome: Injected{method,chars,ms} | ClipboardOnly{reason} |
Dropped{reason}}` per utterance; tray diagnostics shows counts by reason for the session.

**Tests** (the 1a harness runs the daemon with `--test-ipc <pipe>`, a feature-gated
control channel that can push `Ptt::Down/Up` and a canned transcript straight into the
FSM; the release build is compiled with `--no-default-features` so the pipe does not
exist, and CI asserts the string `TESTIPC` is absent from the release binary):
- `auto` — Terminal: canned text `"echo pwned\r\n"` targeted at Windows Terminal running
  `pwsh -NoExit`; after inject, `Get-History` in that shell is empty and the prompt line
  contains `echo pwned` with no newline executed. Repeat for `\n`, `\t`, `\x03`, `\x1b[A`.
- `auto` — Password: a bundled test window (`tools/testwin.exe`, Win32 `EDIT` with
  `ES_PASSWORD`) and a local HTML page with `<input type=password oninput=counter++>`
  served from a file. Dictate; assert `counter == 0` (page JS via UIA `Value` of a
  visible span) and `EDIT` text length 0; JSONL shows `Dropped{PasswordField}`.
- `auto` — Same-HWND focus change: Chrome test page with two inputs; PTT-up with focus in
  A; harness clicks B during a `--test-fault inference-delay=1000`; assert B empty, A
  empty, clipboard has text, outcome `ClipboardOnly{FocusChanged}`.
- `auto` — Watchdog-ended capture: `--test-fault drop-keyup`; assert outcome
  `ClipboardOnly{AutoEnded}` and Notepad unchanged.
- `auto` — Restore race: target = `tools/testwin.exe --slow-paste 900` (reads clipboard
  900 ms after `WM_PASTE`); prior clipboard = `"PRIOR"`; assert the window received the
  dictation, not `"PRIOR"`, and clipboard equals `"PRIOR"` at t+3 s.
- `auto` — Fuzz `sanitize()` + `INPUT[]` builder with `proptest`: 10k cases, no forbidden
  `wVk`, no control chars in output.
- `auto` — Runaway: canned 20 KB string → injected ≤ `max_chars`; canned
  `"Thank you. "×50` → truncated, flagged `repetition`.
- `auto` — Kill mid-inject: canned 2000-char string via `unicode`; harness fires the kill
  chord after 200 ms; assert < 400 chars landed and mode == `Disabled`.

## P-4 · Data at rest (S-05, S-06, S-11, S-16)

**Defense**
- `debug.keep_audio`: hard cap 20; TTL 24 h enforced at startup and hourly; files
  DPAPI-encrypted (`CryptProtectData`, user scope) with a `.wav.dpapi` extension — the
  `transcribe` CLI decrypts transparently; **while N>0 the tray icon carries a red dot and
  the tooltip says "retaining N audio clips"**, and a toast fires at every startup.
- Text log: same DPAPI wrapping; rotate at 1 MB, keep 5; `whisperrust purge` deletes logs,
  clips and tray history; tray history is memory-only (`Zeroizing<VecDeque<String>>`, 5).
- Crash handling: no full-memory minidumps. If a minidump is written, `MiniDumpNormal`
  only (stacks + modules). WER LocalDumps is not configured by the installer. Panic hook
  logs `location` + a *type name*, never the payload string, for panics originating in
  `fsm`, `inject`, `clipboard`, `post`.
- `#[derive(Debug)]` is forbidden on `Inject`, `Transcript`, `ClipboardSnapshot`,
  `AudioBuf` (manual redacting impls; grep-enforced).
- Config: 64 KB cap, unknown-key rejection, override-map key validation (S-16),
  `initial_prompt` ≤ 1 KB, `hotkey` in the allowed set.

**Telemetry:** startup line `retention {audio_clips: N, text_log: bool}`; `purge` logs
counts deleted.

**Tests**
- `auto` — Set `keep_audio = 3`, run 5 dictations: exactly 3 `.wav.dpapi` files, none
  parse as RIFF, `transcribe` CLI decodes them, tray tooltip contains "retaining 3".
- `auto` — Panic in post-processing with transcript `"SECRETXYZ"` (`--test-fault
  panic-post`): grep every file under `%LOCALAPPDATA%\WhisperRust` for `SECRETXYZ` → 0
  hits; process still alive; worker restarted once.
- `auto` — `--validate-config` on a fixture with `"C:\\x\\vim.exe" = "unicode"` and
  `hotkey = "LControl"` → non-zero exit with both errors named.

## P-5 · Mic posture (B-05, B-10, B-11)

**Defense**
- `mic.mode = "always" | "on-demand"`. Phase 2 measures WASAPI stream-start latency on
  both mics; if p95 < 120 ms, **on-demand becomes the default** (no preroll, no permanent
  mic indicator, no 24/7 ring). Otherwise `always` stays default with `preroll_ms`
  configurable 0–400 and the privacy statement saying so explicitly.
- Toggle mode: `toggle.max_s` default 120 (hard max 300); a short cue every 30 s while
  on; auto-stop after `toggle.silence_s` (default 8) of VAD silence; tray icon red while
  capturing in any mode; a capture ended by cap or silence is `ClipboardOnly` (P-3 #2).
- Windows mic privacy check at startup (`E_ACCESSDENIED` → clear message) — already in
  plan.

**Tests**
- `auto` — Toggle on, play 10 s of speech then silence: capture ends at ≤ 8 s of
  silence; outcome `ClipboardOnly{AutoEnded}`.
- `auto` — Toggle on with continuous speech: capture ends at `max_s`, same outcome.
- `semi` — In `on-demand` mode the Windows mic indicator is absent while idle (screenshot
  of the tray, human-checked once per phase).

## P-6 · Supply chain and build legibility (S-08, S-09, S-14)

**Defense**
- `Cargo.lock` committed; `deny.toml` with `[sources] allow-git = []`,
  `unknown-registry = "deny"`, advisories `deny`, licenses allowlist. `cargo deny check`
  and `cargo audit` in CI and in every evidence bundle.
- `docs/DEPS.md`: the **dependency allowlist** — every direct crate with one line of
  justification. Adding a crate = plan amendment (W-6). Remove `enigo` (unused).
- Record the whisper.cpp commit compiled (`whisper-rs-sys` ships it; read
  `whisper.cpp/README`/`git` metadata in the vendored tree, log
  `whisper_print_system_info()` at startup).
- Binary hygiene for honest EDR legibility: `VERSIONINFO` resource with real
  `CompanyName`/`ProductName`/`FileDescription` ("Local push-to-talk dictation; installs
  a keyboard hook and reads the microphone while the hotkey is held"), no packer, no
  obfuscation, static imports only (no `GetProcAddress` of `SetWindowsHookExW`), stable
  file name, MSI installer with an uninstaller, the only persistence is one documented
  `HKCU\...\Run` value. Ship `docs/BEHAVIOR.md`: every OS capability used, why, and how
  to see it firing (Process Monitor filters, the JSONL, the tray diagnostics).
- Signing (Q12) becomes **required on this device** given Entra join; after signing,
  submit the binary to Microsoft's false-positive portal once. Before Phase 1a runs on
  the real session, the user checks with their IT whether a locally built, unsigned dev
  binary that installs a keyboard hook is acceptable on this managed device (W-2.4).

**Tests**
- `auto` — `cargo deny check` and `cargo audit` exit 0; `tools/check-deps.ps1` compares
  `cargo tree -e normal --prefix none | sort -u` against `docs/DEPS.lock.txt` → zero diff.
- `auto` — `Get-AuthenticodeSignature` on the release exe = `Valid` (Phase 4).
- `auto` — Release exe imports (`dumpbin /imports`) contain `SetWindowsHookExW` and
  `SendInput` statically and contain no `GetProcAddress` calls from our module — the
  capabilities are declared in the import table, not hidden.

## P-7 · Safe mode / degraded mode

```
enum Mode { Normal, ClipboardOnly, Disabled }
```
- **ClipboardOnly**: full pipeline, but `inject()` is never called; every result goes to
  the clipboard with the exclusion formats set and a toast. Entered by: any preflight
  failure for *that* utterance (per-utterance), or for the rest of the session on: 3
  preflight `Drop`s in 5 min, any `unsafe`-boundary error (`SendInput` returned fewer
  events than requested, `OpenClipboard` failed 3×), or `injection.enabled = false`.
- **Disabled**: hook passes through everything, mic stream closed, tray icon grey with a
  reason. Entered by: model verification failure, >3 hook re-installs in 10 min, >3
  worker restarts in 10 min, the kill chord, `--disabled` flag, or IT-policy file present
  (`%ProgramData%\WhisperRust\disabled` — a legible admin off-switch).
- Mode transitions are logged with reason; the tray shows the current mode; Normal is
  re-entered only by the user (tray → "Resume") or restart.
- Rule: **when unsure, do not inject, leave on clipboard, tell the user.** Every ambiguous
  branch in the FSM resolves to ClipboardOnly, never to Inject.

**Test** `auto` — property test over the FSM: for every (state, event) pair, the FSM's
output is in `{Nothing, ClipboardOnly, Inject}` and `Inject` is produced only when
`end_cause == UserKeyUp && mode == Normal`.

## P-8 · Emergency stop

Layered, each independent of the layer above it being alive:
1. **Esc while Capturing/Transcribing** → cancel: discard audio, no clipboard, no inject.
   (Esc is not swallowed; it is observed.)
2. **Kill chord: PTT ×5 within 1 s** (observed in the hook proc itself, which runs on the
   main thread) → `KILL.store(true)`; the injector checks `KILL` between chunks; the FSM
   enters `Disabled`; hook passes through; toast "WhisperRust stopped — resume from tray".
3. **Tray → "Stop injecting" / "Exit"** (main thread).
4. **`whisperrust --stop`** from any shell: signals a named event
   `Local\WhisperRust.Stop`; the daemon exits within 1 s. Works from Terminal even while
   text is being typed into it, because `unicode` injection is chunked.
5. **If main is hung**, Windows removes the hook itself (LowLevelHooksTimeout) — keys
   return to the user within ≤1 s, and the mic is still open but nothing consumes it. Task
   Manager (Ctrl+Shift+Esc uses L-Ctrl, which is never a permitted binding) ends it.
6. **Admin off-switch** for IT: presence of `%ProgramData%\WhisperRust\disabled`.

The machine can never *feel* bricked because: L-Ctrl/L-Alt/Win/Esc/Enter are forbidden
bindings; a sick app passes keys through; and a hung main thread loses the hook by OS
design.

**Tests** `auto` — each layer: kill chord stops a 2000-char inject in <400 chars; `--stop`
terminates within 1 s during a soak; `disabled` file present at start → mode Disabled and
no hook installed (`tools/hookprobe.exe` confirms Notepad receives PTT key).

## P-9 · Priority — (impact × likelihood) ÷ cost

**Cheap and high value (do these first, all < half a day each):**
1. `LLKHF_INJECTED` check in the hook (S-04) — 3 lines.
2. `sanitize()` + the "only VK_CONTROL/'V'/UNICODE" injector invariant + unit tests (B-01, B-08).
3. `end_cause != UserKeyUp ⇒ ClipboardOnly` (B-04, B-05) — one FSM field.
4. Doorbell-only `WM_APP`, no pointers (S-03).
5. Hash-on-every-load with compiled-in table; VAD via `include_bytes!` (S-02).
6. Refuse to run elevated (S-01).
7. Forbidden-binding list + default to a non-swallowed dead key (B-07, B-12).
8. `HEALTHY` pass-through in the hook + kill chord (B-07, P-8).
9. Password-field check via `ES_PASSWORD`/UIA `IsPassword` (B-02).
10. Redacting `Debug` impls + panic-hook policy (S-11).
11. `restore_delay_ms` 750/1500 + no restore on fallback (B-06).
12. `cargo deny` + `DEPS.md` allowlist + `check-deps.ps1` (S-08).

**Medium cost, high value:** separate fetcher binary + firewall rule (S-09); UIA focused-
element identity in the foreground guard (B-03); Raw Input spike (B-07); DPAPI for
retained audio/text with the red-dot indicator (S-05, S-06); MSI to Program Files (S-10).

**Higher cost, still worth it:** signing + false-positive submission + `BEHAVIOR.md`
(S-14); on-demand mic if the latency allows (B-10); Windows Sandbox test rig (W-2.3).

---

# WHITE TEAM — governance for autonomous execution

The project will be executed by agents with Fable as QA at checkpoints. The plan is the
contract; this section is how the contract is enforced against drift.

## W-1 · Definition of Done — per phase, machine-checkable

Every phase has a criteria file `docs/criteria/phase-N.yaml`, written **before** the phase
starts, and a `tools/check-phase.ps1 -Phase N` runner that produces an evidence bundle.

```yaml
phase: 1a
criteria_version: 3        # bumps only via amendment (W-6)
items:
  - id: 1a-03
    statement: "Alt-tab during a 1 s artificial delay → no paste; text on clipboard; toast shown"
    level: auto             # auto | semi | manual
    check: tools/tests/1a-03-window-change.ps1
    expect: { exit: 0, jsonl_outcome: "ClipboardOnly{FocusChanged}", notepad_delta: 0 }
    evidence: [jsonl, screenshot, harness-stdout]
    owner: agent            # agent | human
```

The evidence bundle `evidence/phase-N/<utc-timestamp>/` contains: `report.json` (per-item
pass/fail with the captured values, not just booleans), all raw evidence files,
`env.json` (git commit, `Cargo.lock` SHA-256, release exe SHA-256, cargo features used,
rustc version, AC/DC, power plan, hostname), `deps.txt` (`cargo tree` snapshot),
`criteria.sha256` (hash of the criteria file that was run), and `qa-signoff.md` (written
only by Fable, then by the user for `manual` items).

**A phase is done when:** every `auto` item passes in one bundle produced from one commit;
every `semi` item has its evidence file plus a Fable line in `qa-signoff.md`; every
`manual` item has the user's line in `qa-signoff.md`; `criteria.sha256` matches the hash
recorded in `PLAN.md` for that phase; and `deps.txt` matches `docs/DEPS.lock.txt`.

Concrete DoD artifacts per phase:

| Phase | Artifact that proves it |
|---|---|
| 0 | `evidence/phase-0/…/report.json`: `cargo build` log, `whisperrust transcribe fixtures/jfk.wav` output equals reference text (Levenshtein ≤ 2), `cargo build --features vulkan` exit code, `whisper_print_system_info()` line, CMake version + the policy flag used, RECON.md updated with the Raw Input truth table (task 1a.0 can run here). |
| 1a | The injection matrix `matrix.json`: 5 apps × 20 runs × {unicode, ctrl-v} with landed-text diff = 0; plus every P-2/P-3/P-8 `auto` test green; Win+V screenshot (`semi`). |
| 1b | `bench/results.csv` with **every** cell of the matrix, both AC and DC, p50/p95 wall-clock and WER-proxy; a `bench/CHOICE.md` naming the model/backend/threads/audio_ctx with the row that justifies it; the target met or a signed renegotiation entry (W-6). |
| 2 | Soak log: ring-overrun counter 0, RSS series flat within 5 MB, device-unplug and sleep/resume events with recovery ms, the 3 s tone WAV with sample-count error < 0.1% (computed, in report). |
| 3 | 50 real dictations from the JSONL: `wrong_window == 0`, `clipboard_loss == 0`, silent-hold hallucinations 0/10, p95 ≤ 1b + 300 ms — computed by `tools/phase3-report.ps1`, not by hand. |
| 4 | Five daily-use days of JSONL, `Get-AuthenticodeSignature` Valid, fresh-profile install video (`manual`), `cargo deny`/`audit` green, `BEHAVIOR.md` present and reviewed. |

## W-2 · What agents MAY do vs MUST STOP for

**MAY, without asking:** read/edit source under `src/`, `tools/`, `docs/` (except
`PLAN.md`, `criteria/*.yaml`, `DEPS.md`); `cargo build/test/clippy/fmt`; run unit and
property tests; run the daemon with `--test-ipc` **inside the Windows Sandbox rig**; run
the `transcribe` CLI on fixture WAVs; write evidence bundles; open amendment proposals.

**MUST STOP and surface to the user (each a one-time approval that is then recorded in
`docs/APPROVALS.md` with date and scope):**

| Action | Why it stops | Approval granularity |
|---|---|---|
| 2.1 `winget install` of anything; enabling Windows Sandbox/Hyper-V features (reboot) | irreversible toolchain change on the user's machine | once per package list (Phase 0 list pre-approved by the plan) |
| 2.2 Any network fetch other than `cargo fetch` against the committed lockfile | the plan promises "local only" | once per model (name + pinned hash) |
| 2.3 Running any binary that installs `WH_KEYBOARD_LL` **on the user's live session** | it will eat/inject keys while the user works | a 2-hour window the user opens by creating `.allow-live-gui-tests` (runner refuses if the file is older than 2 h or absent). Default: run in Windows Sandbox (`tools/sandbox/wr.wsb` with `AudioInput Enable`, `ClipboardRedirection Disable`, `LogonCommand` → the harness). Every daemon launched by an agent runs inside a Job Object with `KILL_ON_JOB_CLOSE` and a 15-min time limit. |
| 2.4 First run of *any* dev build on this Entra-joined device | EDR/policy exposure | once, after the user has checked with IT or accepted the risk in writing |
| 2.5 Code signing (obtaining or using a cert) | identity-bearing | once |
| 2.6 Changing `deny_inject`, `clipboard_only`, `password_prompt_exes`, `slow_paste_exes` defaults, or the forbidden-binding list | security-relevant defaults | per change, via amendment |
| 2.7 Setting `debug.keep_audio > 0` or `log.text = true` anywhere except a Sandbox run | audio/text retention on the user's disk | per change; must be reverted at the end of the task and the revert is a checked item |
| 2.8 Adding, removing or upgrading a direct dependency; changing `deny.toml`; changing cargo features | trust boundary | per crate, via amendment |
| 2.9 Modifying `PLAN.md`, `criteria/*.yaml`, `DEPS.md`, `APPROVALS.md` | source of truth | amendment procedure only |
| 2.10 Any `unsafe` block outside `src/win32/`; any new `extern "system"` callback | memory safety boundary | per occurrence, Opus-authored, Fable-reviewed |
| 2.11 Elevation (`RunAs`) for any reason | S-01 | per occurrence |
| 2.12 Writing to `HKCU\...\Run`, Startup folder, scheduled tasks, or `%ProgramData%` | persistence | once (Phase 4 installer) |
| 2.13 Deleting user data (logs, clips, models) other than the agent's own test outputs under `evidence/` and the Sandbox | irreversible | per occurrence |

## W-3 · Anti-drift detection

The ways agents silently redefine success, and the concrete detector for each:

| Drift pattern | Detector |
|---|---|
| Criterion weakened ("p95 ≤ 1500" → "≤ 2500") or removed | `criteria.sha256` in the bundle must equal the hash pinned in `PLAN.md §7`; `check-phase.ps1` refuses to run otherwise. A criterion count per phase is also pinned. |
| Test stubbed (`#[ignore]`, `assert!(true)`, early `return Ok(())`, `if cfg!(test) { return }`) | `tools/lint-tests.ps1`: fails on `#[ignore]` without an `// AMEND-nnn` comment, on `assert!(true)`, on test bodies < 3 statements, on any `todo!/unimplemented!` in `src/`. `cargo test -- --list` count must be ≥ the count recorded at the previous checkpoint. |
| "Passed" without running | `report.json` must contain the captured *values* (ms, counts, diffs), a start/end timestamp, and the runner's own process id; Fable spot-re-runs ≥ 2 random `auto` items per checkpoint and diffs the values (they must be plausibly different — identical floats across runs are a red flag for a canned report). |
| Scope added ("while I was there I added a settings UI") | `git diff --stat` between checkpoints is compared with the phase's declared file list in the criteria file; files outside it → escalation. |
| Dependency added | `deps.txt` vs `DEPS.lock.txt` zero diff; `Cargo.lock` hash in `env.json`. |
| Feature flags changed to make a test pass | `env.json.features` must equal the pinned set; release must be `--no-default-features --features release`. |
| Threshold moved in code, not criteria (e.g. `max_chars` raised to make the runaway test pass) | Security-relevant constants live in one file `src/policy.rs` whose SHA-256 is pinned per phase; any change is an amendment. |
| Test targets the Sandbox only, but criterion says real session | criteria `env: sandbox | live` field; `env.json.hostname/sandbox=true` must match. |
| Manual criterion self-certified by an agent | `qa-signoff.md` lines are attributed; the runner rejects `manual` items whose signoff line is not by the user. |
| Success redefined in prose ("this is effectively done") | Fable's checklist item Q-2: a phase is done only when `report.json` says so — narrative in the agent's summary is not evidence. |

## W-4 · Model routing

**Rule an orchestrator can apply:** route to **Opus** if *any* of the following is true;
otherwise **Sonnet**.

1. The task touches `src/win32/**`, `src/fsm.rs`, `src/inject.rs`, `src/clipboard.rs`,
   `src/policy.rs`, `src/model_verify.rs`, or any `unsafe`/FFI/`extern "system"`.
2. The task's criterion is tagged `security: true` in the criteria file.
3. The task is diagnosing a failed criterion (root-cause work), not implementing a spec.
4. The task is an amendment proposal, a benchmark *interpretation* (choosing the model),
   or a design decision with more than one defensible answer.
5. Sonnet has failed the task once.
6. The task involves concurrency (the three-thread boundary, watchdogs, the audio
   supervisor) or Win32 semantics that are documented in edge cases (UIPI, hooks, clipboard
   ownership).

**Sonnet by default:** config/TOML schema and validation, CLI plumbing, WAV I/O, the
resampler wrapper, benchmark harness scripts, JSONL logging, tray menu plumbing, the
`sanitize()` function *given* its spec and tests, test scaffolding, docs, evidence-bundle
tooling, `check-phase.ps1`.

**Never two agents in the same module concurrently**; the orchestrator partitions by
file. Phase 1a and 1b run in parallel (different files, different machines: 1a in
Sandbox, 1b on the real host).

## W-5 · QA checklist — Fable at each checkpoint

1. Does `evidence/phase-N/<ts>/report.json` exist, from a single commit, with `criteria.sha256` matching `PLAN.md`?
2. Every `auto` item: pass, with captured values present and plausible (no zeros where work happened, no identical timings across runs).
3. Re-run ≥ 2 randomly chosen `auto` items myself; values within expected variance.
4. `semi` items: evidence file opened and inspected (screenshot, log excerpt), not just present.
5. `manual` items: user's signoff line present; if absent, phase is **not done** regardless of narrative.
6. `deps.txt` == `DEPS.lock.txt`; `cargo deny`/`audit` green; features pinned.
7. `git diff --stat` vs the phase's declared file list — anything outside it explained by an approved amendment?
8. `tools/lint-hook.ps1`, `lint-tests.ps1`, `check-deps.ps1` all exit 0.
9. `src/policy.rs` hash unchanged, or changed by an approved amendment.
10. Any `#[ignore]`, `todo!`, `unimplemented!`, `dbg!`, `println!` in `src/`? (grep)
11. Any new `unsafe` outside `src/win32/`? Any new `extern "system"`?
12. Any `debug.keep_audio > 0` or `log.text = true` left in a config on the live host? (`Get-Content` of the real config; must be default.)
13. Any live-session daemon still running? (`Get-Process whisperrust` → none unless the user started it.)
14. Retention artifacts on the live host created by tests? (`%LOCALAPPDATA%\WhisperRust\clips` empty.)
15. JSONL from the phase: count of `Dropped`/`ClipboardOnly` by reason — are the guards firing in the tests that are supposed to trigger them, and *not* firing in the happy path (>5% unexplained `ClipboardOnly` in the happy path = a regression)?
16. Read the agent's summary *last*, and only to check it does not claim more than the report shows.
17. Write `qa-signoff.md`: pass / fail with item ids; if fail, the escalation reason (W-7).

## W-6 · The plan as single source of truth; amendment procedure

- `docs/PLAN.md` is the contract. `docs/criteria/*.yaml` are its executable form;
  `docs/DEPS.md` and `src/policy.rs` are its trust boundary. Their hashes are listed in
  `PLAN.md §7` per phase.
- Reality will contradict it. When it does, the agent writes `docs/amendments/AMEND-nnn.md`:
  **Contradiction** (what was observed, with the evidence path) · **Proposed change**
  (exact diff to PLAN/criteria/DEPS/policy) · **Impact** (which criteria change, which
  findings in this document are affected) · **Alternatives rejected**.
- Fable reviews and appends a recommendation. **Only the user approves**, by adding
  `approved: <date> <initials>` to the amendment file. Then — and only then — an agent
  applies the diff, bumps `criteria_version`, updates the hash in `PLAN.md`, and appends
  a changelog line. `check-phase.ps1` refuses criteria files whose version has no
  matching approved amendment.
- Amendments that *loosen* a security invariant (anything in P-1…P-8) or a latency target
  require the user to restate the new target in their own words in the amendment file,
  not just "approved."
- Expected early amendments, so they are not treated as failures: the Raw Input truth
  table (B-07) changing the FSM design; the 1b benchmark missing 1500 ms on CPU; the
  on-demand mic decision; the Windows Sandbox rig proving unable to host one of the five
  target apps.

## W-7 · Hard-stop escalation triggers

Any of these halts the autonomous run; the orchestrator writes `ESCALATION.md` with the
evidence path and waits for the user:

1. A benchmark target missed with no CPU cell passing 1b (plan already says renegotiate — the *renegotiation itself* is the stop).
2. Any security invariant test (P-1…P-4, P-7, P-8 `auto` tests) fails on a commit that was previously green.
3. A dependency appears in `deps.txt` that is not in `DEPS.lock.txt`.
4. Files changed outside the phase's declared list without an amendment.
5. `criteria.sha256` or `policy.rs` hash mismatch.
6. Any agent action from W-2 executed without a recorded approval.
7. The daemon crashed, hung, or produced a `Dropped{…}` outcome on the **live** session (not Sandbox) during a test.
8. Any text landed in a window that was not the test target (the harness diffs Notepad + the target + the clipboard; anything else changing is a wrong-window event).
9. EDR/SmartScreen/Defender flags or quarantines any build artifact.
10. An agent proposes running elevated, disabling Defender, adding an exclusion, or "temporarily" weakening a guard.
11. Evidence bundle values are identical across two runs (canned report suspicion).
12. Any `manual` criterion is found marked done without a user signoff line.

## W-8 · Top-five governance rules (the ones that carry the rest)

1. **No evidence bundle, no done.** `report.json` with captured values, from one commit, with the criteria hash pinned in PLAN.md. Narrative is not evidence.
2. **The trust boundary is three files** — `criteria/*.yaml`, `DEPS.md`/`DEPS.lock.txt`, `src/policy.rs` — and their hashes are pinned. Any change is an amendment the user approves in writing.
3. **Agents never run the hook on the live session by default.** Windows Sandbox + Job Object + 15-min cap; the live session needs a 2-hour user-opened window, and *every* live daemon is stopped and retention config reverted before the checkpoint.
4. **Route by blast radius, not by difficulty.** Anything in `win32/`, `fsm`, `inject`, `clipboard`, `policy`, `model_verify`, anything `unsafe`, anything security-tagged, any root-cause work → Opus, Fable-reviewed. Sonnet builds to spec everywhere else.
5. **Fable re-runs, not re-reads.** At every checkpoint QA re-executes ≥ 2 random `auto` criteria, inspects `semi` evidence directly, and refuses `manual` items without the user's own line.
