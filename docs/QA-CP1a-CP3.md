# Independent QA — CP-0, CP-1a, CP-2, CP-3

**Date:** 2026-09-20 · **Reviewers:** two fresh-context Fable agents, neither of which built the code.

## Verdicts

| Checkpoint | Verdict | Reason |
|---|---|---|
| CP-0 | **CONDITIONAL** | Every measurable claim reproduced, including the 7× `/O2` finding. But nothing fails if `/O2` regresses, criterion (d) self-signed cert is not done, and the report has integrity slips. |
| CP-1a | **FAIL** | No evidence bundle (G-1). Three pass criteria are contradicted by the code itself. |
| CP-2 | **CONDITIONAL** | Amended: the raw log contained 62 WASAPI errors and ~1.4 s of lost audio that the summary omitted while marking the criterion PASS. |
| CP-3 | **FAIL** | No evidence bundle, no session log, 50-dictation criterion not performed, and five defects that would surface inside those 50 dictations. |

**This is what the gate is for.** Running QA per phase, as the plan specifies, would have caught most of
this one phase at a time. Running four at once means several defects are now embedded under later work.

---

## The defects that matter most

### D-1 (HIGH) — every pair of consecutive dictations is glued together

`postprocess::apply_join` prepends a space (`main.rs:406`); `deliver()` then calls
`sanitize()` (`main.rs:429`), which trims it (`sanitize.rs`, step 3). The join space
is destroyed after being added.

Measured by QA against the real code:

| Dictation 1 | Dictation 2 | Result |
|---|---|---|
| `First thought.` | `Second thought.` | `First thought.Second thought.` |
| `send the file to` | `Bob in accounting.` | `send the file tobob in accounting.` |
| `we should call` | `NASA about it.` | `we should callnASA about it.` |

Every unit test passes because **no test ever chains `apply_join` into `sanitize`**. Each
function is correct alone. The bug lives in the seam, which is exactly where unit tests
do not look.

### D-4 (HIGH) — the clipboard path sleeps the hook-owning thread

`deliver()` runs on the main thread (`main.rs:608`), which owns the keyboard hook.
It reaches `WinClipboard::restore_text`, which calls `std::thread::sleep` for
**750–1500 ms** (`clipboard.rs:210`, `policy.rs` slow-paste apps).

A `WH_KEYBOARD_LL` procedure cannot run while its thread sleeps. So every keystroke on the
machine stalls, and Windows silently unregisters the hook after repeated timeouts.

The project's own Phase 1a criterion says *"1500 ms stall → watchdog must re-hook."*
The design deliberately performs the exact stall its own criterion identifies as fatal.
Triggered by any dictation over 300 characters into Slack, Discord, Teams or VS Code.

### D-2/D-3 (HIGH) — the worker is deaf during inference

`transcribe_utterance` runs synchronously inside `run_actions`, so the audio drain and the
heartbeat both stop for the duration of inference. Measured: 1.75–1.81 s for an 11 s
utterance, **3.6–4.4 s for 44 s**.

Consequences: a PTT press during inference is lost or arrives with `hold≈0` and is discarded
as a short tap; the 2 s audio ring overruns once inference exceeds it; and any dictation
over ~30 s exceeds the 3 s heartbeat window, so it is downgraded to "daemon degraded —
clipboard only" while the hook goes transparent.

The Phase 2 "zero ring overruns" result was measured on a harness that never stalls the
drain, so it did not and could not detect this.

### D-7 (MED) — a filter layer is dead in production

`validate_pcm` pads audio to 1.0 s (`backend.rs:141`) *before* `audio_secs` is computed
(`backend.rs:263`). So `audio_secs >= 1.0` always, and the `< 0.3` duration check in
`postprocess.rs:153` can never fire. The unit test constructs a `Transcript` directly and
never exercises the real backend, giving false assurance.

### D-6 (MED) — legitimate one-word replies are silently discarded

`Thank you.` `Okay.` `Yeah.` `Bye.` are all rejected as hallucinations with no user feedback.
These are routine chat dictations. Meanwhile `[Music playing]` and `Subtitles by Amara.org`
are *accepted*, because the denylist is brittle exact-match.

### I-8 is only half implemented

`target.rs` checks `GWL_STYLE & ES_PASSWORD`, which works for Win32 controls (QA verified
live against a WinForms password box). It does **not** cover browser `<input type=password>`
or Electron — there is no UIA `IsPassword` check, which PLAN I-8 explicitly requires. The
doc comment claims "the browser case is handled conservatively by the caller"; it is not.
**REDTEAM B-02 is currently unmitigated in browsers.**

---

## What QA confirmed is genuinely sound

Worth recording, because the failures are concentrated at integration seams rather than in
the security core:

- **I-3 is compiler-enforced.** QA copied the project and tried two illegal `Clearance`
  constructions. Both were rejected: `test_clearance` does not exist outside `cfg(test)`,
  and the private field blocks struct-literal construction.
- **I-4 strips every C0/C1 control character** — verified against NUL, TAB, LF, CR, CRLF, VT,
  FF, ESC, DEL, NEL, CSI.
- **`emit()`'s runtime allowlist is the right shape** and refuses Enter, Delete, F4, 'A'.
- **The hook proc is allocation-free and never swallows.**
- **`validate_pcm` closes the ggml-abort door** — no path found to get NaN/Inf/empty to `full()`.
- **Clipboard-history exclusion actually works** — the test verifies the format is present
  after a write.
- **105 tests, 0 ignored**, no `todo!`/`dbg!`/`unimplemented!` anywhere.
- **The performance numbers are real**, reproducing within a few percent, with the 7× `/O2`
  speedup independently rebuilt and confirmed at 7.1–7.6×.

---

## Evidence-integrity findings against my own reports

- `phase-0/report.json` claims `runs: 2` for the PTT oracle; the artifact contains **one** run.
- The physical-key PTT run has **no artifact** — narrative only, which G-1 says is not evidence.
- `phase-0` `git_sha: af782e9` **predates** `20cbf5c`, the commit containing the `/O2` fix
  being measured.
- `phase-2` had no `git_sha` at all, and a round-number timestamp matching neither the log
  nor the file mtime.
- **G-1/G-2 infrastructure does not exist**: no `criteria/*.yaml`, no `criteria.sha256`,
  no `DEPS.md`, no `AMEND-nnn.md`. The "hash pinned per phase" trust boundary the plan
  mandates is currently unenforceable.

The pattern: **raw artifacts were honest, summaries smoothed them.**

---

## Fix order before CP-3 can be retried

1. **D-1** — apply the join *after* sanitize, or make sanitize preserve a leading space.
2. **D-4** — never sleep the hook thread; restore the clipboard from a helper thread.
3. **D-2/D-3** — move inference off the drain/heartbeat thread; timestamp PTT events in the
   hook rather than at processing time.
4. **D-5** — reset the hook's `HELD` flag when Watchdog B fires, or the next dictation is
   silently swallowed.
5. **D-10** — every non-`Injected` outcome must leave text on the clipboard; no restore on
   a failure path.
6. **D-7** — compute `audio_secs` from the un-padded length.
7. **D-6** — gate short denylist entries on `no_speech_prob` rather than exact match.
8. **I-8** — implement the UIA half, or have the user accept in writing that browser
   password fields are unprotected (G-2 requires restating a weakened security target).
9. **G-2 infrastructure** — `criteria/`, `DEPS.md`, pinned hashes, retroactively for 0–2.
10. Discharge outstanding items: physical PTT run artifact, self-signed cert, C920 unplug,
    sleep/resume.
