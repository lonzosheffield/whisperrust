# Spike result — PTT state oracle (PLAN.md §0.2)

**Date:** 2026-09-20 · **Status:** RESOLVED · **Outcome:** Option A adopted

## Question

The daemon's keyboard hook was specified to *swallow* the PTT key (return 1) so
applications never see a bare Ctrl. Watchdog B was specified to poll
`GetAsyncKeyState(VK_RCONTROL)` to detect a stuck key.

The red-team review claimed these two are incompatible: a swallowed key never reaches the
asynchronous key-state table, so `GetAsyncKeyState` would read UP for the entire hold,
Watchdog B would fire ~50 ms into every capture, and **every dictation would be killed
before it started**.

This had to be settled before the state machine was written, because the answer determines
its shape.

## Method

`spikes/ptt-oracle` installs a real `WH_KEYBOARD_LL` hook and drives a key down/up cycle
while sampling `GetAsyncKeyState` and `GetKeyState` every ~20 ms. Each key is run twice —
once with the hook chaining via `CallNextHookEx`, once returning `LRESULT(1)`.

Three keys were tested to rule out anything specific to modifiers: `VK_RCONTROL`,
`VK_SCROLL`, `VK_PAUSE`.

## Result — claim CONFIRMED

| Key | Mode | Hook saw down | `GetAsyncKeyState` | `GetKeyState` |
|---|---|---|---|---|
| VK_RCONTROL | passthrough | yes | **DOWN** | **DOWN** |
| VK_RCONTROL | **swallow** | yes | **UP throughout** | **UP throughout** |
| VK_SCROLL | passthrough | yes | **DOWN** | **DOWN** |
| VK_SCROLL | **swallow** | yes | **UP throughout** | **UP throughout** |
| VK_PAUSE | passthrough | yes | **DOWN** | **DOWN** |
| VK_PAUSE | **swallow** | yes | **UP throughout** | **UP throughout** |

The hook observed key-down in every case — the input reached us. Swallowing prevents it
from reaching the key-state tables. **Both** oracles are blinded, not just the async one,
so `GetKeyState` is not an escape hatch either.

Reproduced across two independent runs. Raw output:
`evidence/phase-0/20260920T022704Z/ptt-oracle-synthetic.txt`.

## Decision — Option A: do not swallow

| Option | Verdict |
|---|---|
| **A. Do not swallow the PTT key** | **ADOPTED** |
| B. Swallow + Raw Input (`RIDEV_INPUTSINK`) as an independent oracle | Rejected — correct but buys complexity we do not need |
| C. Dead key (F24/ScrollLock/Pause), not swallowed | Rejected as default; kept as a config option |

**Rationale.** Not swallowing restores `GetAsyncKeyState` as a valid oracle, which keeps
Watchdog B simple and keeps the hook procedure trivial — and the hook proc is the one place
in this program where being slow gets us silently unregistered by Windows. Option B would
have added a second input pipeline and a message-only window to feed it, inside the most
latency-critical and least debuggable component.

**The cost is that applications see a bare Right-Ctrl press.** A lone Ctrl keypress is a
no-op in essentially every application — it is a modifier with no standalone binding. It is
not free in principle, so Phase 1a verifies it empirically across all eight §10.4 target
apps rather than assuming.

## Consequences for the plan

1. **§0.2 is resolved.** The hook chains via `CallNextHookEx` unconditionally for the PTT
   key. The `return LRESULT(1)` in the v3 sketch is deleted.
2. **Watchdog B is viable as originally specified** — but only *because* of this change.
   The dependency is now explicit: if anyone later reintroduces swallowing, Watchdog B
   breaks silently and every capture dies. This is recorded as an invariant.
3. **New invariant I-13:** *The PTT key is never swallowed.* Enforced by a test that
   asserts the hook proc returns `CallNextHookEx` for the configured PTT virtual-key, and
   by this spike being re-runnable as a regression check.
4. **Invariant I-12 is reinforced.** Since the key is no longer swallowed, a forbidden
   binding is now worse, not better: binding to L-Ctrl would leave Ctrl+C/V working but
   would still let a wedged app interfere. The forbidden list stands.
5. **Phase 1a gains a pass criterion:** in each of the eight target apps, holding and
   releasing the PTT key with no dictation must produce *no* visible effect — no menu
   activation, no focus change, no input.

## Caveat — synthetic vs physical input

The automated run drives the key with `SendInput`. Injected input traverses the same path
as physical input after the hook, so the mechanism under test is identical, and the result
is consistent across three keys and two state APIs.

It is nonetheless *injected*. `spikes/ptt-oracle --manual` runs the same trials against a
physically held key. **That run should be done once before Phase 1a closes**, to convert a
near-certainty into a verified fact. It needs a human to hold Right-Ctrl for three seconds,
twice.
