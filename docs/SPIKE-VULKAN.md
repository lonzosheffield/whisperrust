# Spike result — Vulkan backend (PLAN.md Phase 0 criterion b)

**Date:** 2026-09-20 · **Status:** PARKED · **Time spent:** ~25 min of the 2 h box

## Outcome

Vulkan is **parked**, exactly as the plan's time-box provides for
("on failure record 'Vulkan parked' and pass on CPU alone").

## What works

The Vulkan *runtime* is confirmed present and functional on this machine (Phase 0 recon):
`vulkaninfo --summary` enumerates `Intel(R) Graphics`, API 1.4.348, driver 101.8826, with
the ICD registered at `igvk64.json`. A Vulkan-enabled binary would find a device.

## What blocked

Building `whisper-rs --features vulkan` needs the **SDK** (headers, `vulkan-1.lib`,
`glslc` for compiling ggml's GLSL shaders), not just the runtime.

| Attempt | Result |
|---|---|
| LunarG installer, `--root .tools\VulkanSDK` (user scope) | `Installation aborted!` while unpacking `Helpers/VC_redist.x64.exe` — the VC redistributable step wants elevation, and the installer rolled the whole install back |
| Same, restricted to `com.lunarg.vulkan.sdk` | `Component(s) not found` — wrong identifier |
| `list` to discover component names | Not supported by this installer build |

Root cause is the same one that stalled the winget installs: **anything wanting elevation
stalls or aborts in this environment**, and the LunarG installer treats a failed sub-step
as fatal to the whole transaction.

## Why parking is the right call, not a concession

1. The plan explicitly permits it, and the time-box exists for exactly this shape of problem.
2. **The CPU path already meets the target.** `base.en` measured ~1357 ms on an 11 s clip,
   inside the p95 ≤ 1500 ms goal, once the `/O2` build defect was fixed. Vulkan was never
   load-bearing for shipping — it was load-bearing for *upgrading* to `small.en`.
3. Nothing downstream is blocked. Phases 1a, 2, 3 and 3.5 do not touch the backend build.

## What it costs us

One Phase 1b benchmark column. Concretely, the open question it would have answered:

> `small.en-q5_1` measured ~4343 ms on CPU — roughly 3x outside the latency target.
> Would the Arc iGPU bring it inside?

If Vulkan stays parked, `base.en` is the model and `small.en` is out of reach. That is an
acceptable outcome, not a failure.

## How to unpark

Two routes, in order of preference:

1. **Elevated install.** The standard LunarG installer run from an admin shell. ~10 minutes
   with a human present to approve the prompt. This is the reliable path.
2. **Portable assembly**, no elevation required — more fiddly but fully autonomous:
   - headers from `KhronosGroup/Vulkan-Headers` (GitHub release zip)
   - `glslc.exe` from `google/shaderc` release binaries
   - `vulkan-1.lib` from `KhronosGroup/Vulkan-Loader`, or generated from the system DLL
   - then set `VULKAN_SDK` to the assembled tree

Route 1 is worth ten minutes if `small.en` quality turns out to matter after living with
`base.en`. Revisit at CP-1b with real transcription-quality evidence rather than speculation.
