# Tooling notes and known traps

Short, concrete lessons learned while working in this repo. Add to it when something
costs more than ten minutes to diagnose.

---

## Trap #1 — Large heredocs passed inline to the shell get truncated

### Symptom

```
/usr/bin/bash: -c: line 134: unexpected EOF while looking for matching `''
```

The line number is near the *end* of the command. The error names a quoting problem, which
is misleading — **the quoting is fine.** Hit twice while writing markdown docs
(2026-09-19), both times with a `cat > file <<'EOF' ... EOF` block of well over 100 lines.

### What it is NOT

These were tested directly and all pass, so stop suspecting the content:

| Suspected cause | Result |
|---|---|
| Apostrophes in the body (`Fable's`, `isn't`) | OK — a quoted delimiter (`<<'EOF'`) suppresses all expansion |
| Backticks (`` `code` ``) | OK |
| `$(...)` or `$VAR` | OK |
| Unicode arrows, em-dashes, box-drawing (`→ ─ │ ⚠ ≤ ×`) | OK |
| CRLF vs LF line endings | OK, both |
| Heredoc length — up to 800 lines / 42 KB **from a script file** | OK |

That last row is the tell. The same large heredoc **works from a file** and **fails
inline**. So the failure is in transporting a long multi-line string into the shell, not in
bash's parsing of it. The terminator never arrives, bash reaches EOF still looking for the
end of the quoted string, and reports it as a quote mismatch.

### The rule

**Never pipe a large document through the shell. Use the right tool for the job.**

| Task | Use |
|---|---|
| Create or overwrite a file of prose/markdown/code | The **Write** tool. Always. Any size. |
| Change a few lines in an existing file | The **Edit** tool |
| Programmatic edit (splice, regex, renumber sections) | Write the *content* to a scratch file with Write, then a **short** `python -c` that reads it |
| Genuinely need a heredoc | Keep it under ~30 lines and ASCII-ish |

### The pattern that works for programmatic edits

When a section must be spliced into an existing document, do not inline the section:

```bash
# 1. Write the section body with the Write tool -> scratchpad/section.md
# 2. Then a short, single-quote-free python that only does the splice:
python -c "
p='docs/PLAN.md'
sec=open('/path/to/scratchpad/section.md',encoding='utf-8').read()
s=open(p,encoding='utf-8').read()
a='## Anchor Heading'
assert a in s, 'anchor missing'
open(p,'w',encoding='utf-8').write(s.replace(a, sec+a, 1))
"
```

Two habits that make this safe:

- **`assert anchor in s`** before writing. A silent no-op replace is worse than a crash,
  because the file looks edited and is not.
- **`encoding='utf-8'` on every open**, both read and write. Windows Python defaults to the
  system codepage, which will mangle the arrows and em-dashes this project's docs use.

### Verify, do not assume

After any programmatic edit, confirm the structure rather than trusting the exit code:

```bash
grep -nE '^#{1,3} ' docs/PLAN.md    # headings still sane, numbering intact?
```

---

## Trap #2 — CMake 4.x versus whisper.cpp

whisper.cpp's `CMakeLists.txt` opens with `cmake_minimum_required(VERSION 3.5)`, which sits
exactly on the compatibility boundary CMake 4.x removed. winget only offers CMake 4.x.

Fix, in order of preference:

1. Pin CMake 3.31.x outside winget.
2. Pass `-DCMAKE_POLICY_VERSION_MINIMUM=3.5` through to the `whisper-rs-sys` build.

Resolve this in Phase 0. It is a guaranteed time sink if it surfaces mid-build.

---

## Trap #3 — The Silero VAD model is not in the whisper.cpp repo

`ggerganov/whisper.cpp` on HuggingFace contains **no** VAD files. The model lives in a
separate repo:

```
https://huggingface.co/ggml-org/whisper-vad/resolve/main/ggml-silero-v6.2.0.bin
```

It is under 1 MB, so vendor it with `include_bytes!` rather than downloading it at runtime.

---

## Trap #4 — Verify crate versions and APIs, never recall them

The two LLM-generated blueprints that seeded this project specified `whisper-rs = "0.11"`
(actual: 0.16), `cpal = "0.15"` (actual: 0.18), `enigo = "0.2"` (actual: 0.6), and a Silero
VAD API (`load_silero_vad()`, `forward_chunk()`, `prob[[0,0]]`) that **does not exist in any
published crate**. Following them would have produced code that could not compile.

Before depending on a crate or an API:

```bash
curl -s "https://crates.io/api/v1/crates/<name>" | python -c "import sys,json;print(json.load(sys.stdin)['crate']['max_stable_version'])"
curl -s "https://docs.rs/<crate>/<version>/<crate>/all.html" | grep -oE 'struct\.[A-Za-z]+\.html'
```

This also found the single biggest simplification in the project: whisper-rs 0.16 ships
Silero VAD built in (`WhisperVadContext`), which deleted an entire ONNX Runtime dependency
that both blueprints were designed around.

Check reviewers too — a review claimed `arboard` exposes `SetExtWindows` for excluding
content from Windows clipboard history. It does not; `arboard` 3.6.1 publishes only the
Linux extension traits. That one is real work via the `windows` crate.
