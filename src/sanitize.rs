//! Output sanitization — invariant I-4.
//!
//! Nothing reaches the injector without passing through [`sanitize`].
//!
//! The motivating failure (REDTEAM.md B-01): Whisper output, custom vocabulary, or any
//! future post-processing stage can introduce a newline. A newline injected into a
//! terminal is Enter, and Enter executes whatever is on the line. Dictating into a shell
//! must never be able to run a command.

use crate::policy;

/// Why text was modified. Recorded in the session log so silent mangling is visible.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SanitizeReport {
    pub stripped_control: usize,
    pub truncated_from: Option<usize>,
    pub collapsed_repeats: bool,
}

impl SanitizeReport {
    pub fn is_clean(&self) -> bool {
        self.stripped_control == 0 && self.truncated_from.is_none() && !self.collapsed_repeats
    }
}

/// Make text safe to inject.
///
/// - Strips every C0/C1 control character, including CR, LF and TAB. There is no
///   "safe" newline: we cannot know the target is not a shell.
/// - Collapses pathological repetition (Whisper's decoder can loop).
/// - Caps total length.
///
/// Returns the cleaned string plus a report of what was changed.
pub fn sanitize(input: &str) -> (String, SanitizeReport) {
    let mut report = SanitizeReport::default();

    // 1. Strip control characters. Newlines and tabs are deliberately included.
    let mut out = String::with_capacity(input.len());
    let mut last_was_space = false;
    for ch in input.chars() {
        let is_control = ch.is_control() || matches!(ch, '\u{0080}'..='\u{009F}');
        if is_control {
            report.stripped_control += 1;
            // A control character becomes a single space rather than vanishing, so
            // "line one\nline two" does not become "line oneline two".
            if !last_was_space && !out.is_empty() {
                out.push(' ');
                last_was_space = true;
            }
            continue;
        }
        last_was_space = ch == ' ';
        out.push(ch);
    }

    // 2. Collapse repeated n-grams.
    //
    // collapse_repeats reports whether it actually removed anything. Do NOT infer this by
    // comparing strings: the function also normalizes whitespace, so string inequality
    // reports a collapse on text that merely had double spaces, putting a false
    // collapsed_repeats into the session log that later feeds analytics.
    let (collapsed, did_collapse) = collapse_repeats(&out);
    report.collapsed_repeats = did_collapse;
    out = collapsed;

    // 3. Trim and cap.
    let trimmed = out.trim();
    if trimmed.len() != out.len() {
        out = trimmed.to_string();
    }
    let char_count = out.chars().count();
    if char_count > policy::MAX_INJECT_CHARS {
        report.truncated_from = Some(char_count);
        out = out.chars().take(policy::MAX_INJECT_CHARS).collect();
    }

    (out, report)
}

/// Collapse a word-level n-gram repeated more than `MAX_NGRAM_REPEATS` times.
///
/// Whisper occasionally loops, emitting "the the the the the ..." or a repeated phrase,
/// especially on near-silence. Pasting several hundred repetitions into a document is a
/// bad enough outcome to be worth guarding directly.
fn collapse_repeats(s: &str) -> (String, bool) {
    let words: Vec<&str> = s.split_whitespace().collect();
    if words.len() < policy::MAX_NGRAM_REPEATS * 2 {
        return (s.to_string(), false);
    }

    let mut out: Vec<&str> = Vec::with_capacity(words.len());
    let mut i = 0usize;
    let mut did_collapse = false;

    while i < words.len() {
        let mut collapsed_here = false;

        // Try n-gram lengths from 1 up to 5 words.
        for n in 1..=5usize {
            if i + n * 2 > words.len() {
                break;
            }
            let gram = &words[i..i + n];
            let mut repeats = 1usize;
            let mut j = i + n;
            while j + n <= words.len() && &words[j..j + n] == gram {
                repeats += 1;
                j += n;
            }
            if repeats > policy::MAX_NGRAM_REPEATS {
                // Keep MAX_NGRAM_REPEATS copies, drop the rest.
                for _ in 0..policy::MAX_NGRAM_REPEATS {
                    out.extend_from_slice(gram);
                }
                i = j;
                collapsed_here = true;
                did_collapse = true;
                break;
            }
        }

        if !collapsed_here {
            out.push(words[i]);
            i += 1;
        }
    }

    (out.join(" "), did_collapse)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newline_never_survives() {
        // B-01: the whole point. A newline in a terminal is Enter.
        for evil in [
            "hello\nrm -rf /",
            "hello\r\nformat c:",
            "hello\rworld",
            "hello\tworld",
            "hello\u{0085}world",
            "a\u{000B}b\u{000C}c",
        ] {
            let (out, _) = sanitize(evil);
            assert!(
                !out.contains('\n') && !out.contains('\r') && !out.contains('\t'),
                "control char survived in {out:?}"
            );
            assert!(!out.chars().any(|c| c.is_control()), "control char in {out:?}");
        }
    }

    #[test]
    fn control_chars_become_a_space_not_nothing() {
        let (out, r) = sanitize("line one\nline two");
        assert_eq!(out, "line one line two");
        assert_eq!(r.stripped_control, 1);
    }

    #[test]
    fn ordinary_text_is_untouched() {
        let input = "Hello, world. This is a normal sentence with punctuation!";
        let (out, r) = sanitize(input);
        assert_eq!(out, input);
        assert!(r.is_clean());
    }

    #[test]
    fn unicode_is_preserved() {
        let input = "caf\u{e9} na\u{ef}ve \u{2014} r\u{e9}sum\u{e9} \u{1F600}";
        let (out, _) = sanitize(input);
        assert_eq!(out, input);
    }

    #[test]
    fn length_is_capped() {
        // Must be NON-repeating, or the n-gram collapser shortens it below the cap and
        // truncation never fires. (That is exactly what the first version of this test
        // got wrong.)
        let long: String = (0..3000)
            .map(|i| format!("w{i} "))
            .collect::<Vec<_>>()
            .concat();
        let (out, r) = sanitize(&long);
        assert!(out.chars().count() <= policy::MAX_INJECT_CHARS);
        assert!(r.truncated_from.is_some(), "expected truncation, got {r:?}");
    }

    #[test]
    fn collapse_runs_before_truncation() {
        // Documents the ordering the test above tripped over: a pathological Whisper loop
        // is collapsed to something short rather than truncated at 2000 chars of garbage.
        let looped = "word ".repeat(2000);
        let (out, r) = sanitize(&looped);
        assert!(r.collapsed_repeats);
        assert!(out.chars().count() < 50, "got {} chars", out.chars().count());
    }

    #[test]
    fn single_word_loop_is_collapsed() {
        let (out, r) = sanitize("the the the the the the the the end");
        assert!(r.collapsed_repeats);
        assert_eq!(out.matches("the").count(), policy::MAX_NGRAM_REPEATS);
    }

    #[test]
    fn phrase_loop_is_collapsed() {
        let (out, r) = sanitize("thanks for watching thanks for watching thanks for watching thanks for watching");
        assert!(r.collapsed_repeats);
        assert_eq!(out.matches("thanks").count(), policy::MAX_NGRAM_REPEATS);
    }

    #[test]
    fn legitimate_short_repetition_survives() {
        // "very very very" is real English and must not be mangled.
        let (out, r) = sanitize("that is very very very good");
        assert_eq!(out, "that is very very very good");
        assert!(!r.collapsed_repeats);
    }

    #[test]
    fn whitespace_normalization_is_not_reported_as_a_collapse() {
        // Regression: comparing strings to detect a collapse produced a false positive on
        // any text with extra spaces, which would have polluted the session log.
        let (out, r) = sanitize("  Hello from WhisperRust.
rm -rf /  ");
        assert_eq!(out, "Hello from WhisperRust. rm -rf /");
        assert!(!r.collapsed_repeats, "false positive: {r:?}");
        assert_eq!(r.stripped_control, 1);
    }

    #[test]
    fn empty_and_whitespace() {
        assert_eq!(sanitize("").0, "");
        assert_eq!(sanitize("   \n\t  ").0, "");
    }
}
