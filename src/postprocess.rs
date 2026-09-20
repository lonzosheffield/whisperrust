//! Turning a raw `Transcript` into text worth injecting.
//!
//! Two jobs, in order: decide whether this is real speech at all, then decide how it joins
//! to what came before.
//!
//! # The hallucination problem
//!
//! Whisper does not return "I heard nothing." Fed near-silence, room tone, a cough or a
//! keyboard clack, it confidently produces fluent text — overwhelmingly drawn from the
//! subtitle corpora it was trained on. "Thank you.", "Thanks for watching!", "[BLANK_AUDIO]",
//! ". . ." and similar are not rare edge cases; they are what the model does when asked to
//! transcribe nothing.
//!
//! For a subtitle tool that is a cosmetic flaw. For a tool that types into whatever window
//! you are looking at, it means a stray keypress can paste "Thanks for watching!" into a
//! customer email. So this filter is not a nicety, and it is layered deliberately:
//!
//! 1. **Skip inference entirely** when VAD finds no speech (`backend::trim_to_speech`).
//!    The cheapest garbage is the kind never generated.
//! 2. **`no_speech_prob`** from the model itself.
//! 3. **A denylist** of known artifacts, matched on normalized text.
//! 4. **Duration sanity** — a 200 ms capture cannot contain a 12-word sentence.
//!
//! Each layer catches what the others miss; none is sufficient alone.

use crate::backend::Transcript;

/// Above this, the model itself believes the audio was not speech.
///
/// 0.6 rather than 0.5: the earlier layers (VAD skip, denylist) already remove the clear
/// cases, so this one should only catch strong signals. Set too low it eats real quiet
/// speech, which is a worse failure than an occasional artifact the denylist will catch.
const NO_SPEECH_THRESHOLD: f32 = 0.6;

/// Phrases Whisper emits for non-speech, normalized to lowercase with punctuation removed.
///
/// These are matched against the WHOLE transcript only. A partial match would be wrong:
/// "thank you" is a perfectly normal thing to dictate in an email, and refusing to type it
/// would be a worse bug than the one being fixed.
/// Phrases Whisper emits for non-speech. Matched on the WHOLE normalized transcript only.
///
/// Split into two tiers deliberately. The first tier is never something a person dictates
/// on purpose, so it is rejected outright. The second tier - "thank you", "okay", "yeah" -
/// are things people genuinely say as complete replies in chat, so rejecting them on sight
/// silently eats real dictation. Those are only rejected when the MODEL ALSO doubts the
/// audio was speech.
///
/// Getting this wrong in the strict direction is worse than the bug: the user says
/// "Thank you." into Slack, nothing appears, and nothing explains why.
const HALLUCINATIONS_ALWAYS: &[&str] = &[
    "",
    "blank audio",
    "blank",
    "inaudible",
    "no audio",
    "silence",
    "music",
    "applause",
    "subtitles by the amara org community",
    "transcription by castingwords com",
    "subs by www zeoranger com",
    "please subscribe",
    "like and subscribe",
    "thanks for watching",
    "thank you for watching",
];

/// Plausible as real speech. Rejected only if `no_speech_prob` also exceeds
/// [`AMBIGUOUS_NO_SPEECH`].
const HALLUCINATIONS_IF_UNSURE: &[&str] = &[
    "you",
    "thank you",
    "thanks",
    "okay",
    "ok",
    "yeah",
    "yes",
    "no",
    "so",
    "uh",
    "um",
    "hmm",
    "the",
    "i",
    "bye",
    "bye bye",
];

/// Lower bar for the ambiguous tier: these phrases are real words, so we need the model to
/// corroborate that the audio was not speech before discarding them.
const AMBIGUOUS_NO_SPEECH: f32 = 0.25;

/// Words per second above which a transcript is implausible for the audio length.
///
/// Fast speech is ~4 words/sec. 6 leaves headroom while still catching the case where the
/// model invents a sentence for a fraction of a second of audio.
const MAX_WORDS_PER_SEC: f32 = 6.0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Real speech; inject it.
    Accept,
    /// Model output, but not speech. Discard silently.
    Reject(RejectReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    Empty,
    NoSpeechProbability,
    KnownHallucination,
    ImplausibleRate,
    TooShort,
}

impl RejectReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            RejectReason::Empty => "empty",
            RejectReason::NoSpeechProbability => "no_speech_prob",
            RejectReason::KnownHallucination => "known_hallucination",
            RejectReason::ImplausibleRate => "implausible_word_rate",
            RejectReason::TooShort => "audio_too_short",
        }
    }
}

/// Lowercase, reduce punctuation to word boundaries, collapse whitespace.
///
/// The subtlety a first version got wrong: silently *dropping* punctuation turns
/// `[BLANK_AUDIO]` into `blankaudio`, which then fails to match the denylist entry
/// `blank audio` - so the single most common Whisper artifact sailed straight through the
/// filter and would have been typed. Punctuation must act as a SEPARATOR, not vanish.
///
/// Apostrophes are the deliberate exception and are dropped without a space, because
/// `don't` must normalize to `dont` rather than `don t`.
fn normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_space = true;
    for ch in s.chars() {
        if ch.is_alphanumeric() {
            for c in ch.to_lowercase() {
                out.push(c);
            }
            last_space = false;
        } else if ch == '\'' || ch == '\u{2019}' {
            // join: don't -> dont
        } else if !last_space {
            // Any other punctuation or whitespace is a word boundary.
            out.push(' ');
            last_space = true;
        }
    }
    out.trim().to_string()
}

pub fn judge(t: &Transcript) -> Verdict {
    let norm = normalize(&t.text);

    if norm.is_empty() {
        return Verdict::Reject(RejectReason::Empty);
    }

    // Tier 1: never a deliberate dictation.
    if HALLUCINATIONS_ALWAYS.contains(&norm.as_str()) {
        return Verdict::Reject(RejectReason::KnownHallucination);
    }

    // Tier 2: real words. Discard only with corroboration from the model.
    if HALLUCINATIONS_IF_UNSURE.contains(&norm.as_str()) && t.max_no_speech > AMBIGUOUS_NO_SPEECH {
        return Verdict::Reject(RejectReason::KnownHallucination);
    }

    if t.max_no_speech > NO_SPEECH_THRESHOLD {
        return Verdict::Reject(RejectReason::NoSpeechProbability);
    }

    // Below ~300ms there is not enough audio for a word, whatever the model says.
    if t.audio_secs < 0.3 {
        return Verdict::Reject(RejectReason::TooShort);
    }

    let words = norm.split_whitespace().count() as f32;
    if t.audio_secs > 0.0 && words / t.audio_secs > MAX_WORDS_PER_SEC {
        return Verdict::Reject(RejectReason::ImplausibleRate);
    }

    Verdict::Accept
}

/// How the new text should attach to the previous injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Join {
    /// First utterance, or too long since the last one.
    Fresh,
    /// Previous ended with sentence punctuation: new sentence, keep capitalization.
    NewSentence,
    /// Previous ended mid-sentence: continue it, lowercase the first word.
    Continuation,
}

/// Seconds after which two utterances are unrelated.
const JOIN_WINDOW_SECS: u64 = 10;

pub fn decide_join(prev: Option<(&str, std::time::Instant)>) -> Join {
    let Some((prev_text, at)) = prev else {
        return Join::Fresh;
    };
    if at.elapsed().as_secs() > JOIN_WINDOW_SECS {
        return Join::Fresh;
    }
    let trimmed = prev_text.trim_end();
    match trimmed.chars().last() {
        Some('.') | Some('!') | Some('?') | Some(':') | Some(';') => Join::NewSentence,
        Some(_) => Join::Continuation,
        None => Join::Fresh,
    }
}

/// Apply the join decision, producing the exact string to inject.
pub fn apply_join(text: &str, join: Join) -> String {
    let t = text.trim();
    if t.is_empty() {
        return String::new();
    }
    match join {
        Join::Fresh => t.to_string(),
        Join::NewSentence => format!(" {t}"),
        Join::Continuation => {
            let mut chars = t.chars();
            let Some(first) = chars.next() else {
                return String::new();
            };
            // "I" stays capitalized; so does anything that looks like a proper noun
            // already embedded mid-word (e.g. "iPhone"). Lowercasing those would be more
            // annoying than the sentence-case problem it fixes.
            let rest: String = chars.collect();
            let keep_case = first == 'I'
                && (rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\''));
            if keep_case {
                format!(" {t}")
            } else {
                let lowered: String = first.to_lowercase().collect();
                format!(" {lowered}{rest}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Segment;
    use std::time::{Duration, Instant};

    fn tr(text: &str, no_speech: f32, secs: f32) -> Transcript {
        Transcript {
            text: text.into(),
            segments: vec![Segment {
                text: text.into(),
                no_speech_prob: no_speech,
                start_cs: 0,
                end_cs: 100,
            }],
            max_no_speech: no_speech,
            inference: Duration::from_millis(1),
            audio_secs: secs,
        }
    }

    #[test]
    fn real_speech_is_accepted() {
        assert_eq!(
            judge(&tr("Let us meet on Wednesday afternoon.", 0.02, 3.0)),
            Verdict::Accept
        );
    }

    #[test]
    fn unambiguous_hallucinations_are_always_rejected() {
        for s in [
            "Thanks for watching!",
            "Thanks for watching",
            "[BLANK_AUDIO]",
            " . . . ",
            "Subtitles by the Amara.org community",
            "[Applause]",
            "(music)",
        ] {
            assert!(
                matches!(judge(&tr(s, 0.05, 2.0)), Verdict::Reject(_)),
                "should have rejected {s:?} even with low no_speech"
            );
        }
    }

    #[test]
    fn real_one_word_replies_survive_when_the_model_is_confident() {
        // Regression: these were rejected outright, so saying "Thank you." into Slack
        // produced nothing at all and no explanation. They are ordinary dictation.
        for s in ["Thank you.", "Okay.", "Yeah.", "Bye.", "Thanks."] {
            assert_eq!(
                judge(&tr(s, 0.02, 1.2)),
                Verdict::Accept,
                "{s:?} is a legitimate reply and must be typed"
            );
        }
    }

    #[test]
    fn ambiguous_phrases_are_rejected_when_the_model_doubts_the_audio() {
        for s in ["Thank you.", "Okay.", "you"] {
            assert!(
                matches!(judge(&tr(s, 0.45, 1.2)), Verdict::Reject(_)),
                "{s:?} with high no_speech should be filtered"
            );
        }
    }

    #[test]
    fn thank_you_inside_a_real_sentence_is_kept() {
        // Whole-transcript matching, not substring - substring would eat these.
        // THE false-positive that would make this filter worse than the bug.
        // Substring matching would eat this; whole-transcript matching must not.
        assert_eq!(
            judge(&tr("Thank you for sending the contract over.", 0.02, 3.0)),
            Verdict::Accept
        );
        assert_eq!(
            judge(&tr("I wanted to say thank you.", 0.02, 2.5)),
            Verdict::Accept
        );
    }

    #[test]
    fn high_no_speech_probability_is_rejected() {
        match judge(&tr("Some plausible words here.", 0.95, 3.0)) {
            Verdict::Reject(RejectReason::NoSpeechProbability) => {}
            other => panic!("expected no-speech rejection, got {other:?}"),
        }
    }

    #[test]
    fn a_sentence_from_a_fraction_of_a_second_is_rejected() {
        // Twelve words cannot fit in 200ms of audio, whatever the model claims.
        match judge(&tr("one two three four five six seven eight nine ten", 0.1, 0.2)) {
            Verdict::Reject(_) => {}
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn implausible_word_rate_is_rejected() {
        let words = "word ".repeat(40);
        match judge(&tr(&words, 0.1, 2.0)) {
            Verdict::Reject(RejectReason::ImplausibleRate) => {}
            other => panic!("expected rate rejection, got {other:?}"),
        }
    }

    #[test]
    fn normal_speaking_rate_is_accepted() {
        // ~3 words/sec is ordinary.
        assert_eq!(
            judge(&tr("this is a perfectly normal sentence to dictate", 0.02, 3.0)),
            Verdict::Accept
        );
    }

    #[test]
    fn join_is_fresh_with_no_history() {
        assert_eq!(decide_join(None), Join::Fresh);
        assert_eq!(apply_join("Hello there.", Join::Fresh), "Hello there.");
    }

    #[test]
    fn join_after_punctuation_starts_a_new_sentence() {
        let j = decide_join(Some(("First thought.", Instant::now())));
        assert_eq!(j, Join::NewSentence);
        assert_eq!(apply_join("Second thought.", j), " Second thought.");
    }

    #[test]
    fn join_mid_sentence_continues_lowercase() {
        let j = decide_join(Some(("the meeting is on", Instant::now())));
        assert_eq!(j, Join::Continuation);
        assert_eq!(apply_join("Wednesday afternoon.", j), " wednesday afternoon.");
    }

    #[test]
    fn continuation_preserves_capital_i() {
        let j = Join::Continuation;
        assert_eq!(apply_join("I think so.", j), " I think so.");
        assert_eq!(apply_join("I'm not sure.", j), " I'm not sure.");
    }

    #[test]
    fn old_utterances_do_not_join() {
        let long_ago = Instant::now() - Duration::from_secs(60);
        assert_eq!(decide_join(Some(("something", long_ago))), Join::Fresh);
    }

    #[test]
    fn normalize_treats_punctuation_as_a_word_boundary() {
        // Regression: dropping punctuation instead of separating on it turned
        // "[BLANK_AUDIO]" into "blankaudio", so the most common Whisper artifact did not
        // match the denylist and would have been injected.
        assert_eq!(normalize("  Thank  YOU!! "), "thank you");
        assert_eq!(normalize("[BLANK_AUDIO]"), "blank audio");
        assert_eq!(normalize("[ Silence ]"), "silence");
        assert_eq!(normalize("Amara.org"), "amara org");
        assert_eq!(normalize("..."), "");
        // Apostrophes still join.
        assert_eq!(normalize("don't"), "dont");
        assert_eq!(normalize("I\u{2019}m"), "im");
    }
}
