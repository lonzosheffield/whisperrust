//! `whisperrust stats` — reads the session log and answers the questions that matter.
//!
//! Every number here is *derived* from records already written. Nothing extra is
//! instrumented, which is the whole reason the log schema was made complete on day one
//! (seam S-1): a field that was never written cannot be back-filled, but a metric can
//! always be computed later.
//!
//! # The three latency numbers, and why they are different
//!
//! * **Speaking WPM** — words ÷ audio duration. Your natural speaking rate; typically
//!   120–160. Says nothing about the tool.
//! * **Effective WPM** — words ÷ (PTT release → text delivered). The honest throughput,
//!   latency included. This is the number the tool is actually responsible for.
//! * **Time saved** — effective WPM measured against a typing baseline.
//!
//! Quoting speaking WPM as though it were throughput would flatter the tool by exactly the
//! amount of latency it adds, which is the one thing the measurement exists to expose.

use std::collections::BTreeMap;

use serde::Deserialize;

/// Typing baseline for the time-saved calculation. Average sustained typing is ~40 wpm;
/// a fast touch typist is ~70. 65 is deliberately near the high end so the comparison
/// understates the benefit rather than overselling it.
const DEFAULT_TYPING_WPM: f64 = 65.0;

#[derive(Debug, Deserialize, Default)]
struct Rec {
    #[serde(default)]
    at: String,
    #[serde(default)]
    hold_ms: u64,
    #[serde(default)]
    trimmed_audio_secs: f32,
    #[serde(default)]
    raw_audio_secs: f32,
    #[serde(default)]
    infer_ms: f64,
    #[serde(default)]
    resample_ms: f64,
    #[serde(default)]
    vad_ms: f64,
    #[serde(default)]
    word_count: usize,
    #[serde(default)]
    verdict: String,
    #[serde(default)]
    decision: String,
    #[serde(default)]
    decision_reason: Option<String>,
    #[serde(default)]
    inject_outcome: Option<String>,
    #[serde(default)]
    target_exe: String,
    #[serde(default)]
    on_battery: bool,
    #[serde(default)]
    release_to_delivered_ms: f64,
    #[serde(default)]
    model: String,
    #[serde(default)]
    stream_errors: u64,
    #[serde(default)]
    ring_overruns: u64,
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

pub fn run(typing_wpm: f64) -> i32 {
    let dir = std::env::var("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join("WhisperRust")
        .join("sessions");

    let mut files: Vec<_> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().map(|x| x == "jsonl").unwrap_or(false))
            .collect(),
        Err(_) => {
            println!("No session logs found at {}", dir.display());
            println!("Run the daemon and dictate something first.");
            return 1;
        }
    };
    files.sort();

    let mut recs: Vec<Rec> = Vec::new();
    let mut malformed = 0usize;
    for f in &files {
        let Ok(text) = std::fs::read_to_string(f) else { continue };
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Rec>(line) {
                Ok(r) => recs.push(r),
                // A torn final line is expected with append-only JSONL after a crash.
                Err(_) => malformed += 1,
            }
        }
    }

    if recs.is_empty() {
        println!("No utterances recorded yet ({} files scanned).", files.len());
        return 1;
    }

    // ---- partition by outcome ----
    let injected: Vec<&Rec> = recs
        .iter()
        .filter(|r| r.inject_outcome.as_deref() == Some("injected"))
        .collect();
    let clipboard: Vec<&Rec> = recs.iter().filter(|r| r.decision == "clipboard_only").collect();
    let dropped: Vec<&Rec> = recs.iter().filter(|r| r.decision == "drop").collect();
    let filtered: Vec<&Rec> = recs
        .iter()
        .filter(|r| !r.verdict.is_empty() && r.verdict != "accepted" && r.verdict != "canned")
        .collect();

    let words: usize = injected.iter().map(|r| r.word_count).sum();
    let speak_secs: f64 = injected.iter().map(|r| r.trimmed_audio_secs as f64).sum();
    let e2e_secs: f64 = injected
        .iter()
        .map(|r| r.trimmed_audio_secs as f64 + r.release_to_delivered_ms / 1000.0)
        .sum();

    let speaking_wpm = if speak_secs > 0.0 { words as f64 / (speak_secs / 60.0) } else { 0.0 };
    let effective_wpm = if e2e_secs > 0.0 { words as f64 / (e2e_secs / 60.0) } else { 0.0 };

    let typing_mins = words as f64 / typing_wpm;
    let actual_mins = e2e_secs / 60.0;
    let saved_mins = typing_mins - actual_mins;

    let mut lat: Vec<f64> = injected.iter().map(|r| r.release_to_delivered_ms).collect();
    lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mut inf: Vec<f64> = recs.iter().filter(|r| r.infer_ms > 0.0).map(|r| r.infer_ms).collect();
    inf.sort_by(|a, b| a.partial_cmp(b).unwrap());

    println!("=============== WhisperRust stats ===============");
    println!("log files          : {}", files.len());
    println!("utterances         : {}", recs.len());
    if malformed > 0 {
        println!("malformed lines    : {malformed} (expected after a crash; append-only JSONL)");
    }
    println!();
    println!("--- outcomes ---");
    println!("  injected         : {}", injected.len());
    println!("  clipboard-only   : {}", clipboard.len());
    println!("  dropped          : {}", dropped.len());
    println!("  filtered as noise: {}", filtered.len());
    println!();

    if injected.is_empty() {
        println!("Nothing was injected yet, so throughput cannot be computed.");
    } else {
        println!("--- throughput (injected utterances only) ---");
        println!("  words dictated   : {words}");
        println!("  speaking rate    : {speaking_wpm:.0} wpm   (your natural rate)");
        println!("  EFFECTIVE rate   : {effective_wpm:.0} wpm   (includes latency - the honest number)");
        println!("  typing baseline  : {typing_wpm:.0} wpm");
        if saved_mins >= 0.0 {
            println!("  time saved       : {saved_mins:.1} min vs typing");
        } else {
            println!("  time LOST        : {:.1} min vs typing - latency exceeds the benefit", -saved_mins);
        }
        println!();
        println!("--- latency, release to text (CP-3 criterion) ---");
        println!("  p50              : {:.0} ms", percentile(&lat, 0.50));
        println!("  p95              : {:.0} ms   (criterion: <= Phase 1b figure + 300)", percentile(&lat, 0.95));
        println!("  max              : {:.0} ms", percentile(&lat, 1.0));
    }

    if !inf.is_empty() {
        println!();
        println!("--- inference ---");
        println!("  p50              : {:.0} ms", percentile(&inf, 0.50));
        println!("  p95              : {:.0} ms", percentile(&inf, 0.95));
    }

    // ---- audio health: the thing a summary omitted once before ----
    let worst_errors = recs.iter().map(|r| r.stream_errors).max().unwrap_or(0);
    let worst_overruns = recs.iter().map(|r| r.ring_overruns).max().unwrap_or(0);
    println!();
    println!("--- audio health ---");
    println!("  OS stream errors : {worst_errors}   (non-zero = WASAPI dropped audio)");
    println!("  ring overruns    : {worst_overruns}");

    // ---- per-app ----
    let mut by_app: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for r in &recs {
        if r.target_exe.is_empty() {
            continue;
        }
        let e = by_app.entry(r.target_exe.as_str()).or_insert((0, 0));
        e.0 += 1;
        if r.inject_outcome.as_deref() == Some("injected") {
            e.1 += 1;
        }
    }
    if !by_app.is_empty() {
        println!();
        println!("--- by application ---");
        let mut rows: Vec<_> = by_app.into_iter().collect();
        rows.sort_by_key(|(_, (n, _))| std::cmp::Reverse(*n));
        for (exe, (total, ok)) in rows.iter().take(12) {
            println!("  {exe:<28} {ok:>4}/{total:<4} injected");
        }
    }

    // ---- why text did not land ----
    let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
    for r in recs.iter().filter(|r| r.decision != "inject") {
        if let Some(why) = &r.decision_reason {
            *reasons.entry(why.clone()).or_default() += 1;
        }
    }
    for r in &filtered {
        *reasons.entry(format!("filter:{}", r.verdict)).or_default() += 1;
    }
    if !reasons.is_empty() {
        println!();
        println!("--- why text did not land ---");
        let mut rows: Vec<_> = reasons.into_iter().collect();
        rows.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        for (why, n) in rows {
            println!("  {why:<28} {n:>4}");
        }
    }

    let on_batt = recs.iter().filter(|r| r.on_battery).count();
    if on_batt > 0 && on_batt < recs.len() {
        println!();
        println!("NOTE: {on_batt} of {} utterances were on battery. Latency is not", recs.len());
        println!("      comparable across power states on this CPU - split before concluding.");
    }

    let models: std::collections::BTreeSet<&str> =
        recs.iter().map(|r| r.model.as_str()).filter(|m| !m.is_empty()).collect();
    if models.len() > 1 {
        println!();
        println!("NOTE: {} different models appear in this log. Latency figures mix them.", models.len());
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_handles_edges() {
        let v = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert_eq!(percentile(&v, 0.0), 1.0);
        assert_eq!(percentile(&v, 1.0), 5.0);
        assert_eq!(percentile(&v, 0.5), 3.0);
        assert_eq!(percentile(&[], 0.5), 0.0);
    }

    #[test]
    fn effective_wpm_is_lower_than_speaking_wpm() {
        // The invariant that keeps the number honest: effective throughput includes
        // latency, so it can never exceed the raw speaking rate. If it did, we would be
        // quoting the speaking rate and calling it throughput.
        let words = 20.0f64;
        let speak_secs = 6.0f64;
        let latency_secs = 1.2f64;
        let speaking = words / (speak_secs / 60.0);
        let effective = words / ((speak_secs + latency_secs) / 60.0);
        assert!(effective < speaking);
        assert!((speaking - 200.0).abs() < 1.0);
    }

    #[test]
    fn malformed_lines_do_not_abort_parsing() {
        // Append-only JSONL after a crash leaves a torn final line. One bad record must
        // not cost the user every other record in the file.
        let good = r#"{"utterance_id":1,"word_count":5}"#;
        assert!(serde_json::from_str::<Rec>(good).is_ok());
        assert!(serde_json::from_str::<Rec>(r#"{"utterance_id":1,"word_c"#).is_err());
    }

    #[test]
    fn missing_fields_default_rather_than_failing() {
        // Older records must stay readable as the schema grows.
        let minimal = r#"{"utterance_id":9}"#;
        let r: Rec = serde_json::from_str(minimal).unwrap();
        assert_eq!(r.word_count, 0);
        assert!(r.target_exe.is_empty());
    }
}
