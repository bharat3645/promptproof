//! Corpus-driven precision/recall test.
//!
//! Every file under `corpus/malicious/` must be flagged `dangerous`; no file
//! under `corpus/benign/` may be flagged `dangerous`; and most benign content
//! must come back fully clean. Run with `cargo test -- --nocapture` to see the
//! confusion summary.

use std::fs;
use std::path::{Path, PathBuf};

use promptproof::{scan, Verdict};

fn corpus_files(dir: &str) -> Vec<PathBuf> {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(dir);
    let mut v: Vec<PathBuf> = fs::read_dir(&base)
        .unwrap_or_else(|e| panic!("read {}: {e}", base.display()))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    v.sort();
    assert!(!v.is_empty(), "no corpus files in {}", base.display());
    v
}

fn verdict_of(path: &Path) -> Verdict {
    let bytes = fs::read(path).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    scan(&text).verdict
}

fn name(p: &Path) -> String {
    p.file_name().unwrap().to_string_lossy().into_owned()
}

#[test]
fn every_malicious_sample_is_dangerous() {
    let misses: Vec<String> = corpus_files("corpus/malicious")
        .iter()
        .filter(|p| verdict_of(p) != Verdict::Dangerous)
        .map(|p| format!("{} → {:?}", name(p), verdict_of(p)))
        .collect();
    assert!(
        misses.is_empty(),
        "malicious samples not flagged dangerous: {misses:?}"
    );
}

#[test]
fn no_benign_sample_is_dangerous() {
    let fps: Vec<String> = corpus_files("corpus/benign")
        .iter()
        .filter(|p| verdict_of(p) == Verdict::Dangerous)
        .map(|p| name(p))
        .collect();
    assert!(
        fps.is_empty(),
        "benign samples wrongly flagged dangerous (false positives): {fps:?}"
    );
}

#[test]
fn benign_clean_rate_is_high() {
    let files = corpus_files("corpus/benign");
    let total = files.len();
    let clean = files
        .iter()
        .filter(|p| verdict_of(p) == Verdict::Ok)
        .count();
    // At least 70% of benign content must be fully clean; the remainder may be
    // 'suspicious' (e.g. a security post quoting an injection phrase, or docs
    // that say "use the X tool") but never dangerous.
    assert!(
        clean * 10 >= total * 7,
        "benign clean rate too low: {clean}/{total}"
    );
}

#[test]
fn confusion_summary() {
    let mal = corpus_files("corpus/malicious");
    let ben = corpus_files("corpus/benign");

    let mal_dangerous = mal
        .iter()
        .filter(|p| verdict_of(p) == Verdict::Dangerous)
        .count();
    let ben_clean = ben.iter().filter(|p| verdict_of(p) == Verdict::Ok).count();
    let ben_suspicious = ben
        .iter()
        .filter(|p| verdict_of(p) == Verdict::Suspicious)
        .count();
    let ben_dangerous = ben.len() - ben_clean - ben_suspicious;

    eprintln!("\n== promptproof corpus summary ==");
    eprintln!(
        "malicious: {}/{} dangerous (recall {:.0}%)",
        mal_dangerous,
        mal.len(),
        100.0 * mal_dangerous as f64 / mal.len() as f64
    );
    eprintln!(
        "benign:    {} clean, {} suspicious, {} dangerous (of {})",
        ben_clean,
        ben_suspicious,
        ben_dangerous,
        ben.len()
    );
    eprintln!(
        "benign specificity (not-dangerous): {:.0}%\n",
        100.0 * (ben.len() - ben_dangerous) as f64 / ben.len() as f64
    );

    // Sanity floor so the summary can't silently rot.
    assert_eq!(mal_dangerous, mal.len());
    assert_eq!(ben_dangerous, 0);
}
