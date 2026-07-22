//! Aggregate findings into a score and a verdict, under a tunable [`Policy`].

use crate::report::{Finding, Severity, Verdict};

/// Tunable thresholds and toggles for a scan.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// Minimum score to be at least `suspicious`.
    pub suspicious_at: u32,
    /// Minimum score to be `dangerous`.
    pub dangerous_at: u32,
    /// Whether to decode and rescan base64/hex/percent blobs.
    pub decode_encoded: bool,
    /// Hard cap on findings retained in the report (defensive, for adversarial input).
    pub max_findings: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            suspicious_at: 1,
            dangerous_at: 6,
            decode_encoded: true,
            max_findings: 1000,
        }
    }
}

/// Sum of finding severity weights.
pub fn score(findings: &[Finding]) -> u32 {
    findings.iter().map(|f| f.severity.weight()).sum()
}

/// Decide the verdict. Any `Critical` finding forces `Dangerous` regardless of
/// thresholds (a hidden ASCII payload is dangerous even alone); otherwise the
/// score is compared against the policy thresholds.
pub fn verdict(findings: &[Finding], score: u32, policy: &Policy) -> Verdict {
    if findings.iter().any(|f| f.severity == Severity::Critical) {
        return Verdict::Dangerous;
    }
    if score >= policy.dangerous_at {
        Verdict::Dangerous
    } else if score >= policy.suspicious_at {
        Verdict::Suspicious
    } else {
        Verdict::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Category;

    fn finding(sev: Severity) -> Finding {
        Finding {
            id: "t",
            category: Category::HiddenText,
            severity: sev,
            message: String::new(),
            start: 0,
            end: 0,
            snippet: String::new(),
            detail: None,
        }
    }

    #[test]
    fn empty_is_ok() {
        let p = Policy::default();
        assert_eq!(verdict(&[], 0, &p), Verdict::Ok);
    }

    #[test]
    fn one_low_is_suspicious() {
        let p = Policy::default();
        let f = vec![finding(Severity::Low)];
        let s = score(&f);
        assert_eq!(s, 1);
        assert_eq!(verdict(&f, s, &p), Verdict::Suspicious);
    }

    #[test]
    fn one_high_is_dangerous() {
        let p = Policy::default();
        let f = vec![finding(Severity::High)];
        let s = score(&f);
        assert_eq!(verdict(&f, s, &p), Verdict::Dangerous);
    }

    #[test]
    fn critical_forces_dangerous_even_with_high_threshold() {
        let p = Policy {
            dangerous_at: 999,
            ..Policy::default()
        };
        let f = vec![finding(Severity::Critical)];
        let s = score(&f);
        assert_eq!(verdict(&f, s, &p), Verdict::Dangerous);
    }
}
