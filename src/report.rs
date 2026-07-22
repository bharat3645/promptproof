//! Public result types: [`Severity`], [`Category`], [`Verdict`], [`Finding`], [`Report`].
//!
//! All byte offsets in a [`Finding`] index into the **original** input passed to
//! [`crate::scan`], never into any normalized/decoded intermediate — so a caller
//! can slice the exact bytes a finding refers to.

/// How serious a single finding is. Ordered: `Info < Low < Medium < High < Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Contribution to the aggregate risk score.
    pub fn weight(self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 3,
            Severity::High => 6,
            Severity::Critical => 10,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// The kind of signal a finding represents. Stable strings; safe to match on in tooling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// Hidden/zero-width/format characters used as a covert channel.
    HiddenText,
    /// Bidirectional or directional override controls (Trojan-Source style).
    Bidi,
    /// Unicode Tag characters (U+E0000..U+E007F) smuggling ASCII into the text.
    AsciiSmuggling,
    /// Natural-language attempt to override prior instructions.
    InstructionOverride,
    /// Injected fake role / chat-template delimiters (`system:`, `<|im_start|>`, ...).
    RoleInjection,
    /// Directive telling the model to call a tool / run a command.
    ToolHijack,
    /// Data-exfiltration channel or lure (markdown-image beacon, "send ... to <url>").
    Exfiltration,
    /// A credential-shaped secret sitting inside untrusted content.
    Secret,
    /// An encoded blob (base64/hex/percent) that decodes to another signal.
    EncodedPayload,
    /// Trigger words obfuscated with mixed-script confusable characters.
    Confusable,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::HiddenText => "hidden-text",
            Category::Bidi => "bidi",
            Category::AsciiSmuggling => "ascii-smuggling",
            Category::InstructionOverride => "instruction-override",
            Category::RoleInjection => "role-injection",
            Category::ToolHijack => "tool-hijack",
            Category::Exfiltration => "exfiltration",
            Category::Secret => "secret",
            Category::EncodedPayload => "encoded-payload",
            Category::Confusable => "confusable",
        }
    }
}

/// Overall disposition of a piece of content. Ordered: `Ok < Suspicious < Dangerous`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Ok,
    Suspicious,
    Dangerous,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Ok => "ok",
            Verdict::Suspicious => "suspicious",
            Verdict::Dangerous => "dangerous",
        }
    }

    /// Process exit code the CLI returns for this verdict (`ok`=0, `suspicious`=1, `dangerous`=2).
    pub fn exit_code(self) -> i32 {
        match self {
            Verdict::Ok => 0,
            Verdict::Suspicious => 1,
            Verdict::Dangerous => 2,
        }
    }
}

/// A single detected signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Stable rule identifier, e.g. `"invisible.tag-chars"`.
    pub id: &'static str,
    pub category: Category,
    pub severity: Severity,
    /// Human-readable one-line explanation.
    pub message: String,
    /// Byte offset of the finding in the original input (inclusive).
    pub start: usize,
    /// Byte offset in the original input (exclusive).
    pub end: usize,
    /// A short, control-character-safe excerpt of what matched.
    pub snippet: String,
    /// Optional extra context (e.g. the ASCII decoded out of smuggled tag chars).
    pub detail: Option<String>,
}

/// Cheap descriptive counts about the scanned input.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub bytes: usize,
    pub chars: usize,
    /// Count of hidden/format/control characters encountered.
    pub invisible_chars: usize,
}

/// The result of scanning one piece of content.
#[derive(Debug, Clone)]
pub struct Report {
    pub verdict: Verdict,
    /// Sum of finding severity weights (with escalation rules applied to the verdict, not the score).
    pub score: u32,
    /// Findings, sorted by `start` offset then `id`.
    pub findings: Vec<Finding>,
    pub stats: Stats,
}

impl Report {
    pub fn is_ok(&self) -> bool {
        self.verdict == Verdict::Ok
    }
}
