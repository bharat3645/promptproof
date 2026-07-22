//! The detectors. Each produces zero or more [`Finding`]s with byte offsets into
//! the text it was given (the original input at the top level; a decoded blob
//! when called from [`crate::encoded`]).
//!
//! Layers:
//!   * `detect_invisible` — hidden/format/bidi/tag characters, over raw text.
//!   * `detect_text_over` — natural-language triggers, chat-template role
//!     delimiters, tool-hijack directives, exfiltration lures, planted secrets,
//!     and confusable-obfuscated triggers, over the normalized view.
//!   * encoded payloads are handled in [`crate::encoded`] and merged in by
//!     [`detect_all`].

use crate::matcher::{find_sub, match_seq, tokenize, Tok};
use crate::normalize::{classify_invisible, InvisibleKind, Normalized};
use crate::report::{Category, Finding, Severity, Stats};
use crate::util::{safe_excerpt, visible_string};

/// One natural-language / directive pattern over word tokens.
struct Pat {
    id: &'static str,
    cat: Category,
    sev: Severity,
    msg: &'static str,
    seq: &'static [Tok],
    gap: usize,
}

// Natural-language triggers, matched over word tokens (word boundaries + a
// token-gap budget). Ordered elements must appear in order.
static PATTERNS: &[Pat] = &[
    Pat {
        id: "instruction.ignore-previous",
        cat: Category::InstructionOverride,
        sev: Severity::Medium,
        msg: "imperative to ignore/disregard prior instructions or rules",
        seq: &[
            Tok::Eq(&[
                "ignore",
                "disregard",
                "forget",
                "neglect",
                "overlook",
                "skip",
            ]),
            Tok::Prefix(&[
                "instruct",
                "prompt",
                "direction",
                "rule",
                "context",
                "guideline",
                "guardrail",
            ]),
        ],
        gap: 4,
    },
    Pat {
        id: "instruction.override",
        cat: Category::InstructionOverride,
        sev: Severity::Medium,
        msg: "imperative to override/replace the system instructions",
        seq: &[
            Tok::Eq(&["override", "overwrite", "replace", "supersede", "bypass"]),
            Tok::Prefix(&[
                "instruct",
                "prompt",
                "system",
                "guardrail",
                "restriction",
                "safety",
                "polic",
            ]),
        ],
        gap: 4,
    },
    Pat {
        id: "instruction.secrecy",
        cat: Category::InstructionOverride,
        sev: Severity::Medium,
        msg: "directive to hide an action from the user",
        seq: &[
            Tok::Eq(&["not", "never", "don", "dont", "without"]),
            Tok::Eq(&[
                "tell", "telling", "reveal", "inform", "mention", "disclose", "say", "show",
            ]),
            Tok::Eq(&["user", "anyone", "human", "them", "this", "operator"]),
        ],
        gap: 3,
    },
    Pat {
        id: "instruction.you-are-now",
        cat: Category::InstructionOverride,
        sev: Severity::Medium,
        msg: "attempt to redefine the assistant's role",
        seq: &[Tok::Eq(&["you"]), Tok::Eq(&["are"]), Tok::Eq(&["now"])],
        gap: 1,
    },
    Pat {
        id: "instruction.new-instructions",
        cat: Category::InstructionOverride,
        sev: Severity::Medium,
        msg: "claims to supply new/updated instructions",
        seq: &[
            Tok::Eq(&["new", "updated", "revised", "real", "actual", "important"]),
            Tok::Prefix(&["instruct", "directive", "system", "mission"]),
        ],
        gap: 2,
    },
    Pat {
        id: "instruction.developer-mode",
        cat: Category::InstructionOverride,
        sev: Severity::Medium,
        msg: "jailbreak persona request (developer mode / DAN / do anything now)",
        seq: &[
            Tok::Eq(&["developer", "dan", "god", "sudo"]),
            Tok::Eq(&["mode"]),
        ],
        gap: 1,
    },
    Pat {
        id: "hijack.call-tool",
        cat: Category::ToolHijack,
        sev: Severity::Medium,
        msg: "directive to call a tool/function/command",
        seq: &[
            Tok::Eq(&[
                "call", "invoke", "use", "run", "execute", "trigger", "launch", "perform", "issue",
            ]),
            Tok::Prefix(&[
                "tool", "function", "command", "api", "endpoint", "action", "plugin",
            ]),
        ],
        gap: 3,
    },
    Pat {
        id: "hijack.exec-code",
        cat: Category::ToolHijack,
        sev: Severity::Medium,
        msg: "directive to execute the following code/script/command",
        seq: &[
            Tok::Eq(&["run", "execute", "eval", "evaluate", "exec", "interpret"]),
            Tok::Eq(&[
                "the",
                "this",
                "following",
                "below",
                "code",
                "script",
                "command",
                "payload",
                "shell",
            ]),
        ],
        gap: 1,
    },
    Pat {
        id: "exfil.send-to-url",
        cat: Category::Exfiltration,
        sev: Severity::Medium,
        msg: "directive to send/upload/exfiltrate data to a URL",
        seq: &[
            Tok::Eq(&[
                "send",
                "post",
                "upload",
                "exfiltrate",
                "leak",
                "transmit",
                "forward",
                "deliver",
                "email",
            ]),
            Tok::Prefix(&["http"]),
        ],
        gap: 12,
    },
];

// Chat-template / role delimiters an attacker embeds to fake a turn boundary.
// Searched as contiguous substrings of the normalized (lowercased) stream.
static ROLE_MARKERS: &[(&str, Severity, &str)] = &[
    ("<|im_start|>", Severity::High, "ChatML role delimiter"),
    ("<|im_end|>", Severity::High, "ChatML role delimiter"),
    ("<|system|>", Severity::High, "role delimiter"),
    ("<|user|>", Severity::High, "role delimiter"),
    ("<|assistant|>", Severity::High, "role delimiter"),
    ("<|endoftext|>", Severity::High, "special end-of-text token"),
    ("[inst]", Severity::High, "Llama instruction delimiter"),
    ("[/inst]", Severity::High, "Llama instruction delimiter"),
    ("<<sys>>", Severity::High, "Llama system delimiter"),
    ("<</sys>>", Severity::High, "Llama system delimiter"),
    ("<system>", Severity::Medium, "system-role tag"),
    ("</system>", Severity::Medium, "system-role tag"),
    ("system:", Severity::Medium, "system-role prefix"),
    ("assistant:", Severity::Medium, "assistant-role prefix"),
];

/// Top-level detection entry point: run every layer over `input` and return the
/// merged, sorted, de-duplicated findings plus descriptive stats.
pub fn detect_all(input: &str, decode_encoded: bool) -> (Vec<Finding>, Stats) {
    let mut findings = detect_text_over(input);
    detect_invisible(input, &mut findings);
    if decode_encoded {
        crate::encoded::detect_encoded(input, &mut findings);
    }

    findings.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| a.id.cmp(b.id)));
    findings.dedup_by(|a, b| a.id == b.id && a.start == b.start && a.end == b.end);

    let stats = stats_of(input);
    (findings, stats)
}

fn stats_of(input: &str) -> Stats {
    let mut invisible = 0;
    let mut chars = 0;
    for c in input.chars() {
        chars += 1;
        if classify_invisible(c).is_some() {
            invisible += 1;
        }
    }
    Stats {
        bytes: input.len(),
        chars,
        invisible_chars: invisible,
    }
}

/// Detect hidden / non-printing characters directly over the raw text.
pub fn detect_invisible(input: &str, out: &mut Vec<Finding>) {
    // Collapse consecutive hidden chars of the same class into one finding.
    let mut prev_visible: Option<char> = None;
    let chars: Vec<(usize, char)> = input.char_indices().collect();

    let mut i = 0;
    while i < chars.len() {
        let (off, c) = chars[i];
        let kind = match classify_invisible(c) {
            Some(k) => k,
            None => {
                prev_visible = Some(c);
                i += 1;
                continue;
            }
        };

        // Extend the run over same-kind hidden chars.
        let start = off;
        let mut j = i;
        let mut run: Vec<char> = Vec::new();
        while j < chars.len() {
            let (_, cj) = chars[j];
            if classify_invisible(cj) == Some(kind) {
                run.push(cj);
                j += 1;
            } else {
                break;
            }
        }
        let end = if j < chars.len() {
            chars[j].0
        } else {
            input.len()
        };
        let next_visible = chars.get(j).map(|&(_, c)| c);

        emit_invisible(kind, &run, start, end, prev_visible, next_visible, out);
        i = j;
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_invisible(
    kind: InvisibleKind,
    run: &[char],
    start: usize,
    end: usize,
    prev_visible: Option<char>,
    next_visible: Option<char>,
    out: &mut Vec<Finding>,
) {
    let count = run.len();
    match kind {
        InvisibleKind::Tag => {
            // Tag characters carry a hidden ASCII payload — decode it and show it.
            let decoded: String = run
                .iter()
                .filter_map(|&c| {
                    let u = c as u32;
                    if (0xE0020..=0xE007E).contains(&u) {
                        Some((u - 0xE0000) as u8 as char)
                    } else {
                        None
                    }
                })
                .collect();
            let detail = if decoded.is_empty() {
                None
            } else {
                Some(format!("smuggled ASCII: {:?}", decoded))
            };
            out.push(Finding {
                id: "invisible.tag-chars",
                category: Category::AsciiSmuggling,
                severity: Severity::Critical,
                message: format!(
                    "{count} Unicode Tag character(s) smuggling hidden ASCII into the text"
                ),
                start,
                end,
                snippet: run_snippet(run),
                detail,
            });
        }
        InvisibleKind::Bidi => {
            // Overrides/isolates are the attack; plain marks (LRM/RLM/ALM) are common in RTL text.
            let is_override = run.iter().any(|&c| {
                let u = c as u32;
                (0x202A..=0x202E).contains(&u) || (0x2066..=0x2069).contains(&u)
            });
            let sev = if is_override {
                Severity::High
            } else {
                Severity::Low
            };
            out.push(Finding {
                id: "invisible.bidi",
                category: Category::Bidi,
                severity: sev,
                message: format!(
                    "{count} bidirectional control character(s) (text-direction override)"
                ),
                start,
                end,
                snippet: run_snippet(run),
                detail: None,
            });
        }
        InvisibleKind::ZeroWidth => {
            // Zero-width chars wedged between ASCII letters are word-splitting
            // obfuscation; elsewhere (emoji ZWJ, Indic scripts) they are benign.
            let between_letters = matches!(prev_visible, Some(p) if p.is_ascii_alphanumeric())
                && matches!(next_visible, Some(n) if n.is_ascii_alphanumeric());
            // ZWJ/ZWNJ outside an ASCII word are legitimate emoji/Indic-script
            // joiners — don't flag them.
            if !between_letters && run.iter().all(|&c| c == '\u{200C}' || c == '\u{200D}') {
                return;
            }
            let sev = if between_letters {
                Severity::High
            } else {
                Severity::Low
            };
            let why = if between_letters {
                " splitting an ASCII word (obfuscation)"
            } else {
                ""
            };
            out.push(Finding {
                id: "invisible.zero-width",
                category: Category::HiddenText,
                severity: sev,
                message: format!("{count} zero-width/invisible character(s){why}"),
                start,
                end,
                snippet: run_snippet(run),
                detail: None,
            });
        }
        InvisibleKind::VariationSelector => {
            out.push(Finding {
                id: "invisible.variation-selector",
                category: Category::HiddenText,
                severity: Severity::Low,
                message: format!("{count} variation selector(s) (possible covert channel)"),
                start,
                end,
                snippet: run_snippet(run),
                detail: None,
            });
        }
        InvisibleKind::Control => {
            out.push(Finding {
                id: "invisible.control",
                category: Category::HiddenText,
                severity: Severity::Low,
                message: format!("{count} C0/C1 control character(s)"),
                start,
                end,
                snippet: run_snippet(run),
                detail: None,
            });
        }
    }
}

fn run_snippet(run: &[char]) -> String {
    let mut s = String::new();
    for (i, &c) in run.iter().enumerate() {
        if i >= 8 {
            s.push('…');
            break;
        }
        s.push_str(&format!("<U+{:04X}>", c as u32));
    }
    s
}

/// Run the normalized-text detectors over an arbitrary piece of text and return
/// findings whose offsets index into that same text.
pub fn detect_text_over(text: &str) -> Vec<Finding> {
    let norm = Normalized::build(text);
    let mut out = Vec::new();
    if norm.is_empty() {
        return out;
    }
    let tokens = tokenize(&norm.chars);

    // Natural-language / directive patterns.
    for p in PATTERNS {
        if let Some((cis, cie)) = match_seq(&tokens, p.seq, p.gap) {
            let (s, e) = norm.orig_span(cis, cie);
            out.push(Finding {
                id: p.id,
                category: p.cat,
                severity: p.sev,
                message: p.msg.to_string(),
                start: s,
                end: e,
                snippet: safe_excerpt(text, s, e, 80),
                detail: None,
            });
            // If the matched span used non-ASCII look-alike letters, the attacker
            // obfuscated it — record that as its own signal.
            if span_has_non_ascii_alpha(text, s, e) {
                out.push(Finding {
                    id: "confusable.obfuscated-trigger",
                    category: Category::Confusable,
                    severity: Severity::Medium,
                    message: "trigger phrase written with mixed-script look-alike characters"
                        .to_string(),
                    start: s,
                    end: e,
                    snippet: safe_excerpt(text, s, e, 80),
                    detail: None,
                });
            }
        }
    }

    // Role / chat-template delimiters.
    for (marker, sev, desc) in ROLE_MARKERS {
        let needle: Vec<char> = marker.chars().collect();
        if let Some(ci) = find_sub(&norm.chars, &needle, 0) {
            let (s, e) = norm.orig_span(ci, ci + needle.len());
            out.push(Finding {
                id: "role.delimiter",
                category: Category::RoleInjection,
                severity: *sev,
                message: format!("injected {desc} ({marker})"),
                start: s,
                end: e,
                snippet: safe_excerpt(text, s, e, 40),
                detail: None,
            });
        }
    }

    scan_markdown_and_urls(text, &mut out);
    scan_secrets(text, &mut out);
    out
}

fn span_has_non_ascii_alpha(text: &str, start: usize, end: usize) -> bool {
    text.get(start..end)
        .map(|s| s.chars().any(|c| !c.is_ascii() && c.is_alphabetic()))
        .unwrap_or(false)
}

/// Exfiltration channels: markdown-image beacons and dangerous URI schemes.
fn scan_markdown_and_urls(text: &str, out: &mut Vec<Finding>) {
    let bytes = text.as_bytes();

    // Markdown image beacons: ![alt](url)
    let mut search = 0;
    while let Some(rel) = text[search..].find("![") {
        let bang = search + rel;
        // Find the "](" that closes the alt text.
        if let Some(mrel) = text[bang..].find("](") {
            let paren_open = bang + mrel + 2;
            if let Some(crel) = text[paren_open..].find(')') {
                let url = &text[paren_open..paren_open + crel];
                let end = paren_open + crel + 1;
                classify_url(url, bang, end, text, true, out);
                search = end;
                continue;
            }
        }
        search = bang + 2;
    }

    // Standalone dangerous URI schemes anywhere in the text.
    for scheme in ["javascript:", "data:text/html", "vbscript:"] {
        if let Some(pos) = ascii_find_ci(bytes, scheme.as_bytes(), 0) {
            let end = (pos + scheme.len() + 32).min(text.len());
            let end = char_boundary_up(text, end);
            out.push(Finding {
                id: "exfil.dangerous-uri",
                category: Category::Exfiltration,
                severity: Severity::High,
                message: format!("dangerous URI scheme `{scheme}` in untrusted content"),
                start: pos,
                end,
                snippet: safe_excerpt(text, pos, end, 60),
                detail: None,
            });
        }
    }

    // URLs carrying credential-shaped query parameters.
    for key in [
        "token=",
        "api_key=",
        "apikey=",
        "access_token=",
        "password=",
        "secret=",
        "auth=",
        "session=",
    ] {
        if let Some(pos) = ascii_find_ci(bytes, key.as_bytes(), 0) {
            // Only if it looks like it is inside a URL (an http(s):// appears before it nearby).
            let window_start = pos.saturating_sub(200);
            if text[window_start..pos].contains("http") {
                let end = char_boundary_up(text, (pos + key.len() + 24).min(text.len()));
                out.push(Finding {
                    id: "exfil.credential-in-url",
                    category: Category::Exfiltration,
                    severity: Severity::High,
                    message: format!("URL carries a credential-like query parameter `{key}`"),
                    start: pos,
                    end,
                    snippet: safe_excerpt(text, pos, end, 60),
                    detail: None,
                });
            }
        }
    }
}

fn classify_url(
    url: &str,
    start: usize,
    end: usize,
    text: &str,
    is_image: bool,
    out: &mut Vec<Finding>,
) {
    let lower = url.trim().to_ascii_lowercase();
    let what = if is_image {
        "markdown image"
    } else {
        "markdown link"
    };
    if lower.starts_with("javascript:") || lower.starts_with("data:text/html") {
        out.push(Finding {
            id: "exfil.markdown-dangerous-uri",
            category: Category::Exfiltration,
            severity: Severity::High,
            message: format!("{what} uses a script/HTML URI"),
            start,
            end,
            snippet: safe_excerpt(text, start, end, 80),
            detail: None,
        });
    } else if (lower.starts_with("http://") || lower.starts_with("https://")) && url.contains('?') {
        out.push(Finding {
            id: "exfil.markdown-image-beacon",
            category: Category::Exfiltration,
            severity: if is_image {
                Severity::High
            } else {
                Severity::Medium
            },
            message: format!(
                "{what} points to an external URL with a query string (data-exfiltration beacon)"
            ),
            start,
            end,
            snippet: safe_excerpt(text, start, end, 80),
            detail: None,
        });
    }
}

/// Credential-shaped secrets sitting in untrusted content. Snippets are masked.
fn scan_secrets(text: &str, out: &mut Vec<Finding>) {
    let checks: &[(&str, &str, usize)] = &[
        ("sk-", "OpenAI-style API key", 20),
        ("ghp_", "GitHub personal access token", 20),
        ("gho_", "GitHub OAuth token", 20),
        ("ghs_", "GitHub server token", 20),
        ("github_pat_", "GitHub fine-grained PAT", 20),
        ("xoxb-", "Slack bot token", 10),
        ("xoxp-", "Slack user token", 10),
        ("AKIA", "AWS access key id", 16),
        ("AIza", "Google API key", 30),
    ];
    let bytes = text.as_bytes();
    for (prefix, label, min_tail) in checks {
        let mut from = 0;
        while let Some(pos) = ascii_find(bytes, prefix.as_bytes(), from) {
            let tail_start = pos + prefix.len();
            let tail_len = count_token_chars(bytes, tail_start);
            if tail_len >= *min_tail {
                let end = tail_start + tail_len;
                out.push(Finding {
                    id: "secret.api-key",
                    category: Category::Secret,
                    severity: Severity::Medium,
                    message: format!("{label} present in untrusted content"),
                    start: pos,
                    end,
                    snippet: mask_secret(prefix, tail_len),
                    detail: None,
                });
                from = end;
            } else {
                from = pos + prefix.len();
            }
        }
    }

    // PEM private key blocks.
    if let Some(pos) = ascii_find(bytes, b"-----BEGIN ", 0) {
        if text[pos..].contains("PRIVATE KEY-----") {
            let end = char_boundary_up(text, (pos + 32).min(text.len()));
            out.push(Finding {
                id: "secret.private-key",
                category: Category::Secret,
                severity: Severity::High,
                message: "PEM private key block present in untrusted content".to_string(),
                start: pos,
                end,
                snippet: "-----BEGIN … PRIVATE KEY-----".to_string(),
                detail: None,
            });
        }
    }
}

fn mask_secret(prefix: &str, tail_len: usize) -> String {
    format!("{prefix}…({tail_len} chars, masked)")
}

/// Number of consecutive token characters (`[A-Za-z0-9_-]`) starting at `from`.
fn count_token_chars(bytes: &[u8], from: usize) -> usize {
    let mut n = 0;
    let mut i = from;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' {
            n += 1;
            i += 1;
        } else {
            break;
        }
    }
    n
}

/// Case-sensitive byte substring search.
fn ascii_find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() || from > hay.len() - needle.len() {
        return None;
    }
    (from..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

/// Case-insensitive (ASCII) byte substring search.
fn ascii_find_ci(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() || from > hay.len() - needle.len() {
        return None;
    }
    (from..=hay.len() - needle.len()).find(|&i| {
        hay[i..i + needle.len()]
            .iter()
            .zip(needle)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

fn char_boundary_up(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// Preview helper reused by the encoded-payload detector.
pub fn preview(s: &str) -> String {
    visible_string(s, 80)
}
