//! `promptproof` command-line interface.
//!
//! Subcommands:
//!   * `scan`      — scan files or stdin for injection/exfiltration signals.
//!   * `sanitize`  — strip hidden characters from a file or stdin.
//!   * `serve`     — long-lived coprocess: framed content in, JSON verdict out.
//!   * `version`   — print the version.
//!   * `help`      — usage.

use std::io::{BufRead, Read, Write};
use std::process::ExitCode;

use promptproof::json::report_json_with_suppressed;
use promptproof::sanitize::SanitizePolicy;
use promptproof::{sanitize, scan_with, Allowlist, Policy, Report, Verdict};

const USAGE: &str = "\
promptproof — data-plane prompt-injection & exfiltration scanner

USAGE:
    promptproof scan [OPTIONS] [PATH...]      scan files (or stdin if none / '-')
    promptproof sanitize [OPTIONS] [PATH]     strip hidden characters
    promptproof serve [SCAN OPTIONS]          coprocess: framed stdin -> JSONL stdout
    promptproof version
    promptproof help

SCAN OPTIONS:
    --json               emit one JSON object per input (JSONL)
    --quiet              print nothing; use the exit code only
    --no-decode          do not decode/rescan base64/hex/percent blobs
    --suspicious-at N    score threshold for 'suspicious' (default 1)
    --dangerous-at N     score threshold for 'dangerous'  (default 6)
    --allowlist PATH     suppress specific known-benign findings; see
                         ALLOWLIST below (accepted by scan and serve)

ALLOWLIST:
    A JSON array of objects, each with a required \"rule\" (a finding id, or
    \"*\" for any rule) and optional \"contains\" (only suppress that rule's
    hits when the scanned document itself contains this substring — a URL,
    doc title, or fixed disclaimer; document-grained, not per-occurrence)
    and \"reason\" (documentation only). Suppressed findings are removed and
    the verdict/score are recomputed from what's left; the suppressed count
    is always reported (human output: a summary line; --json / serve: a
    \"suppressed\" field).
    Example:
        [
          {\"rule\": \"instruction.ignore-previous\", \"contains\": \"As an example\",
           \"reason\": \"training doc, not live content\"}
        ]

SANITIZE OPTIONS:
    --mark               replace hidden chars with visible <U+XXXX> markers
                         (default: delete them)
    --report             print a removal summary to stderr

SERVE PROTOCOL:
    A long-lived scanner for embedding in another process (e.g. a gateway
    that scans tool results or request messages inline). Each request is a
    length-prefixed frame on stdin: an ASCII decimal byte count followed by
    a newline, then exactly that many bytes of content. For each frame the
    same compact JSON report the '--json' scan emits is written to stdout on
    one line and flushed. EOF ends the loop with exit 0. serve accepts the
    same --suspicious-at / --dangerous-at / --no-decode options as scan.

EXIT CODES (scan):
    0 ok   1 suspicious   2 dangerous   3 usage/IO error
    (the worst verdict across all inputs is returned)
";

// Upper bound on a single serve frame. The intended embedder caps content
// far below this (a gateway scans a bounded slice of a tool result); this
// only guards against a corrupt length prefix demanding an absurd
// allocation. 64 MiB is generous headroom over any real tool result.
const MAX_SERVE_FRAME: usize = 64 << 20;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprint!("{USAGE}");
        return ExitCode::from(3);
    }
    match args[0].as_str() {
        "scan" => cmd_scan(&args[1..]),
        "sanitize" => cmd_sanitize(&args[1..]),
        "serve" => cmd_serve(&args[1..]),
        "version" | "--version" | "-V" => {
            println!("promptproof {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("promptproof: unknown subcommand '{other}'\n");
            eprint!("{USAGE}");
            ExitCode::from(3)
        }
    }
}

fn cmd_scan(args: &[String]) -> ExitCode {
    let mut policy = Policy::default();
    let mut json = false;
    let mut quiet = false;
    let mut allowlist_path: Option<String> = None;
    let mut paths: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--quiet" => quiet = true,
            "--no-decode" => policy.decode_encoded = false,
            "--suspicious-at" => {
                i += 1;
                match args.get(i).and_then(|s| s.parse().ok()) {
                    Some(n) => policy.suspicious_at = n,
                    None => return usage_err("--suspicious-at needs a number"),
                }
            }
            "--dangerous-at" => {
                i += 1;
                match args.get(i).and_then(|s| s.parse().ok()) {
                    Some(n) => policy.dangerous_at = n,
                    None => return usage_err("--dangerous-at needs a number"),
                }
            }
            "--allowlist" => {
                i += 1;
                match args.get(i) {
                    Some(p) => allowlist_path = Some(p.clone()),
                    None => return usage_err("--allowlist needs a PATH"),
                }
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            s if s.starts_with("--") => return usage_err(&format!("unknown option '{s}'")),
            s => paths.push(s.to_string()),
        }
        i += 1;
    }

    let allowlist = match load_allowlist(allowlist_path.as_deref()) {
        Ok(a) => a,
        Err(code) => return code,
    };

    let inputs: Vec<(String, String)> = if paths.is_empty() {
        match read_stdin() {
            Ok(text) => vec![("<stdin>".to_string(), text)],
            Err(e) => return io_err("<stdin>", &e),
        }
    } else {
        let mut v = Vec::new();
        for p in &paths {
            let text = if p == "-" {
                match read_stdin() {
                    Ok(t) => t,
                    Err(e) => return io_err("<stdin>", &e),
                }
            } else {
                match std::fs::read(p) {
                    Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                    Err(e) => return io_err(p, &e.to_string()),
                }
            };
            v.push((p.clone(), text));
        }
        v
    };

    let mut worst = Verdict::Ok;
    let stdout = std::io::stdout();
    let mut w = stdout.lock();
    for (source, text) in &inputs {
        let (report, suppressed) = scan_and_filter(text, &policy, allowlist.as_ref());
        if report.verdict > worst {
            worst = report.verdict;
        }
        if quiet {
            continue;
        }
        if json {
            let _ = writeln!(
                w,
                "{}",
                report_json_with_suppressed(source, &report, suppressed)
            );
        } else {
            print_human(&mut w, source, &report, suppressed);
        }
    }

    ExitCode::from(worst.exit_code() as u8)
}

/// Load and parse an allowlist file, if a path was given. A malformed file
/// is a usage error (exit 3) — a policy file that fails to load must never
/// be silently treated as "no policy" (that would fail open on a typo).
fn load_allowlist(path: Option<&str>) -> Result<Option<Allowlist>, ExitCode> {
    let Some(path) = path else { return Ok(None) };
    let text = std::fs::read_to_string(path).map_err(|e| io_err(path, &e.to_string()))?;
    Allowlist::parse(&text)
        .map(Some)
        .map_err(|e| usage_err(&format!("{path}: {e}")))
}

/// Scan, then apply an allowlist if one is set. Returns the (possibly
/// filtered) report and how many findings were suppressed.
fn scan_and_filter(text: &str, policy: &Policy, allowlist: Option<&Allowlist>) -> (Report, usize) {
    let report = scan_with(text, policy);
    match allowlist {
        Some(a) => a.apply(text, report, policy),
        None => (report, 0),
    }
}

fn cmd_serve(args: &[String]) -> ExitCode {
    let mut policy = Policy::default();
    let mut allowlist_path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--no-decode" => policy.decode_encoded = false,
            "--suspicious-at" => {
                i += 1;
                match args.get(i).and_then(|s| s.parse().ok()) {
                    Some(n) => policy.suspicious_at = n,
                    None => return usage_err("--suspicious-at needs a number"),
                }
            }
            "--dangerous-at" => {
                i += 1;
                match args.get(i).and_then(|s| s.parse().ok()) {
                    Some(n) => policy.dangerous_at = n,
                    None => return usage_err("--dangerous-at needs a number"),
                }
            }
            "--allowlist" => {
                i += 1;
                match args.get(i) {
                    Some(p) => allowlist_path = Some(p.clone()),
                    None => return usage_err("--allowlist needs a PATH"),
                }
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            s => return usage_err(&format!("serve: unexpected argument '{s}'")),
        }
        i += 1;
    }

    let allowlist = match load_allowlist(allowlist_path.as_deref()) {
        Ok(a) => a,
        Err(code) => return code,
    };

    let stdin = std::io::stdin();
    let mut reader = std::io::BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    let mut w = std::io::BufWriter::new(stdout.lock());

    loop {
        // Read the length-prefix line. An empty read is a clean EOF.
        let mut header = String::new();
        match reader.read_line(&mut header) {
            Ok(0) => return ExitCode::SUCCESS,
            Ok(_) => {}
            Err(e) => return io_err("<stdin>", &e.to_string()),
        }
        let header = header.trim();
        if header.is_empty() {
            // Tolerate blank separator lines between frames.
            continue;
        }
        let n: usize = match header.parse() {
            Ok(n) => n,
            Err(_) => return usage_err(&format!("serve: bad frame length {header:?}")),
        };
        if n > MAX_SERVE_FRAME {
            return usage_err(&format!("serve: frame length {n} exceeds cap"));
        }

        let mut buf = vec![0u8; n];
        if let Err(e) = reader.read_exact(&mut buf) {
            // A short read means the peer closed mid-frame; nothing more to do.
            return io_err("<stdin>", &e.to_string());
        }
        let text = String::from_utf8_lossy(&buf);
        let (report, suppressed) = scan_and_filter(&text, &policy, allowlist.as_ref());
        if writeln!(
            w,
            "{}",
            report_json_with_suppressed("<serve>", &report, suppressed)
        )
        .is_err()
            || w.flush().is_err()
        {
            // The embedder went away; stop quietly.
            return ExitCode::SUCCESS;
        }
    }
}

fn print_human<W: Write>(w: &mut W, source: &str, r: &Report, suppressed: usize) {
    let suffix = if suppressed > 0 {
        format!(" ({suppressed} suppressed by allowlist)")
    } else {
        String::new()
    };
    if r.findings.is_empty() {
        let _ = writeln!(w, "{source}: OK — clean{suffix}");
        return;
    }
    let _ = writeln!(
        w,
        "{source}: {} — score {}, {} finding(s){suffix}",
        r.verdict.as_str().to_uppercase(),
        r.score,
        r.findings.len()
    );
    for f in &r.findings {
        let _ = writeln!(
            w,
            "  [{}] {}  {}  @{}..{}",
            f.severity.as_str(),
            f.category.as_str(),
            f.id,
            f.start,
            f.end
        );
        let _ = writeln!(w, "      {}", f.message);
        if !f.snippet.is_empty() {
            let _ = writeln!(w, "      {:?}", f.snippet);
        }
        if let Some(d) = &f.detail {
            let _ = writeln!(w, "      ↳ {d}");
        }
    }
}

fn cmd_sanitize(args: &[String]) -> ExitCode {
    let mut policy = SanitizePolicy::default();
    let mut report = false;
    let mut path: Option<String> = None;

    for a in args {
        match a.as_str() {
            "--mark" => policy.mark = true,
            "--report" => report = true,
            "-h" | "--help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            s if s.starts_with("--") => return usage_err(&format!("unknown option '{s}'")),
            s => {
                if path.is_some() {
                    return usage_err("sanitize takes at most one PATH");
                }
                path = Some(s.to_string());
            }
        }
    }

    let text = match path.as_deref() {
        None | Some("-") => match read_stdin() {
            Ok(t) => t,
            Err(e) => return io_err("<stdin>", &e),
        },
        Some(p) => match std::fs::read(p) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(e) => return io_err(p, &e.to_string()),
        },
    };

    let (clean, rep) = sanitize(&text, &policy);
    let stdout = std::io::stdout();
    let mut w = stdout.lock();
    let _ = w.write_all(clean.as_bytes());
    let _ = w.flush();

    if report {
        eprintln!(
            "promptproof: removed {} hidden character(s)",
            rep.removed.len()
        );
        for r in &rep.removed {
            eprintln!(
                "  U+{:04X} ({}) at byte {}",
                r.codepoint,
                r.kind.as_str(),
                r.at
            );
        }
    }
    ExitCode::SUCCESS
}

fn read_stdin() -> Result<String, String> {
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn usage_err(msg: &str) -> ExitCode {
    eprintln!("promptproof: {msg}\n");
    eprint!("{USAGE}");
    ExitCode::from(3)
}

fn io_err(source: &str, msg: &str) -> ExitCode {
    eprintln!("promptproof: cannot read {source}: {msg}");
    ExitCode::from(3)
}
