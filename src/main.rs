//! `promptproof` command-line interface.
//!
//! Subcommands:
//!   * `scan`      — scan files or stdin for injection/exfiltration signals.
//!   * `sanitize`  — strip hidden characters from a file or stdin.
//!   * `version`   — print the version.
//!   * `help`      — usage.

use std::io::{Read, Write};
use std::process::ExitCode;

use promptproof::json::report_json;
use promptproof::sanitize::SanitizePolicy;
use promptproof::{sanitize, scan_with, Policy, Report, Verdict};

const USAGE: &str = "\
promptproof — data-plane prompt-injection & exfiltration scanner

USAGE:
    promptproof scan [OPTIONS] [PATH...]      scan files (or stdin if none / '-')
    promptproof sanitize [OPTIONS] [PATH]     strip hidden characters
    promptproof version
    promptproof help

SCAN OPTIONS:
    --json               emit one JSON object per input (JSONL)
    --quiet              print nothing; use the exit code only
    --no-decode          do not decode/rescan base64/hex/percent blobs
    --suspicious-at N    score threshold for 'suspicious' (default 1)
    --dangerous-at N     score threshold for 'dangerous'  (default 6)

SANITIZE OPTIONS:
    --mark               replace hidden chars with visible <U+XXXX> markers
                         (default: delete them)
    --report             print a removal summary to stderr

EXIT CODES (scan):
    0 ok   1 suspicious   2 dangerous   3 usage/IO error
    (the worst verdict across all inputs is returned)
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprint!("{USAGE}");
        return ExitCode::from(3);
    }
    match args[0].as_str() {
        "scan" => cmd_scan(&args[1..]),
        "sanitize" => cmd_sanitize(&args[1..]),
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
            "-h" | "--help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            s if s.starts_with("--") => return usage_err(&format!("unknown option '{s}'")),
            s => paths.push(s.to_string()),
        }
        i += 1;
    }

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
        let report = scan_with(text, &policy);
        if report.verdict > worst {
            worst = report.verdict;
        }
        if quiet {
            continue;
        }
        if json {
            let _ = writeln!(w, "{}", report_json(source, &report));
        } else {
            print_human(&mut w, source, &report);
        }
    }

    ExitCode::from(worst.exit_code() as u8)
}

fn print_human<W: Write>(w: &mut W, source: &str, r: &Report) {
    if r.findings.is_empty() {
        let _ = writeln!(w, "{source}: OK — clean");
        return;
    }
    let _ = writeln!(
        w,
        "{source}: {} — score {}, {} finding(s)",
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
