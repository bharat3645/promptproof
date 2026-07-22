# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-22

First release. A zero-dependency library + CLI that scans untrusted content for
prompt-injection and exfiltration signals and hardens it by stripping hidden
channels.

### Added

- **Scanner** (`promptproof::scan`) with detectors across seven signal classes:
  - hidden characters — zero-width/format, bidirectional overrides, Unicode Tag
    "ASCII smuggling" (the smuggled ASCII is decoded and shown), variation
    selectors, C0/C1 controls;
  - natural-language instruction overrides, robust to zero-width word-splitting,
    mixed-script confusable letters, case, and whitespace, via a normalized view
    with an offset map back to the original bytes;
  - injected chat-template role delimiters (`<|im_start|>`, `[INST]`, `<<SYS>>`,
    `system:`, ...);
  - tool-hijack directives (call a tool / execute code);
  - exfiltration channels — markdown-image beacons, `data:`/`javascript:` URIs,
    credential-in-URL query parameters, and `send ... to <url>` directives;
  - encoded payloads — base64/hex/percent blobs that decode to any of the above;
  - planted, credential-shaped secrets (masked in output).
- **Compositional scoring**: ambiguous lexical signals are `Medium` (a lone
  match is `suspicious`); high-confidence covert channels are `High`/`Critical`
  (`dangerous`). Verdicts are `ok` / `suspicious` / `dangerous`, thresholds
  tunable via `Policy`.
- **Sanitizer** (`promptproof::sanitize`) that removes (or visibly marks) hidden
  characters while leaving ordinary and non-Latin text untouched.
- **CLI** `promptproof` with `scan` (human + `--json`/JSONL output, exit codes
  0/1/2 by worst verdict, tunable thresholds) and `sanitize` subcommands.
- **Labeled corpus** (`corpus/`) of 12 malicious + 12 benign samples with a
  precision/recall test: 12/12 malicious flagged `dangerous`, 0/12 benign
  flagged `dangerous` (10/12 fully clean).
- **Benchmark** (`cargo run --release --example bench`) reporting real
  throughput.
- 65 tests (unit + integration + corpus + CLI + doctest), `#![forbid(unsafe_code)]`,
  clippy `-D warnings` clean, CI on stable Rust.

### Known limitations

- Prompt injection is unsolved; a pattern scanner cannot make untrusted content
  safe. This is defense-in-depth — pair it with capability sandboxing and least
  privilege. A determined, novel attack can evade any pattern-based detector.
- Content that legitimately *discusses* injection (a security article, tool
  docs) can be flagged `suspicious`. That is by design: `suspicious` means
  "worth a human glance", not "an attack".
- The confusable table is curated (high-value look-alikes), not the full Unicode
  confusables database.

[0.1.0]: https://github.com/bharat3645/promptproof/releases/tag/v0.1.0
