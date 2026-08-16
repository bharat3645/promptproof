# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-08-16

Adds streaming/chunked scanning for very large inputs — the roadmap's
"Streaming / chunked scanning" item.

### Added

- **`promptproof::stream`** — `scan_reader` / `scan_reader_with`, scanning
  any `std::io::Read` source in bounded-memory chunks instead of requiring
  the whole input as one in-memory `&str`. Content is read in overlapping
  chunks so a pattern straddling a chunk boundary is still seen whole; a
  match is only committed once it's clear more data won't change it (never
  right at a chunk's uncertain trailing edge, which — proven by a real bug
  caught in this cycle's own test suite — can otherwise produce spurious or
  duplicate matches from a phrase truncated mid-word). Findings are
  deduplicated by `(id, start, end)` and, on a real 40 KB multi-chunk
  synthetic input, verified byte-for-byte identical in outcome to the
  equivalent non-streaming `scan`.
- `scan --chunk-size BYTES` — the CLI entry point, reading each input
  through the streaming path instead of loading it whole. Rejected as a
  usage error when combined with `--allowlist`, since `contains` scoping
  needs the whole document, which `--chunk-size` is built to avoid holding.
- 12 new unit tests (`src/stream.rs`) and 5 new CLI tests
  (`tests/cli_test.rs`) covering: empty input, small-input parity with the
  non-streaming scan, detection across many tiny (8-byte) chunks, a pattern
  split exactly at a chunk boundary, overlap-region dedup, large synthetic
  multi-chunk parity, invalid-UTF-8 lossy handling, zero-size-parameter
  panics, I/O error propagation, `max_findings` cap enforcement under
  streaming, and CLI-level file/stdin scanning plus both usage-error paths.

## [0.5.0] - 2026-08-16

Adds a Python binding built on the C ABI — the second half of the
roadmap's "language bindings" item (after 0.4.0's C ABI).

### Added

- **`bindings/python/promptproof`** — a thin, zero-third-party-dependency
  `ctypes` wrapper over `libpromptproof_capi` (`promptproof.scan(str |
  bytes) -> dict`). Locates the compiled library via the
  `PROMPTPROOF_CAPI_LIB` environment variable, a `capi/target/{release,
  debug}` path relative to a repo checkout, or the platform shared-library
  search path, in that order. Reimplements no detection logic — every call
  runs the real Rust engine.
- `bindings/python/tests/test_bindings.py` — 11 tests (stdlib `unittest`
  only) against the real compiled library: benign/malicious verdicts,
  `str`/`bytes` input parity, empty input, embedded-NUL-byte handling,
  invalid-UTF-8 lossy decoding, wrong-type rejection, 200 repeated
  alloc/free cycles for use-after-free/double-free safety, report-shape
  parity with the CLI's `--json` output, and the library-not-found error
  path.
- `bindings/python/examples/demo.py` — a real, runnable demo (mirrors
  `capi/examples/demo.c`); its real captured output is pasted into the
  README's new "Python bindings" section.
- Honest scope: not published to PyPI (no packaging metadata or wheel) —
  that remains a separate, permission-gated action; this ships the
  importable module and a real test suite exercising it against the built
  library, matching the C ABI's own scope note.

## [0.4.0] - 2026-08-14

Adds a C ABI so other languages can bind against promptproof without
reimplementing detection — the first half of the roadmap's "language
bindings" item.

### Added

- **`capi/`** — a new `promptproof-capi` crate exporting `promptproof_scan`
  and `promptproof_free_string` as `extern "C"` functions (builds a
  `cdylib`/`staticlib`), plus a C header (`capi/include/promptproof.h`) and
  a real, runnable C demo (`capi/examples/demo.c`). `unsafe` code is
  deliberately confined to this new crate — the core `promptproof` crate
  keeps `#![forbid(unsafe_code)]` untouched. `promptproof_scan` accepts a
  `(ptr, len)` byte buffer (not a NUL-terminated C string, so content with
  embedded NUL bytes still scans correctly) and returns the same JSON report
  shape as `promptproof scan --json`, decoding invalid UTF-8 lossily rather
  than failing.
- Honest scope: this ships a stable C ABI, not first-class Python/Node/Ruby
  packages — those would be thin wrappers over this ABI and remain future
  work, not claimed here.

## [0.3.0] - 2026-08-11

Adds a JSON allowlist policy file so a caller can suppress a specific,
reviewed false positive (the tool's own documented gap — a security post
quoting an attack phrase, API docs mentioning tools by name — see "How
verdicts work" in the README) without lowering detection for anyone else.

### Added

- **`--allowlist PATH`** (accepted by `scan` and `serve`) — a JSON array of
  `{"rule": "...", "contains": "...", "reason": "..."}` entries. `"rule"` is a
  finding id (or `"*"` for any rule); `"contains"` is optional and anchors to
  the whole scanned document, not a single occurrence; `"reason"` is
  documentation only. Suppressed findings are removed and the verdict/score
  recomputed from what's left; the count is always reported (`suppressed` in
  `--json`/`serve` output, a summary line in human output) — an allowlist
  never deletes evidence silently. A malformed or wrong-shaped policy file is
  a hard usage error (exit 3), never a silent no-op.
- `promptproof::allowlist::Allowlist` (library API): `Allowlist::parse` and
  `Allowlist::apply`.
- `src/json_value.rs` — a small, dependency-free JSON *parser* (the existing
  `json.rs` only emits) scoped to what a hand-written policy file needs:
  null/bool/number/string/array/object, full string escapes incl. `\uXXXX`
  surrogate pairs. 9 unit tests including rejection of trailing commas,
  unterminated strings, and bare control characters in strings.
- `json::report_json_with_suppressed` — `report_json` plus a `"suppressed"`
  count, added as a separate function so existing callers of `report_json`
  are unaffected.
- 20 new tests (11 library unit tests in `src/allowlist.rs`, 9 CLI
  integration tests in `tests/cli_test.rs` spawning the real binary) + 1 new
  doctest; `ci/smoke.sh` gained a suppression scenario and a malformed-policy
  usage-error scenario, both run against the real release binary.

### Notes

- No behavior change when `--allowlist` is not passed; existing callers
  (including the `serve` embeddings in mcp-gateway-lite and modelgate) are
  unaffected until they opt in.

## [0.2.0] - 2026-07-22

Adds an embeddable coprocess mode so other services can scan content inline on
their request path without paying a process spawn per scan. This release is what
turns promptproof from a standalone CLI into middleware — it is now embedded in
two other repos in the portfolio (see **Used in production** in the README).

### Added

- **`serve` subcommand** — a long-lived scanner for embedding in another
  process. It reads length-prefixed frames from stdin (an ASCII decimal byte
  count, a newline, then exactly that many content bytes) and writes one compact
  JSON report per frame to stdout, flushing after each. Length framing (not line
  framing) so content containing newlines scans correctly. Honors the same
  `--suspicious-at` / `--dangerous-at` / `--no-decode` options as `scan`; a
  clean EOF exits 0. Reuses the existing detection engine unchanged — no new
  detection logic, no new dependencies.
- Serve-mode integration tests (`tests/cli_test.rs`): one-verdict-per-frame,
  newline-containing frames, threshold honoring, and bad-length-prefix rejection.
- `ci/smoke.sh` drives the real `serve` binary through a multi-frame session.

### Notes

- No behavior change to `scan`, `sanitize`, or the library API; existing callers
  are unaffected. This is a minor version because it only adds a subcommand.

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
