# Contributing to promptproof

Thanks for looking under the hood. This project values small, verifiable changes.

## Ground rules

- **Every change ships with evidence.** Bug fix → a test that fails without it. Feature → tests that pin its behavior AND its failure modes. This repo documents what it *doesn't* do as carefully as what it does — PRs that quietly widen claims get asked to narrow them.
- **Zero new runtime dependencies** without an issue discussing why first. The dependency-free constraint is a feature.
- **Honest docs.** If your change has a limitation, the README states it. "Documented honestly" beats "silently best-effort".

## Getting started

```sh
cargo test                          # unit + integration + corpus tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

CI runs the same commands plus an end-to-end smoke; green CI is required, no exceptions (including for maintainers — check the history: it's how the whole repo was built).

## Working on detectors

A new detector or pattern must come with **both** kinds of corpus evidence:

- add a positive sample under `corpus/malicious/` that your change now catches, and
- confirm no sample under `corpus/benign/` regresses to `dangerous` (the corpus test enforces this).

New signals should also carry the right severity: a *high-confidence, rarely-benign* channel (hidden characters, a decoded payload, an exfil beacon) can be `High`/`Critical`; an *ambiguous lexical* signal (an English phrase that also appears in legitimate docs) should be `Medium` so a lone match is only `suspicious`. The scoring rationale is in the README.

## Good first issues

Issues tagged `good-first-issue` are scoped to be completable without deep context; each states the acceptance evidence expected. If you want one and it's unclear, comment — you'll get a response, not silence.

## Reporting security issues

Email 404ghost.2@gmail.com rather than opening a public issue. You'll get an acknowledgment within 48h and honest handling: if it's real, it ships as a fix with credit; if it's out of threat model, the threat-model doc gets clearer about why.
