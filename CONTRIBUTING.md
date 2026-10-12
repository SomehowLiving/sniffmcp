# Contributing

Thanks for helping. sniffmcp is a security tool, so the bar for detection changes is
**evidence**, not intuition.

## Setup

```bash
uv venv && uv pip install -e '.[dev]'
.venv/bin/python -m pytest -q          # ~10s, no network needed
```

`tests/test_live_stdio.py` spawns a real stdio fixture server (`tests/fixtures/fixture_server.py`)
and runs scan → baseline → rug pull → accept end to end.

## Changing or adding a detection rule

Every rule change must pass all of these:

1. **The real-world false-positive corpus stays quiet.** `REAL_BENIGN_TEXTS` in
   `tests/test_checks.py` holds descriptions from live registry servers that once fooled a
   rule. No rule may raise high/critical on any of them.
2. **Known attacks are still caught.** `test_attacks_still_caught_after_precision_fixes` and
   the Invariant-style poisoning test must pass.
3. **Popular legitimate servers still grade A/B** (`test_benign_server_grades_a_or_b`).
4. **Check it against the crawl if you have one.** Run `sniffmcp crawl rescore` and check
   every new high/critical hit by hand. Our first crawl pass flagged ~80 servers; nearly
   all were false positives. That's normal, and it's why this step exists.
5. **Every false positive you find becomes a test.** Add the text (anonymised to `example`
   domains, no server names) to `REAL_BENIGN_TEXTS`, then fix the rule.

Capabilities are not defects: a tool that can write files or run commands is reported at
low/info, not punished. Reserve high/critical for evidence that something is wrong.

## Check IDs

`SM-xx` IDs are frozen contracts once released: never renumber or reuse them. New checks
get the next free number and an entry in `report.RULES_META` and `report.OWASP_FOR_CHECK`
(a test enforces the OWASP mapping).

## Crawler etiquette

If you touch the crawler, keep its rules: public addresses only, list calls only (never
`tools/call`), per-host limits, no credentials (never stored logins or tokens), no package
execution. Crawl output names third-party
servers; don't commit it (`reports/` is gitignored).

## Benchmarks

`scripts/benchmark_yara.py` compares our rules with Cisco's Apache-2.0 YARA rules
(`uv pip install -e '.[bench]'`). Treat the labelled-corpus numbers with care: the corpus
was built from our own mistakes, so it favours us.

## Commits and PRs

Small, focused PRs with tests. Describe what evidence motivated a detection change
(anonymised examples are fine).

## Releasing (maintainers)

1. Bump `version` in `pyproject.toml` and `sniffmcp/__init__.py`, add a `CHANGELOG.md` entry.
2. Commit, then create a GitHub release with tag `v<version>`.
3. `.github/workflows/release.yml` tests, builds, smoke-tests the wheel and publishes to
   PyPI through trusted publishing (no stored tokens; the upload carries provenance).
   The release fails if the tag and `pyproject.toml` version disagree.
