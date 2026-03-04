# railguard-benchmark

Stores scan findings to SQLite and compares them against hand-curated answer sheets.
This is how we measure whether a scan variant actually works -- without ground truth
comparison, we're just guessing.

## Quick Start

```bash
# After a scan finishes, store its findings:
python3 .claude/skills/railguard-benchmark/scripts/store-and-compare.py store \
  --db railguard-benchmarks.db \
  --repo repos/pixel-vault-xl \
  --findings /tmp/scan-findings.json \
  --scan-type orchestrated \
  --model claude-sonnet-4-6

# Compare against the answer sheet:
python3 .claude/skills/railguard-benchmark/scripts/store-and-compare.py compare \
  --db railguard-benchmarks.db \
  --run-id <RUN_ID> \
  --answer-sheet .claude/skills/railguard-benchmark/scoresheets/pixel-vault-xl/answer-sheet.md

# List all stored runs:
python3 .claude/skills/railguard-benchmark/scripts/store-and-compare.py list \
  --db railguard-benchmarks.db

# Compare two runs head-to-head:
python3 .claude/skills/railguard-benchmark/scripts/store-and-compare.py compare-runs \
  --db railguard-benchmarks.db \
  --run-id-a <RUN_A> \
  --run-id-b <RUN_B>
```

## Eval Repos

These are intentionally vulnerable applications with known, hand-cataloged
vulnerabilities. They exist to give us ground truth -- without them we can't
calculate recall or precision.

All eval repos live in `repos/` within this repository.

### pixel-vault (small, Python/JS)

A Flask retro game collection manager. ~29 files. SQLite + MongoDB, JWT auth,
file uploads, XML import, LLM recommendations. Small enough for the monolithic
scanner to handle in one context window. Good for quick iteration.

- **Answer sheet**: `scoresheets/pixel-vault/answer-sheet.md`
- **Vulnerabilities**: 49 total (41 active, 5 dead-code, 3 FP-bait)
- **Domains covered**: SQLi, NoSQLi, XSS, SSTI, SSRF, path traversal, file upload,
  deserialization, secrets, auth, command injection, XXE, prompt injection

### pixel-vault-xl (large, Python/JS)

Same concept as pixel-vault but significantly expanded -- modular monolith with
gateway, marketplace, tournaments, forums, streaming, modding, admin. ~144 files.
This is the stress test. Large enough to trigger context pressure in monolithic
scans and to test whether the orchestrated variants maintain quality at scale.

- **Answer sheet**: `scoresheets/pixel-vault-xl/answer-sheet.md`
- **Vulnerabilities**: 214 total (170 active, 21 dead-code, 23 FP-bait)
- **Domains covered**: Broad coverage across injection classes, auth, CORS, logic
  flaws, secrets, and business logic vulnerabilities. The repo contains entries for
  domains outside the current scanner scope (SSRF, SSTI, XXE, NoSQL, etc.) that
  serve as benchmark ground truth for future scope expansion.

### pixel-vault-java (small, Java/Spring)

Java port of pixel-vault. Tests whether the same rules and agents work across
language boundaries. Same vulnerability patterns, different framework (Spring Boot,
JPA, Thymeleaf instead of Flask, SQLAlchemy, Jinja2).

- **Answer sheet**: `scoresheets/pixel-vault-java/answer-sheet.md`
- **Vulnerabilities**: 49 total (40 active, 4 dead-code, 5 FP-bait)

### pixel-vault-xl-java (large, Java/Spring)

Java port of pixel-vault-xl. The large-repo Java stress test.

- **Answer sheet**: `scoresheets/pixel-vault-xl-java/answer-sheet.md`
- **Vulnerabilities**: 88 total (75 active, 8 dead-code, 5 FP-bait)

## Answer Sheet Format

Answer sheets are markdown tables with one row per known vulnerability:

```
| ID | Agent | Type | Category | File | Function/Route | Severity | Detection | Description |
```

- **ID**: Unique identifier (e.g., PV-001, XL-042)
- **Agent**: Which scan agent should find this (secrets, sqli, ssrf, etc.)
- **Type**: Vulnerability subtype (e.g., hardcoded_secret, stored_xss, idor)
- **Category**: `active` (real vuln), `dead-code` (vuln in uncalled code), or
  `false-positive-bait` (looks vulnerable but isn't -- tests FP filtering)
- **Detection**: `YES` (should be found) or `NO` (FP bait, should not be reported)
- **Severity**: Expected severity level

The `false-positive-bait` entries are deliberately placed to test whether the scanner
correctly identifies safe code. A scanner that flags FP bait has poor precision.
Dead-code entries test whether the scanner correctly identifies and downgrades
vulnerabilities in unreachable code.

## Metrics

The comparison produces these metrics:

| Metric | What it measures | Why it matters |
|--------|-----------------|----------------|
| **Recall** | % of known vulns found | Are we missing real issues? |
| **Precision** | % of reported findings that are real | Are we drowning users in noise? |
| **True Positives** | Correct findings | The useful work |
| **Missed** | Known vulns not found | Gaps in coverage |
| **Extra** | Findings not in answer sheet | Could be FPs or novel finds |
| **FP Bait Avoided** | Correctly ignored bait entries | FP filtering quality |
| **Dead Code Found** | Found vulns in uncalled code | Dormant code detection |
| **Severity Accuracy** | Correct severity on matched findings | Calibration quality |

## Current Results

Based on runs stored in `railguard-benchmarks.db` (all using orchestrated scan,
Claude Opus 4.6):

| Repo | Findings | TP | Recall | Precision |
|------|----------|-----|--------|-----------|
| pixel-vault | 81 | 44 | 96% | 53% |
| pixel-vault-xl (run 3) | 162 | 108 | 57% | 52% |
| pixel-vault-xl (run 4) | 130 | 83 | 43% | 49% |

Recall drops significantly from pixel-vault (96%) to pixel-vault-xl (43-57%),
confirming that larger repos stress the scanning pipeline. Precision is consistently
around 50%, meaning roughly half of reported findings are noise. Both of these are
areas the scan variant experiments aim to improve.

## How to Add a New Eval Repo

1. Create the repo with intentionally vulnerable code covering the domains you
   want to test
2. Write an answer sheet in the markdown table format above
3. Place the answer sheet in `scoresheets/<repo-name>/answer-sheet.md`
4. Run each scan variant against the repo and store results
5. Compare against the answer sheet to establish baselines
