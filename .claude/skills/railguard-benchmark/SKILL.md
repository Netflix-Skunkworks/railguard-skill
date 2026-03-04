---
name: railguard-benchmark
description: >
  Store security scan findings to SQLite and compare against answer sheets
  or other scan runs. Use when asked to "store findings", "save scan results",
  "compare against answer sheet", "benchmark scan", "compare scan runs",
  "how did the scan perform", "evaluate scan accuracy", "check recall",
  "show dashboard", "benchmark dashboard", "benchmark trends", or "leaderboard".
compatibility: >
  Requires Python 3 and sqlite3 (standard library). Works in Claude Code.
metadata:
  author: Railguard Team
  version: 1.0.0
---

# Railguard Benchmark

Store scan findings to a local SQLite database and compare them against answer sheets
or other scan runs. This skill wraps the `store-and-compare.py` script with instructions
for each workflow.

## Use Case 1: Store Scan Results

After a security scan completes (from `railguard-vulncategory-scan`,
`railguard-orchestrated-scan`, or any other scan variant), persist the findings
to the benchmark database.

### Step 1: Collect Findings

The scan should have produced findings as JSON — either inline in the conversation
or written to a file. If findings are inline, write them to a temporary JSON file:

```bash
cat > /tmp/scan-findings.json << 'FINDINGS_EOF'
[findings array here]
FINDINGS_EOF
```

The JSON should be an array of finding objects, or an object with a `findings` key
containing the array. Each finding should have at minimum: `severity`, `type` (or
`vulnerability_type`), `title`, `file` (or `file_path`), `line_start`, `line_end`.

### Step 2: Store

```bash
python3 <SKILL_DIR>/scripts/store-and-compare.py store \
  --db railguard-benchmarks.db \
  --repo <REPO_PATH> \
  --findings /tmp/scan-findings.json \
  --scan-type <skill|orchestrated|production|superagent> \
  --model <model-name> \
  --notes "optional description of this scan run" \
  --duration-ms 45000 \
  --input-tokens 500000 \
  --output-tokens 12000 \
  --cost-usd 3.50 \
  --files-analyzed 42 \
  --flows-traced 87 \
  --subagent-count 15
```

For `--model`, use the model name (e.g., "claude-sonnet-4-5", "claude-opus-4-5").
This enables comparing scan accuracy across different models.

The `--duration-ms`, `--input-tokens`, `--output-tokens`, `--cost-usd`, `--files-analyzed`,
`--flows-traced`, and `--subagent-count` flags are all optional. When provided, they appear
in the dashboard view for cross-run comparison.

The script outputs a JSON confirmation with the `run_id`. Record this for future
comparisons.

### Step 3: Verify

```bash
python3 <SKILL_DIR>/scripts/store-and-compare.py list --db railguard-benchmarks.db
```

Confirm the new run appears with the correct finding count.

---

## Use Case 2: Compare Against Answer Sheet

Compare a stored scan run against a ground-truth answer sheet to measure detection
accuracy.

### Step 1: Run Comparison

```bash
python3 <SKILL_DIR>/scripts/store-and-compare.py compare \
  --db railguard-benchmarks.db \
  --run-id <RUN_ID> \
  --answer-sheet <PATH_TO_ANSWER_SHEET_MD>
```

The script outputs a JSON comparison result with:
- `summary`: precision, recall, true positives, false negatives, extra findings
- `items`: per-entry status (matched, partial, missed, correctly_not_found)
- `extra_findings`: scan findings not in the answer sheet

### Step 2: Interpret Results

Load `references/comparison-criteria.md` for the full interpretation guide.

For each comparison item, review and add explanatory notes:

**Matched items**: Verify severity agreement. If severities differ, explain why
(scanner applied mitigations, different assessment of impact, etc.).

**Partial matches**: Investigate the weak match. Was the finding reported at a
different location in the same file? Was it merged with another finding?

**Missed items**: This is the most important category. For each missed finding,
determine the root cause:
- Was the discovery gate not activated? (gate coverage gap)
- Was the file not read during data flow tracing? (file budget issue)
- Was the flow not traced to the sink? (tracing gap)
- Was the finding detected but removed by FP analysis? (FP over-removal)
- Was the pattern not recognized? (detection gap)
- Is this a dead-code finding the scanner intentionally skipped? (by design)

**Extra findings**: For each finding the scanner produced that is not in the
answer sheet:
- Is it a genuine vulnerability the answer sheet missed? (novel true positive)
- Is it a false positive? (scanner accuracy issue)
- Is it a duplicate of a matched finding from a different angle? (dedup gap)

### Step 3: Report

Present a summary:

```
## Benchmark Results: [repo name] — Run #[id]

**Precision**: [X]% ([tp] true positives / [tp + extra] total reported)
**Recall**: [X]% ([tp] true positives / [expected] expected)

### Matched: [N] findings
[List with severity comparison notes]

### Missed: [N] findings
[List with root cause explanation for each]

### Extra: [N] findings
[List with classification: novel TP, FP, or duplicate]

### FP Bait: [N/M] correctly avoided
### Dead Code: [N/M] handled correctly

### Key Gaps
[1-3 sentence summary of the biggest detection gaps and recommendations]
```

---

## Use Case 3: Compare Two Scan Runs

Compare two scan runs of the same repository to understand differences between
configurations, models, or skill versions.

### Step 1: Run Comparison

```bash
python3 <SKILL_DIR>/scripts/store-and-compare.py compare-runs \
  --db railguard-benchmarks.db \
  --run-a <RUN_ID_A> \
  --run-b <RUN_ID_B>
```

The script outputs:
- `common_findings`: found by both runs (with severity comparison)
- `only_in_run_a`: findings unique to run A
- `only_in_run_b`: findings unique to run B

### Step 2: Analyze Differences

For each finding unique to one run:
- Is it a real vulnerability the other run missed? (detection gap)
- Is it a false positive one run correctly avoided? (FP accuracy)
- Was it merged into a broader finding in the other run? (dedup difference)
- Is the severity different for common findings? (calibration gap)

### Step 3: Report

```
## Run Comparison: Run #[A] vs Run #[B]

**Run A**: [scan_type], [date], [total findings]
**Run B**: [scan_type], [date], [total findings]

### Common: [N] findings (in both runs)
[List with severity comparison where they differ]

### Only in Run A: [N] findings
[List with assessment of each]

### Only in Run B: [N] findings
[List with assessment of each]

### Summary
[Which run performed better and why]
```

---

## Database Location

By default, the database is created at `railguard-benchmarks.db` in the current
working directory. To use a shared location across scans:

```bash
export BENCH_DB=/path/to/repo/railguard-benchmarks.db
```

Then pass `--db $BENCH_DB` to all commands.

---

## Answer Sheet Format

The comparison script parses answer sheets in this markdown format:

```markdown
### PV-001: Finding Title

| Field | Value |
|-------|-------|
| **Agent** | secrets |
| **Vulnerability Type** | hardcoded_secret |
| **Category** | active |
| **File** | `app/config.py` |
| **Line Range** | 16 |
| **Expected Severity** | HIGH |
| **Expected Detection** | YES |

**Description**: ...
```

Each entry needs at minimum: an ID in the `### ID: Title` header, and table rows
for Agent/Vulnerability Type, File, Line Range, Expected Severity, and Expected
Detection (YES/NO). Category (active/dead-code/fp-bait) is optional but recommended.

---

## Use Case 4: Dashboard

View a leaderboard of all benchmark runs with derived metrics across repos,
models, and scan types.

```bash
# All repos
python3 <SKILL_DIR>/scripts/store-and-compare.py dashboard --db railguard-benchmarks.db

# Single repo
python3 <SKILL_DIR>/scripts/store-and-compare.py dashboard --db railguard-benchmarks.db --repo pixel-vault

# JSON output
python3 <SKILL_DIR>/scripts/store-and-compare.py dashboard --db railguard-benchmarks.db --format json
```

The dashboard shows:
- **Recall / Precision**: from stored comparisons
- **SevAcc**: % of matched findings where severity matches the answer sheet
- **FPBait**: false-positive bait items correctly avoided (e.g., `2/3`)
- **Dead**: dead-code findings detected (e.g., `4/5`)
- **Traces**: % of injection-type findings with a vulnerability trace
- **InTok / OutTok**: input/output tokens (if captured during store)
- **Per-Domain Recall**: breakdown by vulnerability type for the most recent run

Only runs that have been compared against an answer sheet are shown.

---

## Use Case 5: Trends

View recall and precision trends over time for a specific repository.

```bash
# Table format
python3 <SKILL_DIR>/scripts/store-and-compare.py trends --db railguard-benchmarks.db --repo pixel-vault

# JSON format
python3 <SKILL_DIR>/scripts/store-and-compare.py trends --db railguard-benchmarks.db --repo pixel-vault --format json
```

Shows runs chronologically with deltas from the previous run (e.g., `+33.7pp`,
`-0.6pp`). Useful for tracking whether scan improvements are working.

---

## Use Case 6: Compare FP Impact

Measure the value added by the FP validation agent (Phase 4) by comparing a
with-FP scan run against a without-FP scan run on the same repository.

### Prerequisites

1. Run `railguard-db-updates-orchestrated-scan` on a repo and store results
2. Run `railguard-nofp-orchestrated-scan` on the SAME repo and store results
3. Compare BOTH runs against the same answer sheet using `compare`

### Step 1: Run Comparison

```bash
python3 <SKILL_DIR>/scripts/store-and-compare.py compare-fp-impact \
  --db railguard-benchmarks.db \
  --with-fp-run-id <WITH_FP_RUN_ID> \
  --without-fp-run-id <WITHOUT_FP_RUN_ID> \
  --answer-sheet <ANSWER_SHEET_PATH>
```

### Step 2: Interpret Results

The output includes:

| Metric | Description |
|--------|-------------|
| **FP Removal Count** | How many findings the FP agent removed |
| **FP Kill Accuracy** | % of removals that were correct (not in answer sheet) |
| **Incorrectly Removed TPs** | True positives the FP agent wrongly removed |
| **Recall Delta** | `recall_withFP - recall_noFP` (negative = FP agent too aggressive) |
| **Precision Delta** | `precision_withFP - precision_noFP` (positive = FP agent adds value) |
| **Severity Drift** | Common findings with different severity; verdict vs answer sheet |
| **FP Bait Resistance** | Both runs' FP bait scores from existing comparisons |
| **Per-Domain FP Rate** | Per vuln type: count with/without FP, removals |

A `markdown_summary` field contains formatted tables for easy pasting.

### Step 3: Decision Framework

- **Kill Accuracy > 90% + Precision Delta > 0**: FP agent is working well
- **Incorrectly Removed TPs > 0**: FP agent needs tuning (removing real vulns)
- **Recall Delta < 0**: FP agent is too aggressive (hurting detection)
- **Precision Delta ~0**: FP agent has minimal impact (consider removing for cost savings)
