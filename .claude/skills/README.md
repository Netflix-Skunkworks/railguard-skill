# Railguard: Scan Skills

## What we're doing

We're evaluating different approaches to LLM-driven security scanning to find the
best tradeoff between **accuracy** (recall, precision) and **cost** (tokens, sessions,
wall-clock time). The core question: does splitting analysis across many specialized
agents produce meaningfully better results than having one agent do everything?

There's no obvious right answer. More agents means more focused analysis per domain,
but also more cost, more orchestration complexity, and no cross-domain correlation.
Fewer agents means cheaper and simpler, but the model has to juggle more rules and
may give each vulnerability class shallow attention. We're running controlled
experiments to find out where the breakpoints are.

Each scan variant below shares the same rule files (12 vulnerability detection rules),
the same methodology docs (data flow tracing, severity assessment, FP analysis), and
the same benchmark infrastructure. The only thing that changes is how Phase 3
(vulnerability analysis) is structured.

## Scan Variants

### `railguard-vulncategory-scan/` -- Vulnerability Category Sweeps (no orchestrator)

Single agent, single context window. Groups all 12 vulnerability domains into 4
gated category sweeps (Injection, CORS, Access Control, Logic) and
runs them sequentially without subagent dispatch. Cheapest option. Best for
small repos where one agent can hold everything in context without degrading.
Expected to lose accuracy on large repos as context fills and later passes get
less attention.

### `railguard-orchestrated-scan/` -- 12 Specialized Agents (canonical baseline)

Orchestrator dispatches 12 parallel subagents for Phase 3, each loading only 1-3
rule files for its domain. Each agent gets a fresh context and focused attention.
Most expensive option but expected to be the most accurate, especially for niche
domains (file upload, prompt injection) that benefit from dedicated
analysis. This is the baseline we benchmark everything else against.

### `railguard-superagent-scan/` -- Single SuperAgent (monoprompt experiment)

Orchestrator dispatches a single Phase 3 agent that loads all 12 rule files and
covers all vulnerability domains in one pass. The bet: one focused
agent with all the rules is good enough, and 12 specialized agents is
over-engineering. Expected to achieve ~80-90% of orchestrated recall at ~25-35%
of the cost. The open question is whether niche domains get adequate attention.

### `railguard-db-updates-orchestrated-scan/` -- 12 Agents + Progress DB

Same 12-agent dispatch as the canonical baseline, but findings persist to SQLite
instead of flowing through the orchestrator's context. Subagents write to DB and
return lean summaries. Solves the context-accumulation problem on large repos where
12 agents returning full findings can overwhelm the orchestrator. Expected to match
baseline accuracy with better compaction resilience, at ~10-15% higher cost (DB
tool calls).

## Eval Repos

We built intentionally vulnerable applications with hand-cataloged ground truth.
Without these, we'd have no way to measure recall or precision -- we'd just be
eyeballing output and hoping.

All eval repos live in `repos/` within this repository.

### pixel-vault (small Python/JS, ~29 files)

Flask retro game collection manager. SQLite + MongoDB, JWT auth, file uploads, XML
import, LLM recommendations. Small enough that any scan variant should handle it
comfortably. The "can you find the obvious stuff?" test.

**49 known vulnerabilities** (41 active, 5 dead-code, 3 FP-bait)

### pixel-vault-xl (large Python/JS, ~144 files)

Same concept but massively expanded -- gateway, marketplace with auctions,
tournaments, forums, mod support, streaming, admin dashboard. This is the stress
test. Covers broad vulnerability coverage with emphasis on injection chains,
authentication, and business logic flaws in the marketplace/wallet system.
Note: the repo contains vulnerabilities in domains outside current scanner scope
(SSRF, SSTI, race conditions, etc.) preserved as ground truth for future benchmarking.

**214 known vulnerabilities** (170 active, 21 dead-code, 23 FP-bait)

### pixel-vault-java (small Java/Spring, ~49 vulns)

Java/Spring Boot port of pixel-vault. Same vulnerability patterns, different
framework. Tests cross-language rule generalization.

**49 known vulnerabilities** (40 active, 4 dead-code, 5 FP-bait)

### pixel-vault-xl-java (large Java/Spring, ~88 vulns)

Java port of pixel-vault-xl. Large-repo Java stress test.

**88 known vulnerabilities** (75 active, 8 dead-code, 5 FP-bait)

### Why the FP bait matters

Each eval repo includes `false-positive-bait` entries -- code that looks vulnerable
but is actually safe (parameterized queries, properly escaped output, validated
input). A scanner that flags these has poor precision. This directly tests the FP
validation phase (Phase 4) across all scan variants.

### Why dead-code entries matter

Vulnerabilities in uncalled functions should be found but reported at reduced
severity. This tests whether scan variants can distinguish reachable from
unreachable code -- a nuance that affects practical triage.

## Answer Sheets (Scoresheets)

Answer sheets are the ground truth for each eval repo. They live in:

```
railguard-benchmark/scoresheets/
  pixel-vault/answer-sheet.md          # 49 vulns
  pixel-vault-xl/answer-sheet.md       # 214 vulns
  pixel-vault-java/answer-sheet.md     # 49 vulns
  pixel-vault-xl-java/answer-sheet.md  # 88 vulns
```

Format: markdown table with columns for ID, agent, type, category, file, severity,
expected detection. See `railguard-benchmark/README.md` for format details and
instructions on adding new eval repos.

## Evaluation Infrastructure

### `railguard-benchmark/` -- Benchmark Storage and Comparison

Stores scan findings to SQLite (`railguard-benchmarks.db`) and compares them against
answer sheets. Every scan variant's final phase writes to this shared DB, enabling
apples-to-apples comparison across variants, models, and configurations.

Key metrics: recall, precision, true positives, missed findings, extra findings,
FP bait avoidance, dead code detection, severity accuracy.

### Running a full evaluation

```bash
# 1. Scan the repo with any variant (e.g., /railguard-orchestrated-scan repos/pixel-vault-xl)
# 2. The scan's Phase 6 automatically stores results and runs comparison
# 3. To manually compare:
python3 .claude/skills/railguard-benchmark/scripts/store-and-compare.py compare \
  --db railguard-benchmarks.db \
  --run-id <RUN_ID> \
  --answer-sheet .claude/skills/railguard-benchmark/scoresheets/pixel-vault-xl/answer-sheet.md

# 4. To compare two different scan variants head-to-head:
python3 .claude/skills/railguard-benchmark/scripts/store-and-compare.py compare-runs \
  --db railguard-benchmarks.db \
  --run-id-a <ORCHESTRATED_RUN> \
  --run-id-b <SUPERAGENT_RUN>

# 5. List all stored runs:
python3 .claude/skills/railguard-benchmark/scripts/store-and-compare.py list \
  --db railguard-benchmarks.db
```

### Current baselines

All runs so far used the orchestrated variant with Claude Opus 4.6:

| Repo | Findings | True Positives | Recall | Precision |
|------|----------|----------------|--------|-----------|
| pixel-vault | 81 | 44 | 96% | 53% |
| pixel-vault-xl (run 3) | 162 | 108 | 57% | 52% |
| pixel-vault-xl (run 4) | 130 | 83 | 43% | 49% |

The recall drop from pixel-vault (96%) to pixel-vault-xl (43-57%) tells us
something is breaking at scale. Precision hovering around 50% means half the
reported findings are noise. Both are areas the variant experiments aim to improve.

## What we expect to learn

The key experiments, roughly in priority order:

1. **Orchestrated vs SuperAgent accuracy gap.** Is the 12-agent approach actually
   more accurate, or is one agent with all the rules close enough? If the gap is
   <10% recall, the cost savings of the super-agent make it the better default.

2. **Context exhaustion threshold.** At what repo size does the monolithic variant
   start losing findings? We think it's around 100-150 files, but need data.

3. **Niche domain coverage.** Do specialized agents catch more ,
   file upload, and prompt injection findings than the super-agent? These are the
   domains most likely to benefit from focused analysis.

4. **Cost-accuracy frontier.** Plot recall vs cost across all 4 variants on the
   same repos. Where's the knee in the curve? Is there a variant that's 90% as
   accurate at 30% of the cost?

5. **DB overhead vs compaction resilience.** On large repos, does the DB variant
   actually complete more reliably? Is the 10-15% cost premium worth it?

6. **Cross-language generalization.** Do the same rules and agents work equally
   well on Java as Python? The pixel-vault-java variants test this.

## Shared Components

All scan variants share these reference materials (identical copies):

| Component | Count | Purpose |
|-----------|-------|---------|
| `references/rules/` | 12 files | Vulnerability detection rules (SQLi, XSS, CORS, etc.) |
| `references/methodology/` | 6 files | Data flow tracing, severity, FP analysis, triage, dedup |
| `references/schemas/` | 1 file | Finding JSON format specification |
| `scripts/enumerate-files.sh` | 1 file | Phase 1 file enumeration |
| `scripts/run-semgrep.sh` | 1 file | Optional static analysis baseline |

## Quick Comparison

| Variant | Phase 3 Agents | Parallelism | Context Isolation | Cross-Domain | Cost | Expected Recall |
|---------|---------------|-------------|-------------------|--------------|------|----------------|
| VulnCategory | 0 (5 category sweeps) | None | None | Yes | Lowest | Good (small repos) |
| Orchestrated | 20 | Up to 10 | Full | None | Highest | Highest |
| SuperAgent | 1 | None | None | Yes | ~30% of orchestrated | ~80-90% of orchestrated |
| DB-Updates | 20 | Up to 10 | Full | None | ~110% of orchestrated | Same as orchestrated |
