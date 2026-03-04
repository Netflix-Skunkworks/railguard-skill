# railguard-unified-scan (File-Handoff + DB Progress Tracking)

## Architecture

- **Phase 3 strategy**: 12 parallel specialized subagents, gate-conditioned dispatch
- **Findings transport**: File-handoff via `/tmp` (agents write JSON, return stubs only)
- **FP batching**: `merge-findings.py` normalizes, deduplicates, and batches findings for parallel Phase 4 FP agents
- **Progress tracking**: `scan-progress.py` wraps all phases in SQLite lifecycle tracking with crash recovery
- **Context efficiency**: Orchestrator never accumulates large findings JSON; holds only lean stubs

## What This Combines

| Feature | Source | Purpose |
|---------|--------|---------|
| File-handoff (`/tmp` writes + stubs) | orchestrated-scan | Keeps orchestrator context small |
| `merge-findings.py` (verify-p3, merge-p3, merge-p4) | orchestrated-scan | Normalize, dedup, batch for parallel FP |
| Parallel FP dispatch (N agents, one per batch of 25) | orchestrated-scan | Faster FP validation on large finding sets |
| `scan-progress.py` (phase lifecycle) | db-updates-scan | phase-start/phase-complete bracketing |
| Crash recovery (check/resume) | db-updates-scan | Recover from context compaction mid-scan |
| Agent tracking (dispatch-batch/skip/result) | db-updates-scan | Full audit trail per agent |
| Phase result persistence (gate matrix, dataflow) | db-updates-scan | Retrieve context after compaction |
| Multi-scan history | db-updates-scan | Benchmark across runs without DB deletion |

## Data Flow

```
Phase 1: Enumerate files + init progress DB
    |
    v
Phase 2: Discovery agent -> gate matrix
    |  (persisted to DB via phase-complete --result-file)
    v
Phase 2.5: Dataflow agent -> flow traces
    |  (persisted to DB via phase-complete --result-file)
    v
Phase 3: 12 agents (parallel)
    |  - Each writes to /tmp/rgs-{id}-{slug}.json
    |  - Each calls agent-result to record status in DB
    |  - Each returns lean stub to orchestrator
    v
Phase 3.5: merge-findings.py verify-p3 + merge-p3
    |  - Normalize, dedup, split into batches of 25
    |  - Writes /tmp/rgs-{id}-p4-input-{N}.json
    v
Phase 4: N FP agents (parallel, one per batch)
    |  - Each reads from batch file, writes to /tmp/rgs-{id}-p4-output-{N}.json
    |  - merge-findings.py merge-p4 -> /tmp/rgs-{id}-validated.json
    |  - store-findings --phase p4 persists final set to DB
    v
Phase 5: Report synthesis (from validated.json or DB fallback)
    v
Phase 6: Benchmark + cleanup temp files
```

## Subagents

| Phase | Agent(s) | Count |
|-------|----------|-------|
| Phase 2 | discovery-agent | 1 |
| Phase 2.5 | dataflow-agent | 1 |
| Phase 3 | 12 specialized analysis agents | 12 |
| Phase 4 | fp-validation-agent (1-N based on finding count) | 1+ |
| **Total** | | **16+** |

## Why This Should Be the Best Variant

**File-handoff keeps the orchestrator lean.** After Phase 3, the orchestrator holds
only 12 small stub objects (~2K tokens total) instead of the full findings JSON
(easily 30-50K tokens on a noisy repo). This means Phase 4 and 5 dispatch with
a clean context window.

**Parallel FP batching is the key differentiator from db-updates.** The db-updates
variant dispatches a single FP agent that reads all findings from the DB -- a
bottleneck when there are 50+ findings. This variant splits findings into batches
of 25 and dispatches N FP agents in parallel, completing Phase 4 in roughly the
time it takes to validate one batch.

**DB tracking provides crash recovery that file-handoff lacks.** If context gets
compacted mid-scan, the orchestrator can recover the gate matrix and dataflow traces
from the DB and resume from the last completed phase. The `/tmp` files persist
independently of the conversation context.

**Multi-scan history enables benchmarking.** Since all scan metadata persists to
SQLite with incrementing scan_ids, you can run multiple scans of the same repo
(different models, different configs) and compare results directly.

## When to Use

This is the recommended variant for production security scans. It combines the
accuracy benefits of the orchestrated scan (12 focused agents, parallel FP batching)
with the resilience benefits of the DB-tracked scan (crash recovery, multi-scan
history, phase result persistence).

For quick assessments or cost-sensitive scans, use `railguard-superagent-scan` or
`railguard-vulncategory-scan` instead.
