# railguard-db-updates-orchestrated-scan (Progress DB Experiment)

## Architecture

- **Phase 3 strategy**: Same 12 parallel specialized subagents as canonical baseline
- **Key difference**: Findings persist to SQLite `scan-progress.db` instead of flowing inline
- **Subagents write directly to DB** via `scan-progress.py` and return only lean summaries (~100 tokens)
- **Orchestrator reads from DB** when needed via `get-phase-result` and `get-findings`

## Findings Flow

1. Phase 3 subagents write findings directly to progress DB (`store-findings --phase p3`)
2. Subagents return only a lean summary with counts and canary status
3. Orchestrator does NOT receive full findings in context
4. Phase 4 FP validation reads from DB (`get-findings --phase p3`)
5. Phase 5 report agent reads from DB (`get-findings --phase p4`)

## Additional Components

| Component | Purpose |
|-----------|---------|
| `scripts/scan-progress.py` | SQLite progress DB manager (init, phase tracking, finding storage/retrieval) |
| `scan-progress.db` | Per-repo SQLite database storing scan state, phases, and findings |
| Large repo mode | For repos >200 files, all results stored in DB to avoid context bloat |

## Hypothesis and Tradeoffs

### The problem this solves

The canonical orchestrated variant has a hidden failure mode: **context accumulation
in the orchestrator**. After 12 agents return their findings, the orchestrator is
carrying the full JSON output of every agent (easily 30-50K tokens of findings on
a noisy repo) plus the original manifest, gate matrix, and data flows. If context
gets compacted at this point, findings can be silently dropped.

This variant keeps the orchestrator lean by routing findings through SQLite. The
orchestrator never sees the full findings -- it gets ~100 token summaries ("found 3
SQLi, 1 CRITICAL, canary complete") and reads from DB only when needed downstream.

### Why this might win

**Compaction-proof by design.** If the orchestrator's context gets compacted mid-scan
(which happens on large repos), it can recover everything from the progress DB: gate
matrix, data flow traces, all Phase 3 findings, scan metadata. The `check` command
detects interrupted scans and resumes from the last completed phase. This is critical
for repos that push context limits.

**Orchestrator context stays small.** Instead of accumulating 30-50K tokens of findings
inline, the orchestrator carries only lean summaries (~1.5K total for 12 agents).
This means Phase 4 and Phase 5 get dispatched with a clean context, and the
orchestrator has more room for error handling and coordination logic.

**Enables cross-scan benchmarking.** Since all findings persist to SQLite with scan IDs,
you can run multiple scans of the same repo (different models, different configs) and
compare results directly from the DB. The `list-scans` command shows all historical
scans.

### Why this might not be worth the complexity

**More tool calls = more tokens.** Every `phase-start`, `phase-complete`,
`store-findings`, `get-findings`, `agent-dispatch-batch`, and `agent-skip` call adds
token overhead. For a fully-gated scan, that's roughly 20-30 extra Bash tool calls
compared to the canonical variant. Each one costs ~200-500 tokens for the command +
output. Total overhead: ~5-10K tokens.

**DB is another failure point.** If `scan-progress.py` has a bug, or the SQLite file
gets corrupted, or a subagent fails to write its findings, the data is lost. With the
canonical inline variant, findings are in the conversation context -- no external
dependency to break.

**Subagents need more instruction.** Each subagent prompt must include DB connection
details (PROGRESS_DB, PROGRESS_SCRIPT, SCAN_ID, AGENT_NAME) and instructions for
storing findings. This makes the prompts ~500 tokens longer and adds a failure mode
where the agent forgets or misformats the store command.

**Same accuracy, more cost.** Since the agent dispatch and rule loading is identical
to the canonical baseline, we don't expect any accuracy improvement. The benefits are
purely operational (compaction resilience, context efficiency). On small repos where
compaction isn't an issue, this is strictly worse on cost with no accuracy benefit.

### Predictions (testable)

- Accuracy: identical to canonical baseline (same agents, same rules, same gates)
- Cost: ~10-15% higher than canonical baseline (DB tool call overhead)
- On repos >200 files: this should complete successfully where canonical baseline
  might lose findings to compaction
- On repos <100 files: no meaningful benefit over canonical baseline, just added cost
- Context high-water mark in orchestrator: ~60-70% lower than canonical baseline
- Compaction recovery: should successfully resume from any interrupted phase

## When to Use

Large repositories (>200 files) or any scan where context compaction is a real risk.
Also useful when you need to benchmark multiple scan configurations against the same
repo, since all results accumulate in the same DB.
