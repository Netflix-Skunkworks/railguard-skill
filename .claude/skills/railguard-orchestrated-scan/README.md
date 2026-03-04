# railguard-orchestrated-scan (Canonical Baseline)

## Architecture

- **Phase 3 strategy**: 12 parallel specialized subagents, gate-conditioned dispatch
- **Agent granularity**: Each agent loads 1-3 rule files relevant to its domain
- **Concurrency**: Claude Code handles up to 10 concurrent agents; remainder queues automatically
- **Context isolation**: Each agent has its own context window, preventing cross-domain interference

## Findings Flow

Findings flow inline through the orchestrator's context. Each Phase 3 subagent returns
its findings as a JSON array directly in its response. The orchestrator collects and
merges all arrays before passing them to Phase 4 FP validation.

## Subagents

| Phase | Agent(s) | Count |
|-------|----------|-------|
| Phase 2 | discovery-agent | 1 |
| Phase 2.5 | dataflow-agent | 1 |
| Phase 3 | 12 specialized analysis agents | 12 |
| Phase 4 | fp-validation-agent (1-N based on finding count) | 1+ |
| **Total** | | **16+** |

## Hypothesis and Tradeoffs

### Why this should be the most accurate

**Domain-specific focus produces deeper analysis.** When an agent only cares about
SQL injection and loads only the SQL injection rule file, it can apply those rules
thoroughly without being distracted by 18 other vulnerability classes. We expect
each specialized agent to catch edge cases (second-order SQLi, stored procedure
injection) that a generalist agent would miss because it's juggling too many concerns.

**Fresh context per domain.** Each Phase 3 agent starts with a clean context containing
only: the file manifest, gate matrix, data flow traces relevant to its sink types,
and its 1-3 rule files. No accumulated findings from other passes cluttering attention.
The 15th agent gets the same quality of attention as the 1st.

**Parallel execution reduces wall-clock time.** With up to 10 concurrent agents,
a fully-gated repo gets all 12 analysis passes done in roughly the time it takes
to do 2 sequential passes. This is significantly faster than the monolithic variant
for large repos.

### Why this might not be worth the cost

**12 agents = 13x the input token overhead.** Every agent receives the file manifest,
gate matrix, and data flow traces. That's maybe 20-30K tokens of shared context
duplicated across 12 sessions. For a repo where only 6 gates are active, you are
still paying for 6 full agent sessions vs 1 session in the monolithic variant.

**No cross-domain correlation.** The SQL injection agent can't see that there's an
auth bypass 3 files away that makes an otherwise-gated injection reachable. The
path traversal agent can't see that the file it found also feeds into a command injection downstream.
Each agent is blind to findings from other domains. The FP validation phase catches
some of this, but it's post-hoc rather than during analysis.

**Orchestrator context still accumulates.** Even though each agent runs in isolation,
the orchestrator receives ALL findings back inline. On a noisy repo with 50+ raw
findings across 12 agents, the orchestrator context is heavy by the time it reaches
Phase 4. This is the problem the DB-updates variant was designed to solve.

**Dispatch overhead is real.** Reading 15 prompt templates, constructing interpolated
prompts with ACTIVE_RULES, dispatching Task calls, validating canary manifests on
return -- this orchestrator bookkeeping adds token cost and latency that doesn't
exist in the monolithic variant.

### Predictions (testable)

- Highest recall across all variants, especially for niche vulnerability classes
  (file upload, prompt injection) that benefit from focused analysis
- Cost: ~3-5x the monolithic variant for same repo (driven by duplicated context)
- Wall-clock time: faster than monolithic for large repos (parallelism), slower for
  small repos (dispatch overhead)
- FP rate: possibly slightly higher than monolithic (no cross-domain context for
  FP filtering), but FP validation phase should compensate
- On repos with many active gates (12+), this is where the accuracy advantage over
  superagent/monolithic should be most visible
- On repos with few active gates (3-5), the cost premium over superagent is hard
  to justify -- fewer domains means the superagent can handle them adequately

## When to Use

Default choice for production scans where accuracy is the priority. Best when the
repo has many active gates (diverse tech stack) and comprehensive coverage matters
more than cost.
