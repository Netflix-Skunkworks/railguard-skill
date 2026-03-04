# railguard-superagent-scan (Monoprompt Experiment)

## Architecture

- **Phase 3 strategy**: Single SuperAgent replaces all 12 specialized Phase 3 agents
- **Rule loading**: All 12 rule files loaded into one context
- **Gate filtering**: SuperAgent uses the gate matrix internally to skip inactive domains
- **Single dispatch**: One `Task()` call instead of 12

## Findings Flow

Findings flow inline through a single agent response. The SuperAgent returns all
findings as one JSON array covering all vulnerability domains. This is then passed
to Phase 4 FP validation as normal.

## Subagents

| Phase | Agent(s) | Count |
|-------|----------|-------|
| Phase 2 | discovery-agent | 1 |
| Phase 2.5 | dataflow-agent | 1 |
| Phase 3 | super-agent (all 12 domains) | 1 |
| Phase 4 | fp-validation-agent (1-N based on finding count) | 1+ |
| **Total** | | **4+** |

## Hypothesis and Tradeoffs

### The bet

This is a bet that **one focused agent with all the rules is good enough**, and that
the 12-agent orchestrated approach is over-engineering that costs 3-5x more without
proportional accuracy gains. If the super-agent achieves 90%+ of the orchestrated
variant's recall at 30% of the cost, the orchestrated variant is hard to justify
for most use cases.

### Why this might work better than expected

**50K tokens of rules is within comfortable attention range.** Modern models handle
100K+ context well. Loading 12 rule files plus a file manifest and
data flow traces still leaves plenty of room for analysis. The rules are structured
reference material, not noisy conversation history -- models are good at applying
structured rules.

**Cross-domain correlation for free.** Like the monolithic variant, the super-agent
sees all domains simultaneously. It can notice that an auth bypass enables a SQL
injection, or that an auth bypass and path traversal share the same input path. The 12-agent variant
can't do this.

**Still has orchestrator quality gates.** Unlike the monolithic variant, this still
uses the full orchestrator framework: separate discovery agent, separate dataflow
agent, separate FP validation. Phase 3 is the only thing that changes. So we
still get quality gates on gate evaluation, data flow tracing, and FP filtering.

**Significant cost reduction.** 1 Phase 3 session instead of 15. Even accounting for
the super-agent's larger context (50K rules), total Phase 3 cost should be ~25-35%
of the orchestrated variant because we're not duplicating the manifest/gate-matrix/
dataflow-traces across 15 separate sessions.

### Why this might lose

**Attention dilution is the real risk.** When an agent loads 12 rule files and has
to check 12 vulnerability domains, it may give each domain only cursory attention.
The SQL injection agent in the orchestrated variant reads 2 rule files and thinks
about nothing else. The super-agent reads 12 rule files and has to context-switch
across all domains. We expect to see shallower analysis per domain, especially for
niche categories (file upload, prompt injection) that require careful
pattern matching.

**Long output = degraded tail quality.** If the super-agent finds 30+ issues across
multiple domains, the output gets long. Models tend to produce lower-quality output
toward the end of long responses. Findings reported in the first domains analyzed
may be higher quality than findings reported last. This is a well-known issue with
long-form generation.

**No parallelism.** The orchestrated variant runs 10 agents simultaneously. The
super-agent is a single sequential pass. For a fully-gated repo, wall-clock time
for Phase 3 could be 3-5x longer (one agent doing all the work vs 10 doing it
in parallel).

**Single point of failure.** If the super-agent gets confused, context-overflows,
or produces malformed output, ALL domains are affected. With 12 agents, a failure
in the  agent doesn't affect SQL injection results.

**Rule file conflicts.** Some rules may have contradictory or overlapping guidance.
For example, the input-validation rules and the SQL injection rules both discuss
parameterized queries. When loaded together, the agent might apply the wrong
heuristic or get confused about which rule takes precedence. Specialized agents
avoid this because they only see their own rules.

### Predictions (testable)

- Recall on "always-on" domains (XSS, secrets, input validation, logic): should be
  comparable to orchestrated (these get attention regardless)
  10-30% lower recall than orchestrated, because the super-agent gives them less
  focused attention
- Overall recall: ~80-90% of orchestrated variant
- Cost: ~25-35% of orchestrated variant
- Wall-clock time: faster than orchestrated for small repos (no dispatch overhead),
  slower for large repos (no parallelism)
- FP rate: possibly lower (cross-domain context helps), possibly higher (attention
  dilution causes sloppier analysis). Need data.
- Sweet spot: repos with 3-6 active gates. Enough domains to benefit from single-
  context correlation, few enough that the super-agent isn't overwhelmed

## Comparison vs Orchestrated Baseline

| Dimension | Orchestrated (12 agents) | SuperAgent (1 agent) |
|-----------|-------------------------|---------------------|
| Phase 3 LLM sessions | 12 | 1 |
| Rule tokens per agent | ~3-8K | ~50K |
| Shared context duplication | 15x (manifest, gates, flows) | 1x |
| Parallelism | Up to 10 concurrent | None (single agent) |
| Domain isolation | Full | None |
| Cross-domain correlation | None | Natural |
| Failure blast radius | 1 domain | All domains |
| Niche domain depth | Deep (focused) | Shallow (diluted) |
| Expected recall | Highest | ~80-90% of orchestrated |
| Expected cost | Highest | ~25-35% of orchestrated |

## When to Use

Cost-sensitive scans, quick assessments, or repos with few active gates (3-6 domains).
Good for getting a fast directional read before deciding whether to run the full
orchestrated variant. Not recommended for repos with 10+ active gates where niche
domain coverage matters.
