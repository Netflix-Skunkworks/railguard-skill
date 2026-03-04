# railguard-securityagentsonly-scan (Benchmark Control)

## Purpose

This variant exists as a **benchmark control group** to measure the concrete value
of the orchestrated scan's upstream phases: discovery (gate evaluation), data flow
tracing, false positive analysis, and triage. By stripping those features and running
only the raw security analysis agents, we can directly compare:

- **Precision**: How many more false positives does the agents-only variant produce
  without FP validation removing framework-protected, test-only, and unreachable code?
- **Recall**: Does the orchestrated scan's gate-based agent selection miss findings
  by skipping agents, or does discovery correctly identify which domains are relevant?
- **Churn**: How much noise do unconditional agents produce on domains that don't
  exist in the repo (e.g. agent on a Python-only repo)?
- **Cost**: What's the token overhead of running all 12 agents unconditionally vs
  only the gate-activated subset?
- **Accuracy**: Do pre-traced data flows from Phase 2.5 improve agent analysis quality,
  or can agents trace flows independently just as well?

## What This Variant Removes

| Feature | Orchestrated Scan | This Variant |
|---------|-------------------|--------------|
| Discovery (gate evaluation) | Phase 2: 19 gate flags determine which agents run | Removed -- all 12 agents run unconditionally |
| Data flow tracing | Phase 2.5: Pre-traces inputs to sinks, feeds flows to agents | Removed -- agents must self-trace |
| Gate-conditional dispatch | Agents only run if their gate is active | Removed -- all agents always run |
| False positive analysis | Phase 4: Classifies FPs, removes framework-protected findings | Removed -- raw findings reported |
| Severity recalibration | Phase 4: Adjusts severity based on context | Removed -- agent-assigned severity used as-is |
| Deduplication | Phase 4: Cross-agent overlap resolution | Basic only (same file + line + type) |
| Remediation generation | Phase 4: Secure code examples per finding | Removed |
| Triage tier assignment | Phase 4: Tier 0/1/2 with reproduction steps | Removed |

## What This Variant Keeps

- **Phase 1**: File enumeration (needed for agents to know what to read)
- **All 12 Phase 3 agents**: Each loads domain-specific rules and analyzes independently
- **Canary token verification**: Rule loading verification remains
- **Report synthesis**: Raw findings with basic deduplication
- **Benchmark storage**: Findings stored with scan-type `securityagentsonly` for comparison

## Expected Outcomes (Hypotheses)

### Higher FP Rate
Without FP validation, we expect significantly more false positives:
- Template engine auto-escaping not recognized (XSS in Jinja2 with autoescaping ON)
- ORM parameterization not recognized (SQLi on `Model.query.filter_by()`)
- Test/fixture code reported as production vulnerabilities
- Encrypted/placeholder secrets flagged (vault://, "changeme")

### Unnecessary Agent Waste
Without gates, agents run on domains that don't exist:
- File upload agent on a repo with no multipart handling
- CI/CD agent on a repo with no `.github/workflows/`

This demonstrates the cost savings from gate-conditional dispatch.

### Lower Trace Quality
Without pre-traced data flows from Phase 2.5, agents must independently trace
inputs to sinks. We expect:
- Some agents will skip tracing or produce shallow traces
- Cross-file flow tracing will be less thorough (each agent independently discovers
  the same entry points rather than receiving pre-traced flows)
- Inconsistent trace formats across agents

### No Severity Context
Without severity recalibration:
- MD5 password hashing may be reported as LOW instead of HIGH
- Dormant code may keep its original severity without "dormant" reduction
- Auth-protected endpoints won't get barrier-based severity reduction

## Architecture

```
Phase 1: File Enumeration
    |
    v
Phase 2: ALL 12 Agents (unconditional, parallel)
    |  - No gates, no flow context
    |  - Each agent independently reads + analyzes
    |
    v
Phase 3: Report (raw findings, basic dedup only)
    |
    v
Phase 4: Benchmark Storage + Comparison
```

**Total agents**: 12 (always, no variance)

Compare to orchestrated scan: 16+ agents (1 discovery + 1 dataflow + 3-13 gated
analysis + 1+ FP validation), but only the relevant subset runs.

## When to Use

Use this variant exclusively for benchmarking. It should NOT be used for production
security scans because:

1. Raw findings include false positives that waste developer time
2. No remediation guidance means developers must research fixes themselves
3. No triage means no prioritization of what to validate first
4. Unnecessary agents waste tokens on irrelevant domains
5. No severity recalibration means misleading risk assessment

For production scans, use `railguard-orchestrated-scan` (best accuracy) or
`railguard-superagent-scan` (lower cost alternative).

## Benchmark Comparison Workflow

1. Run this scan on a target repo with an answer sheet
2. Run the orchestrated scan on the same repo
3. Compare using the benchmark dashboard:
   ```
   /railguard-benchmark dashboard
   ```
4. Key metrics to compare:
   - **Recall**: Should be similar (agents find the same vulns)
   - **Precision**: Orchestrated should be significantly higher (FP removal)
   - **Extra Findings**: Agents-only should have many more (FPs + irrelevant domains)
   - **Cost**: Agents-only may be higher (12 agents always vs gated subset)
   - **Duration**: Agents-only may be similar (no discovery/dataflow overhead,
     but more agents running)
