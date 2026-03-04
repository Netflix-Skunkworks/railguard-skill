# railguard-vulncategory-scan (Monolithic Single-Agent, 4 Category Sweeps)

## Architecture

- **Execution model**: Single agent, no orchestrator, no subagent dispatch
- **Phase 3 strategy**: 4 sequential gated analysis passes (Injection, CORS, Access Control, Logic) all within one context window
- **Rule loading**: All relevant rules loaded directly by the scanning agent as needed per pass
- **Phase enforcement**: Internal todo tracking protocol (not Task tool dispatch)

## Findings Flow

All findings accumulate inline within the single agent's context:
1. Phase 3 passes report findings immediately as discovered
2. Phase 3.5 deduplicates and validates all findings in-context
3. Phase 4 performs FP analysis and remediation generation on the full set
4. Phase 5 synthesizes final report from accumulated context

No external storage (no DB, no files) until the final report.

## Phases

| Phase | Description | Strategy |
|-------|-------------|----------|
| Phase 1 | File enumeration | `enumerate-files.sh` |
| Phase 1.5 | Semgrep static analysis (optional) | `run-semgrep.sh` |
| Phase 2 | Architecture discovery + gate flags | Read manifests, entry points, routes |
| Phase 2.5 | Data flow tracing (most critical) | Up to 30 files, source-to-sink traces |
| Phase 3A | Injection sweep | SQLi, XSS, Prompt Injection, Command Injection |
| Phase 3B | CORS sweep | CORS misconfigurations |
| Phase 3C | Access control sweep | AuthN, AuthZ, Path Traversal, File Upload |
| Phase 3D | Logic sweep (always runs) | Secrets, Logic, Input Validation |
| Phase 3.5 | Validation and deduplication | Quality gate, snippet verification, semgrep correlation |
| Phase 4 | FP analysis + remediation + triage | False positive filtering, secure code examples, tier assignment |
| Phase 4.5 | Vulnerability research (optional) | Adversarial review for missed chains |
| Phase 5 | Final report | Full finding output with traces and remediation |

## Hypothesis and Tradeoffs

### Why this might win

**Cross-domain correlation for free.** Because one agent sees everything, it can
naturally connect findings across domains -- e.g., noticing that an auth bypass
(Pass 3C) enables a SQL injection (Pass 3A) that wouldn't be reachable otherwise.
The orchestrated variants can't do this; each agent is isolated and blind to other
domains' findings.

**Cheapest possible scan.** 1 LLM session = 1 set of input tokens. No orchestrator
overhead, no coordinator context, no DB tool calls. For a 50-file repo this is
probably 3-5x cheaper than the orchestrated variant.

**No dispatch latency.** Subagent dispatch has real overhead -- reading prompt
templates, constructing interpolated prompts, waiting for agent startup. This
variant just starts analyzing.

### Why this might lose

**Context exhaustion is the killer.** On a 200+ file repo, by the time you finish
Pass 3A (injection), your context is already carrying the file manifest, gate matrix,
all data flow traces, and Pass 3A findings. By Pass 3D, the model may be working
with degraded attention over earlier content. We expect to see later passes (3C, 3D)
produce shallower analysis than earlier passes (3A, 3B) on large repos.

**Sequential passes mean sequential degradation.** Each pass reads more files and
accumulates more findings. The model doesn't get a "fresh start" for each domain
like the orchestrated agents do. If it starts hallucinating or losing focus in
Pass 3B, that noise carries forward into 3C, 3D, and the FP validation.

**No parallelism.** On a repo where all gates are active, this runs 4 passes
sequentially. The orchestrated variant runs up to 10 agents in parallel. Wall-clock
time will be significantly worse for large repos.

**1 agent = 1 point of failure.** If the agent context-overflows, gets confused by
a complex codebase, or hits a tool error, the entire scan is compromised. There's
no fallback.

### Predictions (testable)

- On repos <50 files: comparable recall to orchestrated, lower cost
- On repos 50-150 files: slightly lower recall on later passes (3C/3D), similar cost
- On repos >200 files: meaningfully lower recall, especially for domains checked in
  later passes. Context compaction may drop earlier findings entirely
- FP rate: possibly lower than orchestrated (cross-domain context helps FP filtering)
  but possibly higher on large repos (attention degradation)
- Cost: ~20-30% of orchestrated variant for same repo

## Comparison Table

| Dimension | VulnCategory (this) | Orchestrated (12 agents) | SuperAgent (1 agent) | DB-Updates (12 + DB) |
|-----------|-------------------|-------------------------|---------------------|---------------------|
| LLM sessions | 1 | 16+ | 4+ | 17+ |
| Parallelism | None | Up to 10 concurrent | None | Up to 10 concurrent |
| Context isolation | None | Full per-domain | None | Full per-domain |
| Compaction resilience | None | Low (inline findings) | None | High (DB-backed) |
| Orchestrator overhead | None | Yes | Yes | Yes |
| Rule loading | Per-category-sweep (selective) | Per-agent (1 rule) | All 12 at once | Per-agent (1 rule) |
| Cross-domain correlation | Natural | None (isolated agents) | Natural | None (isolated agents) |
| Large repo suitability | Poor | Good | Moderate | Best |

## When to Use

Quick scans of small repositories (<100 files) where cost and speed matter. Also
useful as a fast triage scan before deciding whether to run the full orchestrated
variant. Not recommended for large repos or when comprehensive coverage is required.
