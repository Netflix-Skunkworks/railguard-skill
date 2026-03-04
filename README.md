# Railguard: Scan Skills

> [!WARNING]
> **Skunkworks project. Use with eyes open.**
> This is an active research effort, not production-grade tool(s). Expect rough edges:
> - **No long-term support.** All things may change without notice.
> - **Unknown coverage gaps.** Detection rules included are references, not production grade; some vulnerability classes or language patterns will be missed. Evolve and add seasoning!
> - **No false-positive guarantees.** Precision varies by repo size, language, and scan variant, expect noise.
> - **Cost unpredictability.** LLM token usage depends heavily on repo size and variant chosen; large repos can get expensive fast.
> - **Not a replacement for manual review.** Findings should be triaged by a human before acting on them.

---

## What This Is

Railguard is an experiment in LLM-driven static security analysis. This is a repository emulating the different approaches for quick evaluation leveraging Claude Code agent skills to scan source code repositories for security vulnerabilities; no runtime execution, no dynamic testing, pure read-and-reason.

The core question driving the work: **does splitting analysis across many specialized agents produce meaningfully better results than having one agent do everything?** There's no obvious right answer. More agents means more focused analysis per domain, but also more cost, more orchestration complexity, and no cross-domain correlation. Fewer agents is cheaper and simpler, but the model has to juggle more rules and may give each vulnerability class shallow attention. We're running controlled experiments to find out where the breakpoints are.

Each scan variant shares the same rule files, methodology docs, and benchmark infrastructure. The only thing that changes is how Phase 3 (vulnerability analysis) is structured.

---

## Repository Structure

```
.
├── LICENSE.md
├── README.md
├── repos/                                         # Eval target repositories
│   ├── vul-anime-rest-api/                        # Intentionally vulnerable FastAPI app
│   └── ...                                        # More to come
│
└── .claude/
    └── skills/
        ├── README.md                              # Skills-level docs (eval focus)
        │
        ├── railguard-orchestrated-scan/           # 12 parallel specialized agents (canonical baseline)
        │   ├── SKILL.md                           # Orchestrator entry point
        │   ├── references/
        │   │   ├── directives/                    # Universal agent directives (tool logging etc.)
        │   │   ├── methodology/                   # Data flow, severity, FP, triage, dedup
        │   │   ├── rules/                         # 12 vulnerability detection rules
        │   │   └── schemas/                       # Finding JSON format
        │   ├── scripts/                           # File enumeration, LSP helpers, merge, semgrep
        │   └── subagents/                         # Prompt templates per analysis domain
        │
        ├── railguard-superagent-scan/             # Single agent covering all 12 rules
        │   ├── SKILL.md
        │   ├── references/
        │   │   ├── methodology/
        │   │   ├── rules/
        │   │   └── schemas/
        │   ├── scripts/                           # File enumeration, semgrep helpers
        │   └── subagents/                         # super-agent.md
        │
        ├── railguard-vulncategory-scan/           # 4 sequential category sweeps, no subagents
        │   ├── SKILL.md
        │   ├── assets/                            # Report templates
        │   ├── references/
        │   │   ├── methodology/
        │   │   ├── rules/
        │   │   └── schemas/
        │   └── scripts/                           # File enumeration, semgrep helpers
        │
        ├── railguard-db-updates-orchestrated-scan/ # 12 agents + SQLite progress persistence
        │   ├── SKILL.md
        │   ├── references/
        │   │   ├── methodology/
        │   │   ├── rules/
        │   │   └── schemas/
        │   ├── scripts/                           # File enumeration, semgrep, scan-progress.py
        │   └── subagents/
        │
        ├── railguard-unified-scan/                # 12 agents + file-handoff FP batching + SQLite
        │   ├── SKILL.md
        │   ├── references/
        │   │   ├── directives/
        │   │   ├── methodology/
        │   │   ├── rules/
        │   │   └── schemas/
        │   ├── scripts/                           # File enumeration, merge-findings.py, scan-progress.py
        │   └── subagents/
        │
        ├── railguard-securityagentsonly-scan/     # 12 agents, no discovery/dataflow/FP phases
        │   ├── SKILL.md
        │   └── subagents/
        │
        └── railguard-benchmark/                   # Benchmark storage and comparison
            ├── SKILL.md
            ├── references/                        # Comparison criteria and scoring guidance
            ├── scripts/                           # store-and-compare.py, test suite
            └── scoresheets/                       # Answer sheets per eval repo (coming soon)
```

---

## Scan Variants

### `railguard-orchestrated-scan`: 12 Specialized Agents (canonical baseline)

Orchestrator dispatches 12 parallel subagents for Phase 3, each loading only 1-3 rule files for its domain. Each agent gets a fresh context and focused attention. Most expensive option but expected to be the most accurate, especially for niche domains (prototype pollution, prompt injection) that benefit from dedicated analysis. This is the baseline everything else is benchmarked against.

**Context management**: Phase 3 agents write findings to `/tmp` files and return only a small stub to the orchestrator, keeping the orchestrator context lean. There is no SQLite phase persistence or crash recovery. If context compaction occurs mid-scan, phase results cannot be recovered without re-running.

### `railguard-superagent-scan`: Single SuperAgent (monoprompt experiment)

Orchestrator dispatches a single Phase 3 agent that loads all 12 rule files and covers all vulnerability domains in one pass. The bet: one focused agent with all the rules is good enough, and 12 specialized agents is over-engineering. Expected to achieve comparable recall to orchestrated individual agent scans while reducing token consumption (~25-35% total of the cost of individual agents).

### `railguard-vulncategory-scan`: Vulnerability Category Sweeps (no orchestrator)

Single agent, single context window. Groups all vulnerability types into 4 gated category sweeps (Injection, Network/CORS, Access Control, Logic) and runs them sequentially without subagent dispatch. Cheapest option. Best for small repos where one agent can hold everything in context without degrading.

### `railguard-db-updates-orchestrated-scan`: 12 Agents + Progress DB

Same 12-agent dispatch as the canonical baseline, but findings persist to SQLite instead of flowing through the orchestrator's context. Subagents write to DB and return lean summaries. Solves context-accumulation on large repos. Expected to match baseline accuracy with better compaction resilience, at ~10-15% higher cost.

### `railguard-unified-scan`: 12 Agents + File-Handoff FP Batching + Progress DB

Combines the DB persistence of `db-updates` with parallel Phase 4 FP batching via `/tmp` file handoff. Phase 3 agents write findings to `/tmp` files and return lean stubs; a merge step batches findings for parallel FP agents. Best of both the orchestrated and DB-updates architectures for large repos.

**Context management**: Phase 3 agents write findings directly to `/tmp` files and return only a small stub to the orchestrator, keeping orchestrator context lean regardless of finding volume. `scan-progress.py` persists phase lifecycle state to SQLite, enabling recovery after context compaction mid-scan. The gate matrix and data flow traces are stored in the DB and can be retrieved after a compaction event without re-running earlier phases.

### `railguard-securityagentsonly-scan`: Security Agents Only (no pipeline)

12 analysis agents run unconditionally: no discovery gate, no data flow tracing, no FP validation. Exists purely as a benchmark control to measure the value of the discovery, dataflow, and FP phases. Not recommended for real use.

---

## Scan Phases (orchestrated variants)

| Phase | Name | What happens |
|-------|------|-------------|
| 1 | File Enumeration | Build manifest of source files, filter noise |
| 2 | Architecture Discovery | Detect frameworks, DBs, auth patterns; produce gate matrix |
| 2.5 | Data Flow Tracing | Trace user inputs from sources to sinks across files |
| 3 | Vulnerability Analysis | Parallel (or sequential) agents per vulnerability domain |
| 4 | FP Validation | Classify false positives, calibrate severity, deduplicate |
| 5 | Report Synthesis | Final findings with traces, remediation, and triage tiers |
| 6 | Benchmark Storage | Store results to SQLite; compare against answer sheet |

---

## Vulnerability Coverage

All variants share 12 detection rule files covering:

| Domain | Rule coverage |
|--------|--------------|
| Injection | SQL injection, OS command injection, XSS (reflected, stored, DOM) |
| CORS | Cross-origin resource sharing misconfiguration and exploitability assessment |
| Authentication | Auth bypass, weak auth, session fixation, credential handling |
| Authorization | IDOR, broken access control, privilege escalation |
| File handling | Path/directory traversal, unrestricted file upload |
| Logic | Business logic flaws, race conditions |
| Input validation | Type and format validation, injection-adjacent weaknesses |
| Secrets | Hardcoded credentials, API keys, and token exposure |
| AI/LLM | Prompt injection |

**Supported languages**: Python, JavaScript, TypeScript, Java (Go, Ruby, PHP in some variants)

> [!NOTE]
> The detection rules in `references/rules/` are baselines for evaluation, not production-grade detection logic. They cover the broad shape of each vulnerability class but are not exhaustive. Before using this scanner on real codebases, review the rules for your stack and extend them with your own expertise: tighten the patterns, add framework-specific sinks and sources, and adjust severity thresholds to match your risk model.

---

## Eval Repos & Benchmarks

Intentionally vulnerable applications with hand-cataloged ground truth for measuring scanner recall and precision. Eval repos are coming soon.

---

## Running a Scan

Run any variant by invoking the skill with a target path:

```
/railguard-orchestrated-scan /path/to/target/repo
/railguard-superagent-scan /path/to/target/repo
/railguard-vulncategory-scan /path/to/target/repo
```

---

## Running Benchmarks

```bash
# Compare a scan run against an answer sheet
python3 .claude/skills/railguard-benchmark/scripts/store-and-compare.py compare \
  --db railguard-benchmarks.db \
  --run-id <RUN_ID> \
  --answer-sheet .claude/skills/railguard-benchmark/scoresheets/<REPO>/answer-sheet.md

# Compare two scan variants head-to-head
python3 .claude/skills/railguard-benchmark/scripts/store-and-compare.py compare-runs \
  --db railguard-benchmarks.db \
  --run-id-a <ORCHESTRATED_RUN> \
  --run-id-b <SUPERAGENT_RUN>

# List all stored runs
python3 .claude/skills/railguard-benchmark/scripts/store-and-compare.py list \
  --db railguard-benchmarks.db
```

---

## Examples of Test Cases and Things We Want to Learn

1. **Orchestrated vs SuperAgent accuracy gap.** Is the 12-agent approach actually more accurate, or is one agent with all the rules close enough? If the gap is <10% recall, the cost savings of the super-agent make it the better default.
2. **Context exhaustion threshold.** At what repo size does the monolithic variant start losing findings? We think it's around 100-150 files, but need data.
3. **Niche domain coverage.** Do specialized agents catch more findings than the super-agent (individual agent architecture), and what is the threshold for repository complexity where this occurs?
4. **Cost-accuracy frontier.** Where's the knee in the curve? Is there a variant that's 90% as accurate at 30% of the cost?
5. **DB overhead vs compaction resilience.** On large repos, does the DB variant actually complete more reliably?
6. **Cross-language generalization.** Do the same rules and agents work equally well on Java as Python?
