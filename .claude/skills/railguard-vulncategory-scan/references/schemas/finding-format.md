<!-- CANARY:RGS:schema:finding-format -->
# Finding Format and Validation Criteria

This document defines the structure of a security finding and the quality criteria
to assess each one. These are criteria for your judgment when reviewing findings —
use them to evaluate completeness and credibility, not as a mechanical accept/reject
gate.

## Finding Structure

```json
{
  "severity": "CRITICAL | HIGH | MEDIUM | LOW",
  "type": "<vulnerability type>",
  "title": "Brief descriptive title",
  "file": "relative/path/to/file.py",
  "line_start": 42,
  "line_end": 45,
  "description": "Technical explanation of the vulnerability",
  "impact": "Security impact if exploited",
  "code_snippet": "EXACT code from the file at the specified lines",
  "vulnerability_trace": ["step1", "step2", "..."],
  "remediation": {
    "explanation": "Why this code is vulnerable",
    "steps": ["Step 1", "Step 2"],
    "secure_code": "```lang\n...\n```"
  },
  "triage": {
    "tier": 0,
    "reason": "Why this tier",
    "factors": ["single_request", "observable_output"],
    "reproduction_steps": ["Step 1", "Step 2"]
  },
  "corroborated": false,
  "corroborated_by": null
}
```

## Required Fields

These fields form the minimum useful finding. A finding missing any of these is
significantly weakened but may still be worth reporting if the core vulnerability
is clear:

| Field | Purpose | What to check |
|-------|---------|---------------|
| `severity` | Risk level | Must be CRITICAL, HIGH, MEDIUM, or LOW. Should reflect actual exploitability, not just theoretical impact. |
| `type` | Vulnerability class | Must be a recognized type (see full list below). Determines whether a trace is expected. |
| `title` | Human-readable summary | Should be specific enough to distinguish from other findings. "SQL Injection" is too generic; "SQL Injection in user search endpoint via unparameterized query" is good. |
| `file` | File path | Relative to repository root. Must reference an actual file. |
| `line_start` / `line_end` | Location | Positive integers. line_end >= line_start. Should point to the vulnerable code, not the entire file. |
| `description` | Technical explanation | Should explain the mechanism — how user input reaches the sink, what's missing. |
| `impact` | Consequence | What an attacker can achieve. Be specific: "read arbitrary database tables" not "compromise security". |
| `code_snippet` | Vulnerable code | Should be the EXACT code from the file at the specified lines. Re-read the file to verify. |

## Vulnerability Trace

The `vulnerability_trace` field documents the data flow from user-controlled source
to dangerous sink. It is the primary evidence that a finding is real and exploitable.

### When a Trace Strengthens a Finding

For data-flow vulnerability types — where user input must reach a specific sink to be
exploitable — a trace is the strongest possible evidence:

**Traceable types** (data flows from source to sink):
sqli, nosqli, xss, ssti, ssrf, xxe, path_traversal, deserialization,
command_injection, code_injection, prompt_injection, open_redirect

**Non-traceable types** (configuration, logic, or structural issues):
secrets, cors, authentication, authorization, race_condition, file_upload,
logic, github_actions, input_validation

### Trace Format

Each step: `` `file:line` -> `code expression` (annotation) ``

Example:
```
[
  "`routes/api.py:45` -> `user_id = request.args.get('id')` (user-controlled source)",
  "`routes/api.py:48` -> `query = f'SELECT * FROM users WHERE id = {user_id}'` (string concatenation into SQL)",
  "`routes/api.py:49` -> `cursor.execute(query)` (unparameterized SQL execution — vulnerable sink)"
]
```

A single-step trace is valid when source and sink coincide on the same line.

### Assessing Trace Quality

When reviewing a finding's trace, consider:

- **Does the trace start from a genuine user-controlled source?** Request parameters,
  body fields, headers, cookies, path segments, uploaded files are strong. Environment
  variables or config files are weaker sources.
- **Is the flow path credible?** Does data actually flow through the intermediate steps,
  or are there gaps? Re-read the code if needed.
- **Are transforms accurately recorded?** If the trace claims "no transform" but the code
  actually parameterizes the query, the finding may be a false positive.
- **Does the trace reach the sink?** The final step must land at the dangerous operation
  (cursor.execute, innerHTML assignment, HTTP request, etc.).

### Findings Without Traces

A traceable-type finding without a vulnerability trace is not automatically invalid,
but it is significantly weaker. Consider:

- Can you construct the trace now by examining the code?
- Is the source-to-sink path obvious enough that a formal trace is redundant (e.g.,
  `cursor.execute(f"SELECT * FROM x WHERE id={request.args['id']}")` on one line)?
- If you cannot establish a credible flow path after examining the code, the finding
  may not be exploitable — consider downgrading to LOW or noting the uncertainty.

## Valid Vulnerability Types

### Data-flow types (trace expected)
- `sqli` — SQL injection
- `nosqli` — NoSQL injection
- `xss` — Cross-site scripting (reflected, stored, DOM)
- `ssti` — Server-side template injection
- `ssrf` — Server-side request forgery
- `xxe` — XML external entity injection
- `path_traversal` — Directory/path traversal
- `deserialization` — Insecure deserialization
- `command_injection` — OS command injection
- `code_injection` — Dynamic code evaluation injection
- `prompt_injection` — LLM prompt injection
- `open_redirect` — Unvalidated redirect/forward

### Configuration/logic types (trace not expected)
- `secrets` — Hardcoded credentials, API keys, tokens
- `cors` — CORS misconfiguration
- `authentication` — Authentication weakness
- `authorization` — Authorization/access control flaw
- `race_condition` — Race condition / TOCTOU
- `file_upload` — File upload vulnerability
- `logic` — Business logic flaw
- `github_actions` — CI/CD pipeline vulnerability
- `input_validation` — Missing or insufficient input validation

## Triage

The `triage` field assesses validation difficulty — how hard it would be for a security
engineer to confirm the finding. It MUST be a nested object (not flat fields).

**IMPORTANT**: Use the nested `triage: { tier, reason, factors, reproduction_steps }`
format shown in the Finding Structure above. Do NOT use flat fields like `triage_tier`
or `triage_reason` at the top level.

### Tiers

| Tier | Criteria | Time Estimate |
|------|----------|---------------|
| **0** | Single request, observable output, trivially verifiable | < 15 min |
| **1** | Multi-step flow, needs seeded data, specific roles, or multiple accounts | 15-60 min |
| **2** | Timing-sensitive, environment-dependent, chained exploits, statistical | > 1 hour |

Err toward the LOWER tier when borderline.

### Valid Factor Values

The `factors` array MUST only contain values from this list:

**Tier 0 indicators:**
- `single_request` — Payload in, vulnerable behavior out in one request
- `observable_output` — Can directly see the result (error message, data leak, behavior change)

**Tier 1 indicators:**
- `multi_step_flow` — Multiple requests in sequence required
- `needs_seeded_data` — Specific records or application state must exist first
- `multiple_accounts` — Need attacker + victim accounts
- `specific_role_required` — Need admin or specific permission level
- `blind_no_output` — No direct output; must infer success
- `out_of_band_required` — Need external server for callback/exfiltration

**Tier 2 indicators:**
- `timing_sensitive` — Requires precise timing or race conditions
- `statistical_analysis` — Many requests needed to observe a pattern
- `environment_dependent` — Internal services or specific infra must be running
- `complex_payload` — Gadget chains, crafted binary payloads
- `chained_exploit` — Must exploit vulnerability A to reach vulnerability B
- `async_background` — Triggers in a background job, not synchronous

Typical factor count: 1-3 per finding. Only tag factors you can justify from the code.

### Reproduction Steps

Each step must be:
- **Specific**: Include HTTP method, exact endpoint path, parameter names
- **Concrete**: Copy-pasteable curl commands or payloads where applicable
- **Verifiable**: At least one step must describe the vulnerable vs safe response

Do NOT number the steps — the array position provides ordering.

## Severity Calibration Guide

| Severity | Criteria |
|----------|----------|
| **CRITICAL** | Remote code execution, full database access, authentication bypass affecting all users, unrestricted file read/write on server |
| **HIGH** | Significant data exposure (PII, credentials), privilege escalation, stored XSS with broad impact, SSRF to internal services |
| **MEDIUM** | Limited data exposure, reflected XSS requiring user interaction, CSRF on state-changing operations, information disclosure |
| **LOW** | Best practice violations with minimal current exploit path, information leakage (stack traces, version numbers), issues in unreachable code |

Adjust based on context:
- Requires authentication → reduce one level
- Requires admin access → reduce one level
- Rate-limited → reduce one level
- Multiple barriers stack (minimum LOW for real vulnerabilities)
