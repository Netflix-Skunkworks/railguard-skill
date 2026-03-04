<!-- CANARY:RGS:methodology:triage-criteria -->
# Triage Criteria

Standards for assigning validation difficulty tiers and generating actionable
reproduction steps for security findings. Triage measures how hard a finding is
to **validate**, not how severe it is.

## Tier Classification

Every finding should be assigned exactly one tier.

### Tier 0 — Quick Win

Single request/response with directly observable results. A security engineer can
validate in under 5 minutes with no setup beyond a running instance.

**Criteria** (all must hold):
- One HTTP request (or trivially small sequence like login + request) triggers the behavior
- The response body, status code, or headers reveal success or failure without inference
- No special data seeding, role assignment, or environment configuration needed

**Example**: Reflected XSS via a query parameter — send a GET with a script payload,
check if it appears unescaped in the response.

### Tier 1 — Moderate Setup

Requires non-trivial setup but uses standard tooling. Expect 15-60 minutes including
preparation.

**Criteria** (one or more):
- Multi-step flow (e.g., create a resource, then exploit it)
- Requires seeded data (specific database records, uploaded files)
- Requires multiple accounts (attacker + victim) or specific roles
- Requires authentication or session setup beyond a simple login

**Example**: Stored XSS — create a comment with a payload (step 1), log in as a
different user and view the page (step 2), observe script execution.

### Tier 2 — Assessment-Level

Environment-dependent, timing-sensitive, or requires complex/chained payloads. Could
take hours and may need specialized infrastructure.

**Criteria** (one or more):
- Timing-sensitive (race conditions, TOCTOU)
- Requires internal services, queues, caches, or specific infrastructure
- Complex or chained payloads (deserialization gadget chains, multi-stage exploits)
- Statistical analysis needed (many requests to observe a pattern)
- Exploit requires triggering async/background processing

**Example**: Race condition in coupon redemption — requires concurrent requests with
precise timing and statistical observation of outcomes.

**Borderline rule**: If uncertain between two tiers, assign the lower tier.

## Factor Tags

Tag ONLY factors you can justify from the code context.

### Available Factors

**Tier 0 indicators:**
- `single_request` — payload in, vulnerable behavior out
- `observable_output` — can directly see the result in the response

**Tier 1 indicators:**
- `multi_step_flow` — multiple requests in sequence
- `needs_seeded_data` — specific records or state must exist
- `multiple_accounts` — need attacker + victim accounts
- `specific_role_required` — need admin or specific permission level

**Tier 1-2 indicators:**
- `blind_no_output` — no direct output; need inference or side channels
- `out_of_band_required` — need external server for callback (SSRF, blind XXE)

**Tier 2 indicators:**
- `timing_sensitive` — requires precise timing or concurrent requests
- `statistical_analysis` — many requests needed to observe a pattern
- `environment_dependent` — internal services, queues, or caches must be running
- `complex_payload` — gadget chains, crafted serialization payloads
- `chained_exploit` — must exploit vulnerability A to reach vulnerability B
- `async_background` — triggers in a background job or async worker

### Constraints
- `single_request` and `multi_step_flow` CANNOT coexist
- `observable_output` and `blind_no_output` CANNOT coexist
- Tier 0 findings should include `single_request` and/or `observable_output`
- 2-3 factors is typical; more than 4 is unusual

## Reproduction Steps

### Quality Requirements

- **Specificity**: Every step must include HTTP method, endpoint path, and relevant
  parameter or field names. No vague "send a malicious request."
- **Payloads**: Include concrete, copy-pasteable curl commands or request bodies with
  realistic values using actual parameter names from the code.
- **Observable result**: At least one step must describe what the vulnerable response
  looks like vs. the safe response.
- **Inline code**: Use backticks for endpoint paths, parameter names, header values.
- **Self-contained**: A pentester should follow the steps without reading source code.

### Step Count
- Tier 0: 2-3 steps
- Tier 1: 3-5 steps
- Tier 2: 4-7 steps (more than 7 suggests the steps are padded)

### Good vs Bad Steps

Good: "Send `POST /api/users/search` with body `{"query": "admin' OR 1=1--", "limit": 10}` — if vulnerable, the response returns all users instead of only matching ones."

Bad: "Inject SQL payload into the search endpoint."

## Triage Reason

- Maximum 1-2 sentences
- Must reference the specific code pattern, endpoint, or architectural property
- Do NOT restate finding description, severity, or impact
- Use backtick inline code for function names, endpoints, or variables
