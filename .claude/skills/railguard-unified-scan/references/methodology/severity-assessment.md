<!-- CANARY:RGS:methodology:severity-assessment -->
# Severity Assessment

Guide for calibrating vulnerability severity based on actual exploitability, impact,
and contextual factors. Severity should reflect the real-world risk, not the theoretical
maximum for a vulnerability class.

## Baseline Severity by Vulnerability Class

These are starting points — adjust based on context.

| Class | Typical Baseline | Rationale |
|-------|-----------------|-----------|
| Remote Code Execution (command_injection, code_eval, deserialization) | CRITICAL | Full system compromise |
| SQL Injection (read/write arbitrary data) | CRITICAL | Full database access |
| SQL Injection (limited scope, parameterized elsewhere) | HIGH | Bounded data access |
| Authentication Bypass | CRITICAL | Unrestricted access |
| Stored XSS (broad impact, admin panel) | HIGH | Persistent, wide reach |
| Reflected XSS (requires victim click) | MEDIUM | Requires social engineering |
| SSRF to internal services / cloud metadata | CRITICAL | Internal network access |
| SSRF to external only (no internal access) | MEDIUM | Limited impact |
| XXE with file read | HIGH | Sensitive file disclosure |
| XXE with DTD only (no file read confirmed) | MEDIUM | Potential information leak |
| Path Traversal (read arbitrary files) | HIGH | Sensitive data exposure |
| Path Traversal (write files) | CRITICAL | Potential RCE via file overwrite |
| SSTI | CRITICAL | Typically leads to RCE |
| IDOR / Horizontal access control | HIGH | Unauthorized data access |
| Vertical privilege escalation | HIGH-CRITICAL | Depending on privilege gap |
| Hardcoded secrets (API keys, passwords) | HIGH | Credential compromise |
| Hardcoded secrets (non-sensitive, test values) | LOW | Minimal risk |
| CORS misconfiguration (credentials + reflected origin) | HIGH | Cross-origin data theft |
| CORS misconfiguration (no credentials) | MEDIUM | Limited cross-origin risk |
| Race condition (financial/state-changing) | HIGH | Double-spend, state corruption |
| Race condition (informational) | LOW | Limited impact |
| Logic vulnerability (payment/auth bypass) | HIGH-CRITICAL | Business impact |
| Logic vulnerability (minor workflow skip) | MEDIUM | Limited impact |
| GitHub Actions (pwn request, no mitigations) | CRITICAL | Repository compromise |
| GitHub Actions (expression injection, push-only) | MEDIUM | Internal attacker only |

## Contextual Adjustments

### Factors That Reduce Severity (one level each, stack cumulatively)

| Factor | Reduction | Rationale |
|--------|-----------|-----------|
| Requires authentication | -1 level | Limits attacker pool |
| Requires admin/privileged access | -1 level | Significantly limits attacker pool |
| Rate-limited endpoint | -1 level | Slows exploitation |
| Network isolation (internal only) | -1 level | Not internet-reachable |
| WAF or input filter in front | -1 level | Additional barrier (may be bypassable) |
| Read-only impact (no data modification) | -1 level | Reduced consequence |

**Minimum**: LOW. Never reduce below LOW for real vulnerabilities.

### Factors That Increase Severity

| Factor | Increase | Rationale |
|--------|----------|-----------|
| Internet-facing, unauthenticated | +1 level if not already at baseline | Maximum exposure |
| Handles PII/financial data | +1 level if context warrants | Regulatory and business impact |
| Chained with another vulnerability | +1 level | Combined impact exceeds individual |
| Automated exploitation possible | Consider if not already factored | Speed and scale of attack |

## Severity Definitions

| Level | Definition |
|-------|-----------|
| **CRITICAL** | Immediate, high-impact exploitation possible. Remote code execution, full database access, authentication bypass affecting all users, unrestricted file read/write. Exploit requires no special access or conditions. |
| **HIGH** | Significant security impact with some constraints. Data exposure (PII, credentials), privilege escalation, stored XSS with broad impact, SSRF to internal services. May require authentication or specific conditions. |
| **MEDIUM** | Moderate impact requiring user interaction or specific conditions. Reflected XSS, CSRF on state-changing operations, information disclosure, limited-scope injection. |
| **LOW** | Minimal current impact. Best practice violations, information leakage (stack traces, version numbers), vulnerabilities in unreachable code, issues requiring complex chaining. |

## Common Miscalibrations

These are specific cases where default analysis frequently assigns the wrong severity.
Apply these overrides after determining the baseline.

| Finding Pattern | Correct Severity | Common Mistake | Rationale |
|----------------|-----------------|----------------|-----------|
| MD5/SHA1 for password hashing | HIGH | Often rated LOW | Cryptographically broken for passwords. No salting or key stretching. Billions of hashes/second on modern hardware. |
| JWT without expiration claim | MEDIUM | Often overlooked | Tokens valid forever cannot be revoked after theft. |
| NoSQL `$where` with user input | CRITICAL | Often rated HIGH | Enables server-side JavaScript execution, not just data access. |
| `pickle.loads` / `yaml.load` (unsafe) on untrusted data | CRITICAL | Sometimes downgraded for dormant code | Even dormant functions with public API names need only one route call to activate. |
| IDOR / missing ownership checks on state-changing operations | HIGH | Sometimes rated MEDIUM | Modifying another user's email enables account takeover via password reset. |
| Race conditions on financial operations (wallet, purchases) | HIGH | Sometimes rated MEDIUM | Direct financial impact: double-spend, balance manipulation. |
| DOM XSS via innerHTML with server-sourced data | MEDIUM | Sometimes rated HIGH | Requires prior database poisoning but affects all frontend users who load the page. |
|  via recursive merge without `__proto__`/`constructor` filtering | MEDIUM | Varies widely | Exploitability depends on downstream gadgets, but the merge primitive itself is the vulnerability. |

## Assessment Process

For each finding:

1. Start with the baseline severity for the vulnerability class
2. Check the common miscalibrations table for specific overrides
3. Assess actual exploitability — is there a confirmed attack path?
4. Apply contextual reductions for authentication, network isolation, rate limiting
5. Apply contextual increases for internet-facing, PII handling, chaining
6. Verify the final severity makes sense in the context of the specific codebase
7. Document the rationale, especially when deviating from baseline
