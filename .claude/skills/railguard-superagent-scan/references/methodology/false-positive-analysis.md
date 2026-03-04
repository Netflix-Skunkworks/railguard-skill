<!-- CANARY:RGS:methodology:false-positive-analysis -->
# False Positive and Mitigation Analysis

This methodology defines how to review findings for false positives and assess
mitigations that affect vulnerability severity or exploitability. Apply this as the
final quality gate before reporting findings.

## Core Principle

When in doubt, report with reduced severity rather than removing. It is better to
report a low-severity finding that might not be exploitable than to miss a real
vulnerability.

## Three Categories of Findings

### 1. FALSE POSITIVES (Remove from report)

Framework protections make exploitation impossible:
- Template rendering with framework auto-escaping enabled (Django, Jinja2 default, React JSX)
- ORM queries using built-in methods (filter, get, where) that auto-parameterize
- Encrypted secrets (ENC[], vault://, environment variable references)
- Test/mock code that never runs in production (verify — see below)
- Misidentified vulnerabilities due to analysis limitations

**Test/Example Code Verification**: Files in `examples/`, `sample/`, `demo/`, `test/`
directories require explicit verification before removing:
- Is this file imported by production code? If yes, treat as production.
- Is this a template users might deploy? If yes, report as LOW, not false positive.
- Does this contain patterns users might copy into production? If yes, report as LOW.
- `__tests__/`, `fixtures/`, `conftest.py`, `*_test.py` — usually safe to mark false positive
- `examples/`, `samples/`, `demos/` — report as LOW (not false positive)

### 2. REAL BUT NOT EXPLOITABLE (Report with LOW severity)

The vulnerability exists in code but has no current attack path:
- Vulnerability in unreachable/dead code
- Vulnerability in unused functions
- Missing attack vector (no user input reaches vulnerability)
- Prerequisites cannot be met in current deployment
- Example: RCE in a function that's never called = LOW severity, not removed

### 3. EXPLOITABLE WITH BARRIERS (Report with reduced severity)

Real vulnerability with mitigations that reduce but don't eliminate risk:
- Requires authentication → reduce one level
- Requires admin access → reduce one level
- Protected by rate limiting → reduce one level
- Network isolation limits access → reduce one level
- Multiple barriers stack (cumulative reduction, minimum LOW)

## Exploitability Assessment

When determining exploitability, verify:

1. **Attack vector exists**: Can an attacker reach the vulnerable code?
2. **Input reaches sink**: Does user-controlled data actually flow to the dangerous operation?
3. **Protections can be bypassed**: Are mitigations bypassable or complete?
4. **Prerequisites achievable**: Can an attacker meet all required conditions?

### Sink Execution Verification

Some sinks **construct** dangerous objects without **executing** them. A finding is only
exploitable if the constructed object's dangerous behavior is actually triggered.

Check for construct-only sinks:
- `new Function(body)` — compiles but does not call. Code runs only when invoked.
- `template.Parse()` — compiles template. Code runs only on `.Execute()`.
- `compile()` — creates code object. Execution requires `exec()` or `eval()`.
- `Class.forName()` — loads class. Static initializers run but methods need invocation.

If the sink only constructs and the return value is discarded or never invoked,
classify as NOT EXPLOITABLE.

## Framework-Specific False Positive Patterns

### Python
- **Django/Jinja2**: Auto-escaping is ON by default. `{{ variable }}` is safe for XSS.
  Only `{{ variable|safe }}` or `Markup()` bypasses escaping.
- **SQLAlchemy/Django ORM**: `.filter()`, `.get()`, `.exclude()` use parameterized queries.
  Only `.raw()`, `.extra()`, or `text()` with string formatting are vulnerable.
- **Encrypted secrets** (ENC[], vault://, secrets manager references) are not plaintext credentials.

### Java
- **Spring Data JPA**: Repository methods, JPQL with parameters, Criteria API auto-parameterize.
- **Spring Security**: CSRF protection enabled by default, authentication filters.
- **MyBatis**: `#{}` syntax uses parameterized binding. `${}` is vulnerable.

### JavaScript/Node.js
- **React JSX**: `{variable}` auto-escapes. Only `dangerouslySetInnerHTML` is vulnerable.
- **Sequelize/Prisma/Knex**: Query builder methods auto-parameterize.
  Only `.raw()` or `Sequelize.literal()` with user input are vulnerable.
- **Express/Helmet.js**: Security headers, CSRF middleware, rate limiting.

### General
- **Parameterized queries**: When properly used, prevent SQL injection regardless of input.
- **Content Security Policy**: Strict CSP mitigates XSS impact (but does not eliminate the vulnerability).
- **HTTPS/TLS**: Transport security, not application-level protection.

## CI/CD Pipeline (GitHub Actions) Considerations

GitHub Actions findings require specialized assessment:
- `pull_request_target` workflows that ONLY label/comment/triage → FALSE POSITIVE
- Expression interpolation in `if:` conditions only → FALSE POSITIVE (expression context)
- Actions pinned to full 40-character SHA → FALSE POSITIVE for supply chain findings
- Fork check present → reduces severity by 2 levels (blocks fork-based exploitation)
- Label gate requiring maintainer action → reduces severity by 1-2 levels
- Environment with required reviewers → reduces severity by 1-2 levels
- Minimal permissions (contents: read) → reduces severity by 1 level

## Severity Adjustment Guidelines

- NEVER remove real vulnerabilities — only reduce severity
- Document why severity was reduced
- Stack multiple mitigations for cumulative reduction
- Minimum severity is LOW (never remove real vulnerabilities)
- If uncertain about a mitigation's effectiveness, assume partial (reduce by one level max)

## Decision Framework

For each finding:

1. **Is it a false positive?** Check framework protections, encryption patterns, test-only code.
   If yes → remove with documented justification.
2. **Is it exploitable?** Trace the complete attack path.
   If no attack path exists → report as LOW with explanation.
3. **Are there barriers?** Authentication, rate limiting, network isolation.
   If barriers exist → reduce severity based on barrier strength.
4. **Is it fully exploitable?** Clear attack path, no mitigations.
   If yes → keep original severity.
