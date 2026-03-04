<!-- CANARY:RGS:methodology:false-positive-analysis -->
# False Positive and Mitigation Analysis

This methodology defines how to review findings for false positives and assess
mitigations that affect vulnerability severity or exploitability. Apply this as the
final quality gate before reporting findings.

## Core Principle

When in doubt, report with reduced severity rather than removing. It is better to
report a low-severity finding that might not be exploitable than to miss a real
vulnerability.

## Analysis Boundaries

These rules constrain your decision-making to prevent systematic errors:

- NEVER mark a finding as FALSE POSITIVE just because another detector found the
  same issue. Duplicate detections indicate CORROBORATION and strengthen confidence.
  Evaluate each finding on its own technical merits.
- NEVER confuse "not currently exploitable" with "false positive." A real vulnerability
  in dead code is NOT EXPLOITABLE (report as LOW). A misidentified non-vulnerability
  is a FALSE POSITIVE (remove). These are fundamentally different.
- NEVER remove real vulnerabilities. Only reduce severity. The minimum is LOW.
- NEVER skip exploitability assessment. Every finding must be evaluated for whether
  an attacker can actually reach and trigger the vulnerability.
- ALWAYS document the rationale when removing, downgrading, or keeping findings.

## Uncertainty Defaults

When you cannot determine a classification with confidence, use these defaults:

| Uncertainty | Default Action |
|-------------|---------------|
| Unsure whether it's a false positive | Report with severity reduced by one level |
| Unsure whether code is reachable | Report as LOW |
| Unsure about framework protection effectiveness | Report with original severity |
| Unsure about mitigation effectiveness | Assume partial mitigation; reduce by one level maximum |
| Unsure about exploitability, no clear attack path | Report as LOW |
| Unsure about exploitability, attack path might exist | Report as MEDIUM |

## Three Categories of Findings

### 1. FALSE POSITIVES (Remove from report)

Framework protections make exploitation impossible:
- Template rendering with framework auto-escaping enabled (Django, Jinja2 default, React JSX)
- ORM queries using built-in methods (filter, get, where) that auto-parameterize
- Encrypted secrets (ENC[], vault://, environment variable references)
- Test/mock code that never runs in production (verify — see below)
- Misidentified vulnerabilities due to analysis limitations

**Test/Example Code Verification**: Files in `examples/`, `sample/`, `demo/`, `test/`
directories require explicit verification before marking as FALSE POSITIVE:

1. **Check for production imports**: Is this file imported by code outside the
   example/test directory? If yes, treat as production code (full analysis).
2. **Check for deployment patterns**: Is this a template users might deploy
   (e.g., `examples/starter-app/`)? If yes, report as LOW, not false positive.
3. **Check for copy-paste risk**: Does this contain vulnerable patterns users
   might copy into production? If yes, report as LOW.

Decision logic by path:
- `__tests__/`, `fixtures/`, `conftest.py`, `*_test.py`, `testdata/` — usually safe
  to mark FALSE POSITIVE
- `examples/`, `samples/`, `demos/` — report as LOW (not false positive)
- If uncertain whether code reaches production — report as LOW, do NOT mark FALSE POSITIVE

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

For each finding, verify the complete exploitation chain:

1. **Attack vector exists**: Can an attacker reach the vulnerable code? Is the endpoint
   exposed, or is the function only callable internally?
2. **Input reaches sink**: Does user-controlled data actually flow to the dangerous
   operation? Trace the complete data flow from attacker input to vulnerable sink.
3. **Protections can be bypassed**: Are mitigations complete or partial? A WAF is
   bypassable; parameterized queries are not.
4. **Prerequisites achievable**: Can an attacker meet all required conditions? Check
   for required permissions, access levels, specific data states, or timing conditions.
5. **Technical complexity**: How difficult is exploitation? A single GET request is
   trivially exploitable; a deserialization gadget chain is not.
6. **Impact is real**: Does successful exploitation actually cause security impact?
   A redirect to a user-controlled URL is an open redirect; a redirect to a hardcoded
   URL is not.

### Sink Execution Verification (Construct vs. Invoke)

Some sinks **construct** dangerous objects without **executing** them. A finding is only
exploitable if the constructed object's dangerous behavior is actually triggered.

**Step 1**: Does the sink execute during processing, or merely construct an object?

Sinks that execute during processing:
- Python `pickle.loads()`, `yaml.load()` with `!!python/object/apply`
- Java `ObjectInputStream.readObject()`
- Ruby `Marshal.load()`

Sinks that only construct:
- `new Function(body)` — compiles but does not call. Code runs only when invoked.
- `new RegExp(pattern)` — creates but does not match.
- `template.Parse()` — compiles template. Code runs only on `.Execute()`.
- `compile()` — creates code object. Execution requires `exec()` or `eval()`.
- `Class.forName()` — loads class. Static initializers run but methods need invocation.

**Step 2**: Is the return value used in a way that triggers dangerous behavior?

- Return value discarded → constructed object is GC'd without execution → NOT EXPLOITABLE
- Return value stored but never accessed → NOT EXPLOITABLE
- Return value passed to a function that invokes/iterates/coerces it → check that path
- Return value rendered in a template or serialized → potentially exploitable via
  implicit invocation (see below)

**Step 3**: Check for implicit invocation paths.

Even when the return value is not explicitly called, these language mechanisms can
trigger execution:
- `toString()` / `valueOf()` called during string coercion or comparison
- `Symbol.toPrimitive`, `[Symbol.iterator]` called by language runtime operations
- `then()` on thenable objects called by `await` or Promise resolution
- Prototype chain methods triggered by property access on deserialized objects
- js-yaml v3.x `!!js/function` uses `new Function()` internally — the tag constructs
  but does not invoke

If no implicit invocation path exists and the return value is discarded, classify as
NOT EXPLOITABLE.

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
