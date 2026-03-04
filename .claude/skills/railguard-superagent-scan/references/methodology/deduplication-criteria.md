<!-- CANARY:RGS:methodology:deduplication-criteria -->
# Deduplication Criteria

Framework for assessing whether multiple findings describe the same underlying
vulnerability. These are criteria for your judgment — apply them contextually,
not mechanically.

## Overlap Signals

Two findings are likely the same vulnerability when ALL of these hold:

1. **Same file**: Both reference the same source file path
2. **Proximate lines**: Line ranges overlap or are within approximately 5 lines of each
   other. Use judgment — if two findings are 10 lines apart but clearly describe the same
   function and the same data flow, they are likely the same issue.
3. **Same or related vulnerability class**: Direct match (both "sqli") or closely related
   types that share the same sink (e.g., "command_injection" and "code_injection" at the
   same eval() call)

## Type Affinity Groups

Findings within the same group are more likely to overlap when they share a file and
line range:

| Group | Types | Common Sink |
|-------|-------|-------------|
| SQL injection | sqli, nosqli | Database query construction |
| Code execution | command_injection, code_injection, ssti, deserialization | eval, exec, template compile, deserialize |
| Output injection | xss, open_redirect, header_injection | HTML output, redirect, response headers |
| File system | path_traversal, file_upload | File path construction, file storage |
| Network | ssrf, xxe | HTTP request, XML parse |

Findings in DIFFERENT groups at the same location are typically distinct vulnerabilities
and should both be reported (e.g., sqli and xss at the same endpoint are different issues
even if they share an input source).

## Corroboration vs Duplication

**Corroboration** occurs when multiple independent detection methods identify the same
vulnerability. This INCREASES confidence — do not remove corroborated findings.

| Scenario | Action |
|----------|--------|
| Semgrep and LLM analysis found the same issue | Mark as corroborated. Keep the LLM finding (richer context). Note the semgrep rule. |
| Two LLM analysis passes found the same issue | Consolidate into one finding with the most complete description. |
| Semgrep found something LLM analysis missed | Evaluate the semgrep finding on its merits. Add if it represents a real issue. |
| LLM found something semgrep missed | Normal — LLM analysis has deeper semantic understanding. Keep. |

## When to Consolidate

Merge two findings into one when:
- They describe the same vulnerability at the same location
- Keeping both would confuse the consumer of the report
- One finding is strictly more detailed than the other

When consolidating, prefer the finding with:
1. A complete vulnerability trace (over one without)
2. A more precise line range
3. A more detailed description and remediation
4. Higher severity (if the assessments differ)

## When NOT to Consolidate

Keep both findings when:
- They represent genuinely different vulnerability classes (sqli + xss at the same endpoint)
- They affect different parameters or data flows even if at the same line
- One is from semgrep (corroboration signal has independent value)
- You are uncertain whether they are the same issue — err on the side of reporting both

## Severity Conflicts

When two findings at the same location have different severities:
- Use the higher severity if the more severe assessment is well-justified
- If the lower severity finding has better evidence (e.g., a mitigation was identified),
  use the lower severity with the stronger justification
- Document the conflict in the finding description
