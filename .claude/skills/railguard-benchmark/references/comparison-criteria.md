# Comparison Criteria

Guide for interpreting scan-vs-answer-sheet comparison results and writing
explanatory notes for each item. The `store-and-compare.py` script produces
the structural matching; your job is to provide the judgment and narrative.

## Match Statuses

| Status | Meaning | Your Action |
|--------|---------|-------------|
| `matched` | Exact match: same file, nearby lines, same type | Verify severity agreement. Note any severity discrepancies. |
| `partial` | Weak match: same file and type but different lines, OR same file and lines but different type | Investigate why. Was the finding merged with another? Did the scanner identify a broader pattern? |
| `missed` | Expected finding not found | Explain why. Common reasons below. |
| `correctly_not_found` | FP bait correctly not flagged | Confirm the scanner avoided the trap. Note if it flagged something related but distinct. |
| `extra` | Scanner found something not in the answer sheet | Classify as novel true positive, false positive, or duplicate. |

## Writing Notes for Missed Findings

When a finding was expected but not detected, explain WHY. Common reasons:

### Legitimate Misses
- **Dead code not reported**: "Scanner correctly identified `_legacy_handler()` as
  unreachable from any route handler. The function exists but is never called. The
  scanner's FP analysis removed it as not exploitable."
- **Merged findings**: "PV-008 and PV-009 describe two XSS sinks in the same file.
  The scanner reported a single finding covering both endpoints. See matched finding
  for PV-008."
- **Severity below threshold**: "The scanner identified this pattern but classified
  it as informational rather than a finding. The answer sheet expects LOW severity."
- **Framework protection recognized**: "The scanner detected the pattern but its FP
  analysis correctly determined Django's auto-escaping prevents exploitation."

### Analysis Gaps
- **Gate not activated**: "The discovery phase did not detect template engine usage,
  so the SSTI analysis pass was skipped entirely."
- **File not read**: "The scanner's 30-file budget was exhausted before reaching this
  file. The vulnerable code is in a utility module not prioritized as an entry point."
- **Flow not traced**: "Data flow tracing did not trace input from the WebSocket
  handler to the SQL query in the service layer. The cross-module flow was missed."
- **Pattern not recognized**: "The scanner did not recognize this as a vulnerability.
  The deserialization pattern uses a custom wrapper function that obscures the
  underlying `pickle.loads` call."

### Scanner Limitations
- **Context window exhaustion**: "By the time this pass ran, accumulated context from
  prior phases left insufficient budget for thorough analysis of this file."
- **Consolidated pass trade-off**: "This vulnerability type was grouped with 6 others
  in the injection sweep. The breadth of the consolidated pass diluted attention on
  this specific pattern."

## Writing Notes for Extra Findings

When the scanner found something not in the answer sheet:

- **Novel true positive**: "The scanner identified a real IDOR vulnerability in
  `/api/users/:id` that is not in the answer sheet. This endpoint returns user data
  without verifying the authenticated user owns the requested resource. Recommend
  adding to the answer sheet."
- **False positive**: "The scanner flagged `config.py:25` as a hardcoded secret, but
  the value `changeme` is a placeholder that is overridden by environment variables
  in all deployment configurations."
- **Duplicate / already covered**: "This finding describes the same vulnerability as
  PV-012 but from a different code path. The scanner traced two routes to the same
  SQL injection sink."

## Severity Comparison

When a finding is matched but severities differ:

| Answer Sheet | Scanner Found | Assessment |
|-------------|---------------|------------|
| CRITICAL | CRITICAL | Agreement |
| CRITICAL | HIGH | Minor underweight — check if scanner applied mitigations (auth required, etc.) |
| HIGH | CRITICAL | Minor overweight — check if scanner missed mitigations |
| HIGH | MEDIUM | Significant gap — investigate whether scanner detected mitigations or misclassified |
| Any | LOW | Large gap — likely scanner's FP analysis reduced severity due to barriers |

Note the discrepancy and explain the scanner's reasoning if visible in the finding's
description or FP category.

## Dead Code Findings

Answer sheets may include dead-code vulnerabilities (category: `dead-code`). These
test whether the scanner:

1. **Detects the pattern** (finds the vulnerability in uncalled code)
2. **Correctly classifies it** (reports at LOW severity or annotates as dormant)
3. **Does not overreport** (does not flag it at CRITICAL/HIGH)

If the scanner missed a dead-code finding entirely, this is a minor gap — the code
is not exploitable. Note it but do not weight it heavily in quality assessment.

If the scanner found it and reported it at full severity (not reduced), that is a
false positive analysis gap worth noting.

## FP Bait Findings

Answer sheets may include false-positive bait (category: `fp-bait`,
expected_detection: `NO`). These test whether the scanner avoids common FP traps:

- ORM-parameterized queries that look like SQL injection
- Auto-escaped template output that looks like XSS
- Encrypted secrets that look like hardcoded credentials

If the scanner flagged FP bait as a real finding, note it as a false positive with
explanation of what the scanner should have recognized (framework protection,
encryption pattern, etc.).

## Quality Metrics

After reviewing all items:

| Metric | Formula | Interpretation |
|--------|---------|----------------|
| **Recall** | true_positives / total_expected | What fraction of real vulnerabilities were found? |
| **Precision** | true_positives / (true_positives + extra) | What fraction of reported findings are real? |
| **Severity accuracy** | matches where severity agrees / total matches | How well does the scanner calibrate severity? |
| **FP bait resistance** | correctly_not_found / total_fp_bait | How well does the scanner avoid false positives? |
| **Dead code handling** | dead code found at LOW / total dead code | Does the scanner handle unreachable code correctly? |

A strong scan result has recall above 0.80, precision above 0.70, and zero FP bait failures.
