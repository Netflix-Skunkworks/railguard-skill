# Security Scan Report

## Executive Summary

**Repository**: [repository path]
**Scan Date**: [date]
**Files Analyzed**: [count]
**Languages**: [detected languages]
**Frameworks**: [detected frameworks]

### Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | [n] |
| HIGH | [n] |
| MEDIUM | [n] |
| LOW | [n] |
| **Total** | **[n]** |

### Key Risk Areas

[1-3 sentence summary of the most significant findings and their business impact]

---

## Architecture Overview

**Languages detected**: [list]
**Frameworks**: [list]
**Database**: [type or "none detected"]
**Authentication**: [mechanism or "none detected"]
**API type**: [REST/GraphQL/gRPC or "N/A"]

### Discovery Gates Activated

[List which analysis passes were executed and why]

---

## Data Flow Summary

- **Input sources identified**: [count]
- **Flows traced**: [count]
- **Potentially vulnerable flows**: [count]
- **Validated (properly protected) flows**: [count]

---

## Findings

[For each finding, include:]

### [Finding #]: [Title]

**Severity**: [CRITICAL/HIGH/MEDIUM/LOW]
**Type**: [vulnerability type]
**File**: `[file path]`
**Lines**: [start]-[end]

**Description**: [Technical explanation]

**Impact**: [Security impact if exploited]

**Vulnerability Trace**:
[Ordered trace steps from source to sink]

**Code**:
```[language]
[vulnerable code snippet]
```

**Remediation**:
[Explanation + steps + secure code example]

**Triage**: Tier [0/1/2] — [reason]
**Reproduction Steps**:
[Numbered steps with concrete payloads]

---

## Scan Metadata

- **Phases completed**: [list]
- **Semgrep**: [enabled/disabled, finding count if enabled]
- **Corroborated findings**: [count] (found by both semgrep and LLM analysis)
- **False positives removed**: [count]
- **Severity adjustments**: [count]
