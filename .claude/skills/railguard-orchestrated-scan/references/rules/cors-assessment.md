<!-- CANARY:RGS:rule:cors-assessment -->

# CORS Vulnerability Severity Assessment Framework

## R: Risk First

**Goal**: Accurately assess CORS vulnerability severity based on real-world exploitability rather than theoretical impact
**Risk**: Over-classification of CORS misconfigurations leads to resource misallocation and security fatigue
**Context**: CORS vulnerabilities require specific conditions to be exploitable and are often over-rated in severity

## CORS Severity Quick Assessment
1. Is CORS implemented? → No: Skip assessment
                       ↓ Yes
2. Is it misconfigured? → No: No vulnerability
                        ↓ Yes  
3. Check exploitability:
   - Returns sensitive data? → Yes: MEDIUM+
   - Has XSS/CSRF vulns? → Yes: HIGH+
   - Critical business system? → Yes: Consider MEDIUM+
   - None of above? → LOW (default)

## A: Attached Constraints

**CRITICAL SECURITY BOUNDARIES**:
- ONLY assess CORS vulnerabilities when CORS implementation already exists in the application
- NEVER recommend implementing CORS if it's not already present
- ALWAYS default to LOW severity for standard CORS misconfigurations
- NEVER assign HIGH/CRITICAL severity without confirmed exploitability requirements
- ALWAYS verify secondary vulnerabilities before upgrading severity

**SECURITY AWARENESS**:
- CORS exploitation requires attacker-controlled website + victim interaction + authenticated session
- Most CORS misconfigurations are not directly exploitable without secondary vulnerabilities
- Proper CSRF protection and secure cookie settings significantly reduce CORS exploitability

## I: Interpretative Framing

**When CORS implementation exists in the application**:
- Assess the specific CORS configuration for misconfigurations
- Check for exploitability requirements before assigning severity
- Default to LOW severity unless specific conditions are met
- Document the attack chain required for exploitation

**When no CORS implementation exists**:
- Do not flag missing CORS as a vulnerability
- Do not recommend implementing CORS
- Focus security analysis on other areas

**When assessing CORS severity**:
- Prioritize evidence of actual exploitability over theoretical impact
- Consider the complete attack chain required
- Evaluate secondary vulnerabilities that enable CORS exploitation

## L: Local Defaults

**CORS Assessment Prerequisites**
```
BEFORE assessing CORS vulnerabilities, verify:
✓ Application contains CORS headers (Access-Control-Allow-Origin, etc.)
✓ Application uses CORS middleware or libraries
✓ Application explicitly handles cross-origin requests

IF NO CORS IMPLEMENTATION EXISTS:
- Do not flag missing CORS as a vulnerability
- Do not recommend implementing CORS
- Focus on other security aspects
```

**Enhanced CORS Severity Determination (When CORS Exists)**
```
CORS Misconfiguration Assessment:

**CRITICAL PRINCIPLE**: CORS misconfigurations are LOW severity by default unless specific exploitability requirements are met. CORS requires both a permissive policy AND exploitable conditions to be dangerous.

**Default Assessment**: LOW severity for standard CORS misconfigurations (Access-Control-Allow-Origin: * with credentials)

**Exploitability Requirements for Higher Severity:**

MEDIUM Severity (Uncommon):
✓ CORS allows attacker-controlled origins with credentials AND
✓ Endpoint performs state-changing operations with weak CSRF protection AND
✓ Operations affect user data or account settings (non-critical)
✓ ONE of the following secondary vulnerabilities exists:
  - XSS vulnerability that can be triggered by cross-origin response data
  - CSRF vulnerability with no proper protection on state-changing operations
  - Endpoint returns sensitive data (PII, internal system details) in response body
  - Client-side parsing vulnerability (JSONP-like responses, DOM injection)

LOW Severity (Default - Most Common):
✓ Standard CORS misconfiguration (Access-Control-Allow-Origin: * with credentials)
✓ No evidence of exploitable secondary vulnerabilities
✓ No sensitive data returned in response bodies
✓ Proper CSRF protection in place for state-changing operations
✓ No client-side parsing vulnerabilities identified

**Assessment Process:**
1. Confirm CORS misconfiguration exists (Access-Control-Allow-Origin: * with credentials)
2. Check for exploitability requirements:
   - Does endpoint return sensitive data in response body?
   - Are there state-changing operations without CSRF protection?
   - Are there XSS or client-side injection vulnerabilities?
   - Is this a financial/payment/admin system?
3. If NO exploitability requirements are met: assign LOW severity
4. If exploitability requirements are met: assess based on impact and secondary vulnerabilities

**Key Exploitability Factors:**
- Attacker must control a website that victim visits
- Victim must be authenticated to target application
- Target endpoint must return exploitable data or perform dangerous operations
- Secondary vulnerabilities (XSS, CSRF, injection) significantly increase risk
- Proper security controls (CSRF tokens, SameSite cookies) reduce exploitability

Assessment Logic:
When CORS exists but no exploitability requirements are met: assign LOW severity.
When CORS exists with secondary vulnerabilities or sensitive data exposure: assess based on specific conditions above.
When no CORS implementation exists: do not assess CORS vulnerabilities at all.
```

## G: Generative Path Checks

1. **CORS Implementation Detection**
   - Does the application contain CORS headers in responses?
   - Are CORS middleware or libraries present in the codebase?
   - Does the application explicitly handle preflight requests?

2. **Misconfiguration Assessment**
   - Is Access-Control-Allow-Origin set to wildcard (*) with credentials?
   - Are sensitive endpoints affected by permissive CORS policy?
   - Are there overly broad Access-Control-Allow-Methods configurations?

3. **Exploitability Requirements Check**
   - Do endpoints return sensitive data in response bodies?
   - Are there unprotected state-changing operations?
   - Are secondary vulnerabilities (XSS, CSRF) present?
   - Is this a critical business system (financial, admin, payment)?

4. **Attack Chain Validation**
   - Can an attacker create a malicious website to exploit CORS?
   - Would a victim need to be authenticated for exploitation?
   - Are there additional barriers to successful exploitation?

5. **Security Controls Assessment**
   - Are CSRF tokens properly implemented for state-changing operations?
   - Are cookies configured with SameSite attributes?
   - Are there rate limiting or other protective measures?

## U: Uncertainty Disclosure

**When uncertain about CORS exploitability**:
- Default to LOW severity for standard CORS misconfigurations
- Require clear evidence of exploitability requirements before upgrading severity
- Document the specific conditions that would make the CORS vulnerability exploitable

**When CORS implementation is unclear**:
- Investigate thoroughly before flagging CORS vulnerabilities
- Look for explicit CORS headers, middleware, or cross-origin handling code
- Do not assume CORS vulnerabilities exist without clear evidence

## A: Auditability

**Required Security Comments**:
- CORS: Mark all CORS-related security assessments
- EXPLOITABILITY: Document specific requirements for higher severity
- SECONDARY: Note any secondary vulnerabilities that increase CORS risk

**Assessment Documentation Requirements**:
- Document CORS configuration details (headers, origins, credentials)
- List specific exploitability requirements checked
- Explain why severity was assigned (default LOW vs. upgraded)
- Note any secondary vulnerabilities that affect CORS exploitability

## R+D: Revision + Dialogue

**Security Review Questions**:
- "Does this application actually implement CORS?"
- "What specific exploitability requirements are met for this CORS misconfiguration?"
- "Are there secondary vulnerabilities that make this CORS issue exploitable?"
- "What would an attacker need to successfully exploit this CORS misconfiguration?"

**Core Security Principle**:
CORS misconfigurations are LOW severity by default. Higher severity requires specific exploitability conditions including sensitive data exposure, secondary vulnerabilities, or critical business system impact.

## Real-World CORS Assessment Examples

### Example 1: Standard CORS Misconfiguration (Most Common)
```
Vulnerability: CORS configured with Access-Control-Allow-Origin: * and credentials enabled
Prerequisites: ✓ Application has CORS implementation

CIA Assessment:
- Confidentiality: LOW (requires complex attack chain with victim visiting malicious site)
- Integrity: LOW (no evidence of exploitable state-changing operations without CSRF protection)
- Availability: LOW (no availability impact)

CORS Exploitability Assessment:
- Existing CORS allows any origin: TRUE
- Credentials supported: TRUE
- Sensitive data in response bodies: FALSE (no API keys, tokens, or PII exposed)
- Secondary vulnerabilities present: FALSE (no XSS, no unprotected CSRF endpoints)
- Critical business operations affected: FALSE (standard web application)

Severity: LOW

Justification: Standard CORS misconfiguration without exploitability requirements. Requires attacker-controlled website + victim interaction + authenticated session, with no evidence of sensitive data exposure or secondary vulnerabilities.
```

### Example 2: CORS with Exploitable Conditions (Rare)
```
Vulnerability: CORS allows any origin with credentials on endpoint returning user PII
Prerequisites: ✓ Application has CORS implementation

CIA Assessment:
- Confidentiality: MEDIUM (exposes user PII in response body)
- Integrity: LOW (no state-changing operations)
- Availability: LOW (no availability impact)

CORS Exploitability Assessment:
- Existing CORS allows any origin: TRUE
- Credentials supported: TRUE
- Sensitive data in response bodies: TRUE (user PII returned in JSON responses)
- Secondary vulnerabilities present: FALSE
- Critical business operations affected: FALSE

Severity: Medium

Justification: CORS misconfiguration with confirmed sensitive data exposure in response bodies. Meets exploitability requirements for higher severity due to actual data exposure risk.
```

### Example 3: CORS with Secondary XSS Vulnerability (High Risk)
```
Vulnerability: CORS misconfiguration combined with DOM XSS in response processing
Prerequisites: ✓ Application has CORS implementation

CIA Assessment:
- Confidentiality: HIGH (XSS can access all user data in authenticated context)
- Integrity: HIGH (XSS can modify application state and data)
- Availability: MEDIUM (can disrupt user sessions)

CORS Exploitability Assessment:
- Existing CORS allows any origin: TRUE
- Credentials supported: TRUE
- Sensitive data in response bodies: FALSE
- Secondary vulnerabilities present: TRUE (DOM XSS triggered by cross-origin response data)
- Critical business operations affected: FALSE

Severity: Medium

Justification: CORS misconfiguration enables exploitation of secondary XSS vulnerability, creating a complete attack chain for account takeover and data access in authenticated context.
```
