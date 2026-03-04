<!-- CANARY:RGS:rule:input-validation -->

# Input Validation Analysis Rules

## Scope

Assess input validation comprehensiveness and quality at input sources and along data flow paths.
If exploitation-level vulnerabilities are found (SQLi, XSS, SSRF, SSTI, command
injection, deserialization, XXE, path traversal, etc.) — domain-specific agents
handle those.

Report validation DEFICIENCIES or gaps:

- Missing server-side validation
- Weak validation strategies (blocklist instead of allowlist)
- Missing constraints (length, range, type)
- Insecure patterns (ReDoS, information disclosure in errors)

## Critical Security Boundaries

- ALWAYS validate all input at trust boundaries using both syntactic and semantic validation
- NEVER trust client-side validation alone — server-side validation is mandatory
- ALWAYS use allowlist (whitelist) validation over blocklist (blacklist) approaches
- NEVER rely solely on sanitization — validate first, sanitize as defense-in-depth
- ALWAYS validate file uploads using content inspection, not just file extensions
- ALWAYS implement ReDoS-resistant regular expressions with proper anchoring
- ALWAYS encode user-controlled data based on the output context before rendering

## Interpretative Framing

### Form Submissions
- Implement both syntactic validation (correct format) and semantic validation (business logic correctness)
- Include length limits, format validation, and business context validation
- Provide clear error messages without revealing system internals
- Use established validation libraries rather than custom implementations

### API Requests
- Validate all parameters against expected schemas (JSON Schema, XML Schema)
- Implement rate limiting and request size limits
- Use structured data formats with proper schema validation
- Validate nested objects and arrays recursively

### File Uploads
- Validate file types using content inspection and magic number verification
- Implement file size limits and scan for malicious content
- Store uploaded files outside the web root with randomized names
- Validate against dangerous file types (crossdomain.xml, .htaccess, executable scripts)
- Use image rewriting libraries for image uploads to strip malicious content

### Unicode Text
- Apply Unicode normalization to ensure canonical encoding
- Use character category allowlisting for international text support
- Validate individual characters when allowing specific punctuation
- Prevent homograph attacks in domain names and identifiers

### Email Addresses
- Perform basic syntactic validation followed by semantic validation
- Use email verification tokens for ownership confirmation
- Consider sub-addressing support and disposable email address policies
- Implement proper length limits (63 chars local part, 254 total)

## Generative Path Checks

For each input source and data flow, assess:

1. **Input Source Identification**: Are all input sources (forms, APIs, files, external feeds) identified and validated?
2. **Validation Placement**: Is validation performed on the server side with proper error handling?
3. **Syntactic vs Semantic**: Are both syntactic (format) and semantic (business logic) validations implemented?
4. **Type-Specific Validation**: Are appropriate validators used for each data type (email, phone, file, Unicode text)?
5. **File Upload Security**: Are file uploads validated using content inspection and dangerous file filtering?
6. **Unicode Handling**: Is Unicode text properly normalized and validated using character categories?
7. **ReDoS Prevention**: Are regular expressions designed to prevent ReDoS attacks with proper timeouts?
8. **Range and Length Limits**: Are appropriate limits enforced for all input types?
9. **Error Handling**: Are validation errors handled securely without information disclosure?
10. **Security Monitoring**: Are validation failures logged for security analysis and attack detection?

## ReDoS Detection

Flag regular expressions that exhibit:
- Nested quantifiers: `(a+)+`, `(a*)*`, `(a{1,10})+`
- Overlapping alternation: `(a|a)+`, `(.*a|.*b)`
- Quantified groups with optional subpatterns: `(a?b)+`
- Missing anchors on user-input regex: `new RegExp(userInput)`
- No timeout mechanism on regex execution against user data

## Schema Validation

Flag endpoints that accept structured input (JSON, XML, form data) without:
- JSON Schema or equivalent validation
- Type checking on nested fields
- Array length limits
- Recursive depth limits for nested objects

## Error Handling / Information Disclosure

Flag validation error responses that leak:
- Internal paths or file names
- Stack traces or framework details
- Database column names or schema details
- Internal service names or network topology
- Detailed regex patterns used for validation

## Uncertainty Disclosure

When uncertain about validation requirements:
- Default to the most restrictive validation possible using allowlist approaches
- Use established validation libraries (validator.js, Django validators) rather than custom implementations
- Implement both client-side (UX) and server-side (security) validation
- Apply Unicode normalization for international text support
- Use content-based file type detection rather than trusting file extensions
