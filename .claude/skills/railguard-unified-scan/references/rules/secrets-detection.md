<!-- CANARY:RGS:rule:secrets-detection -->

# Hardcoded Secrets Detection Security Rules

## R: Risk First

**Goal**: Detect plaintext credentials, API keys, and cryptographic material committed to source code or configuration files
**Risk**: Credential theft, unauthorized access to external services, data breach, and account compromise if secrets are exposed via version control or logs
**Context**: All source files, configuration files (YAML, JSON, .env, .properties), and infrastructure-as-code across any language or framework

## A: Attached Constraints

**CRITICAL SECURITY BOUNDARIES**:
- NEVER flag values that are clearly encrypted, hashed, or managed by a secrets manager
- NEVER flag placeholder values, environment variable references, or template markers
- ALWAYS distinguish between a hardcoded plaintext secret and a reference to a secret stored elsewhere
- ALWAYS check file context — test fixtures, documentation examples, and mock data reduce severity
- NEVER flag secrets that exist only in dead/unreachable code paths

**SECURITY AWARENESS**:
- Hardcoded secrets are frequently the entry point for supply chain attacks and repo scraping
- Secrets in version control history remain exposed even after removal — rotation is required
- Configuration files (.yml, .env, .properties) are the most common location
- Short, high-entropy strings adjacent to credential keywords are the strongest signal

## I: Interpretative Framing

**When evaluating a potential secret**:
- Check for encryption wrappers (`ENC[...]`, `vault://`, `${SECRET_REF}`, environment variable syntax)
- Check for placeholder patterns (`<TO_BE_SET>`, `changeme`, `xxx`, `YOUR_KEY_HERE`, `REPLACE_ME`)
- Check whether the value is referenced from a secrets manager or injected at runtime
- Consider whether the file is a test fixture, documentation, or production config

**When determining severity**:
- Production credentials in plaintext warrant CRITICAL regardless of service type
- Cloud provider keys (AWS, GCP, Azure) are CRITICAL due to blast radius
- Third-party API keys are HIGH — rotate immediately on discovery
- Test/dev credentials are MEDIUM if clearly scoped to non-production environments
- Demo or example values with obvious placeholder content are LOW or informational

**When a value looks like a secret but isn't**:
- Encrypted blobs (base64 DER/PEM blocks without a plaintext key nearby) are not findings
- Hash digests used for integrity checking are not credentials
- Public keys and certificates are not secrets

## L: Local Defaults

### Credential Keyword Triggers

Flag values assigned to keys matching:
```
password, passwd, pwd, secret, key, token, api_key, apikey, api-key,
access_key, secret_key, client_secret, auth_token, private_key,
signing_key, encryption_key, database_url, connection_string
```

### Safe Patterns (Not Findings)

```yaml
# Environment variable reference — safe
api_key: ${API_KEY}
api_key: <%= ENV['API_KEY'] %>

# Secrets manager reference — safe
password:
  encrypted:
    secret: "MGICAQAw..."   # Encrypted blob, not plaintext
database_password: vault://secret/db#password

# Placeholder — safe
api_key: "<YOUR_API_KEY_HERE>"
password: "changeme"
token: "REPLACE_ME"

# Public key / certificate — safe
public_key: "ssh-rsa AAAAB3NzaC1yc2E..."
```

### Vulnerable Patterns (Findings)

```yaml
# Plaintext credential — CRITICAL
database:
  password: "Sup3rS3cr3tP@ss!"

# Hardcoded cloud key — CRITICAL
aws_secret_access_key: "<AWS_SECRET_EXAMPLE>"

# Hardcoded API key — HIGH
stripe_secret_key: "sk_live_<REDACTED>"

# Test credential in shared config — MEDIUM
test_db_password: "testpassword123"
```

### Severity Tiers

| Severity | Condition |
|----------|-----------|
| CRITICAL | Production credentials, cloud provider keys, private keys |
| HIGH | Third-party API keys, OAuth secrets, JWT signing keys |
| MEDIUM | Dev/test credentials, internal service passwords |
| LOW | Example values, demo fixtures with obvious placeholder content |

## G: Generative Path Checks

1. **Keyword scan**: Does the key name match a credential keyword pattern?
2. **Value entropy check**: Is the value a high-entropy string (not a word, not a template marker)?
3. **Encryption check**: Is the value wrapped in an encryption or secrets-manager format?
4. **Placeholder check**: Does the value match known placeholder patterns?
5. **File context**: Is this a test fixture, documentation, or example file?
6. **Dead code check**: Is this code path reachable in production?
7. **Severity classification**: Apply the severity tier based on the service type and environment.

## U: Uncertainty Disclosure

**When uncertain whether a value is a real credential**:
- High-entropy strings adjacent to credential keywords default to HIGH severity pending confirmation
- Partial redaction (e.g., `sk_live_****`) is not a finding
- If the file is clearly a README or docs example, lower severity to LOW/informational

**When context is ambiguous**:
- Treat ambiguous production vs. test scoping as production until proven otherwise
- When an encryption wrapper is present but no decryption integration is visible, flag as LOW rather than dismissing

## A: Auditability

**Required Security Comments**:
- SECRETS: Mark all credential storage patterns with a comment noting the storage mechanism
- ROTATION: Document required rotation steps when a plaintext secret is confirmed

**Logging Requirements**:
- Never log credential values in scan output — log key names and file locations only
- Record file path, line range, key name, and severity for each finding

## R+D: Revision + Dialogue

**Security Review Questions**:
- "Is this value retrieved from a secrets manager or injected via environment variable at runtime?"
- "Does this credential appear in version control history even if now removed?"
- "Is rotation required, and is the owning team aware?"
- "Is there a CI/CD secret scanning gate that would have caught this pre-merge?"

**Core Security Principle**:
Secrets belong in secrets managers, not source code. Any plaintext credential in a config file or source file is a finding regardless of whether the repo is public or private — internal repos are breached too. The threshold for flagging should be low; the threshold for dismissing should be high.
