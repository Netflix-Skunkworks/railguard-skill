<!-- CANARY:RGS:rule:authentication -->

# Authentication Security Rules


## R: Risk First

**Goal**: Ensure secure user authentication and session management
**Risk**: Unauthorized access, credential theft, session hijacking, and identity spoofing
**Context**: All applications requiring user authentication and session management

## A: Attached Constraints

**CRITICAL SECURITY BOUNDARIES**:
- ALWAYS use strong password policies and enforce them server-side
- NEVER store passwords in plaintext or reversible encryption
- ALWAYS use secure session management with proper timeout
- NEVER transmit credentials over unencrypted connections
- ALWAYS implement proper logout functionality
- NEVER use predictable session identifiers
- ALWAYS implement account lockout mechanisms for failed attempts
- NEVER expose authentication errors that reveal user enumeration

**SECURITY AWARENESS**:
- Authentication must be implemented on the server side
- Session tokens must be cryptographically secure and unpredictable
- Multi-factor authentication should be considered for sensitive applications
- Password reset mechanisms are often attack vectors

## I: Interpretative Framing

**When implementing user login**:
- Use secure password hashing (bcrypt, Argon2, or PBKDF2)
- Implement rate limiting for login attempts
- Generate secure session tokens after successful authentication
- Set appropriate session timeouts

**When implementing password reset**:
- Use secure, time-limited tokens
- Require email verification for password reset requests
- Invalidate existing sessions after password change
- Log all password reset activities

**When implementing session management**:
- Use secure, httpOnly, and sameSite cookies for session tokens
- Implement proper session invalidation on logout
- Regenerate session IDs after authentication
- Monitor for concurrent sessions

## L: Local Defaults

### Python Authentication Implementation
See `@../examples/authentication/auth_implementation.py`

### Node.js Authentication Implementation
See `@../examples/authentication/authImplementation.js`

## G: Generative Path Checks

1. **Password Security**: Are passwords hashed using secure algorithms (bcrypt, Argon2, PBKDF2)?
2. **Session Management**: Are session tokens cryptographically secure and properly managed?
3. **Rate Limiting**: Is rate limiting implemented for authentication endpoints?
4. **Account Lockout**: Are failed login attempts tracked and accounts locked appropriately?
5. **Session Timeout**: Are sessions properly expired and invalidated?
6. **Secure Transport**: Are credentials only transmitted over HTTPS?
7. **Logout Functionality**: Is proper session invalidation implemented on logout?

## U: Uncertainty Disclosure

**When uncertain about authentication requirements**:
- Default to the most secure authentication mechanisms available
- Implement multi-factor authentication for sensitive applications
- Use established authentication libraries rather than custom implementations
- Consult security team for specific organizational requirements

**When session management requirements are unclear**:
- Use shorter session timeouts for sensitive applications
- Implement session regeneration after authentication
- Monitor for concurrent sessions and suspicious activity

## A: Auditability

**Required Security Comments**:
- SECURITY: Mark all authentication-related code with security comments
- AUTH: Document authentication mechanisms and their security properties
- SESSION: Identify session management code and security measures

**Logging Recommendations** (for implementation):
- Log all authentication attempts (successful and failed)
- Log session creation, validation, and destruction
- Monitor for suspicious patterns (multiple failed attempts, concurrent sessions)
- Include timestamps, IP addresses, and user identifiers in logs

## R+D: Revision + Dialogue

**Security Review Questions**:
- "Are passwords properly hashed using secure algorithms?"
- "Is session management implemented securely?"
- "Are authentication endpoints protected against brute force attacks?"
- "Is proper logout functionality implemented?"
- "Are authentication events properly logged and monitored?"

**Core Security Principle**:
Implement robust authentication with secure password handling, proper session management, rate limiting, and comprehensive logging to prevent unauthorized access and detect security incidents.
