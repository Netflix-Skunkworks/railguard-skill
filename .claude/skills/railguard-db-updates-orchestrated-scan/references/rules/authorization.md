<!-- CANARY:RGS:rule:authorization -->
# Authorization Security Analysis

## Prerequisites
- Authentication MUST be present in the application
- Skip this rule if no authentication system exists
- Authorization without authentication is meaningless

## Focus Areas

### 1. RBAC Implementation
- Role definitions and assignments
- Permission mapping to roles
- Role hierarchy and inheritance
- Default role assignments

### 2. Permission Checking
- Consistent permission checks on ALL sensitive endpoints
- Permission checks at service layer, not just controller
- Both read and write operations protected
- Admin/privileged operations properly guarded

### 3. Privilege Escalation Paths
- User cannot modify their own role
- Role changes require admin approval
- No exposed role/permission APIs without auth
- Token claims cannot be modified client-side

### 4. IDOR Vulnerabilities
- Resource ownership verified before access
- IDs not predictable/sequential
- Cross-user access prevented
- Tenant isolation enforced

### 5. Horizontal Access Control
- Same-role users cannot access each other's data
- Session binding to user identity
- Multi-tenant resource isolation

## Common Vulnerability Patterns

### Missing Authorization
```python
# VULNERABLE - no permission check
@app.route('/admin/users/<id>/delete')
def delete_user(id):
    User.query.get(id).delete()

# SECURE - permission check
@app.route('/admin/users/<id>/delete')
@requires_permission('admin:delete_user')
def delete_user(id):
    User.query.get(id).delete()
```

### IDOR (Insecure Direct Object Reference)
```python
# VULNERABLE - no ownership check
@app.route('/documents/<id>')
def get_document(id):
    return Document.query.get(id)

# SECURE - ownership verified
@app.route('/documents/<id>')
def get_document(id):
    doc = Document.query.get(id)
    if doc.owner_id != current_user.id:
        abort(403)
    return doc
```

### Privilege Escalation
```python
# VULNERABLE - user can set own role
@app.route('/profile', methods=['PUT'])
def update_profile():
    data = request.json
    current_user.role = data.get('role')  # BAD!
    
# SECURE - role not user-modifiable
@app.route('/profile', methods=['PUT'])
def update_profile():
    data = request.json
    # role field ignored, only admin can change
    current_user.name = data.get('name')
```

## Endpoint Context Analysis

This section helps differentiate between legitimate public endpoints and tools requiring authentication.

### Classification Decision Tree

```
Is endpoint directly exposed with URL?
├─ NO → Check if only called by authenticated code
│   ├─ YES → Likely protected (verify)
│   └─ NO → Flag if performs privileged operations
└─ YES → Analyze functionality
    ├─ Basic user registration/login/reset → Public OK
    ├─ Newsletter/contact forms → Public OK
    └─ Any elevated operations → Auth Required
```

### Legitimate Public Endpoints (No Auth Required)

**User Registration**:
```
Path patterns: /register, /signup, /join, /create-account
Operations: Create new user accounts, send welcome emails
Classification: Legitimate public endpoint - NEVER flag as missing auth
```

**Authentication Endpoints**:
```
Path patterns: /login, /signin, /auth, /authenticate
Operations: Validate credentials, create sessions
Classification: Must be public for users to authenticate
```

**Password Recovery**:
```
Path patterns: /forgot-password, /reset, /recover
Operations: Send reset emails, update passwords with token
Classification: Legitimate public endpoint
```

**Marketing/Forms**:
```
Path patterns: /contact, /newsletter, /subscribe
Operations: Collect non-privileged information
Classification: Legitimate public endpoint
```

### Tools Requiring Authentication

**Manual Triggers/Operations**:
```
Path patterns: /manual/*, /trigger/*, /admin/*, /tools/*
Operations: Bypass normal workflow, trigger operations
Classification: MUST have authentication - FLAG if missing
```

**Data Manipulation Tools**:
```
Path patterns: /import, /export, /sync, /migrate
Operations: Bulk data operations
Classification: MUST have authentication
```

**Configuration Tools**:
```
Path patterns: /config, /settings, /update-config
Operations: Modify system behavior
Classification: MUST have authentication
```

### Call Chain Analysis

**Protected Through Call Chain**:
```
Frontend → Authenticated API → Internal Service → Helper Function
                ↑ Auth Check Here
Helper is protected even without direct auth check
```

**Unprotected Despite Name**:
```
/admin/register → Creates admin accounts
Despite "admin" in path, if publicly accessible = VULNERABILITY
```

### Universal Analysis Questions

1. **Direct Exposure Check**: Is this endpoint mapped to a URL/route?
2. **Call Origin Analysis**: What code paths lead to this function?
3. **Authentication Inheritance**: Do all callers enforce authentication?
4. **Functionality Assessment**: What operations does this perform?
5. **Data Access Scope**: What data can this endpoint access/modify?
6. **Side Effects**: What downstream operations are triggered?

### Classification Indicators

**Likely Protected**:
- Only called from authenticated middleware/filters
- No direct route mapping found
- All references from protected areas
- Session/token validation in call chain

**Likely Vulnerable**:
- Direct route with no auth middleware
- Called from public endpoints
- Performs privileged operations
- No authentication checks in path

### Classification Priority

1. **Actual functionality** (what it does) - most reliable
2. **Call chain analysis** (who can reach it)
3. **Path/naming patterns** (weakest indicator)

### Core Principle

Classify endpoints based on functionality and call chain analysis, not names or patterns. Public registration and basic forms are legitimate public endpoints. Tools providing additional functionality beyond basic user operations require authentication, regardless of their names or paths.

