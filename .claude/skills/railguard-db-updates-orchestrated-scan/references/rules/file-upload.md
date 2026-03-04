<!-- CANARY:RGS:rule:file-upload -->
# File Upload Vulnerability Detection

## Overview

File upload vulnerabilities occur when a web server allows users to upload files without sufficiently validating their name, type, contents, or size. Even a basic image upload can become an attack vector for remote code execution.

## Impact Spectrum

**Worst Case (Critical):** Server executes uploaded file as code (web shell) - full server control
**High:** Filename not validated - attacker overwrites critical files or uses directory traversal
**Medium:** File size not validated - DoS via disk exhaustion
**Low:** MIME type spoofing for stored XSS via SVG/HTML uploads

## What Makes File Uploads Dangerous

### Web Shell Deployment
If a server allows uploading server-side scripts (PHP, JSP, ASPX) AND is configured to execute them, attackers gain full control:
- Read/write arbitrary files
- Execute system commands
- Pivot to internal infrastructure

### The Two Key Factors
1. **What the server fails to validate** - name, type, contents, size
2. **What restrictions exist after upload** - execution permissions, storage location

## Detection Focus Areas

### 1. Insufficient Type Validation
- Trusting client-provided `Content-Type` header
- Blacklisting dangerous extensions instead of whitelisting safe ones
- Not verifying file contents match claimed type

### 2. Filename Handling Failures
- No sanitization of filename from `multipart/form-data`
- Allowing path traversal sequences (`../`)
- No collision prevention (overwriting existing files)

### 3. Execution in Upload Directory
- Upload directory configured to execute scripts
- Files stored with original extension intact
- No separation between storage and execution contexts

### 4. Race Conditions
- File uploaded to main filesystem, then validated, then removed if invalid
- Window exists between upload and removal where file can be executed
- URL-based uploads with predictable temporary paths

## Bypass Techniques to Detect Missing Protection Against

### Extension Obfuscation
- Case variation: `exploit.pHp`, `exploit.PHP`
- Multiple extensions: `exploit.php.jpg`
- Trailing characters: `exploit.php.` or `exploit.php%20`
- URL encoding: `exploit%2Ephp`
- Null bytes: `exploit.asp;.jpg` or `exploit.asp%00.jpg`
- Unicode normalization: `xC0 x2E` sequences

### Content-Type Manipulation
- Sending `image/jpeg` header with PHP payload
- Polyglot files (valid image header + embedded code)

### Configuration File Upload
- `.htaccess` to override Apache settings
- `web.config` for IIS directory-specific configuration
- Mapping custom extensions to executable MIME types

## Vulnerable Patterns to Identify

### Direct Execution Risk
- Upload directory within web root
- No `.htaccess` or equivalent to prevent script execution
- Server configured to execute uploaded file types

### Validation Gaps
- Only checking `Content-Type` header (easily spoofed)
- Blacklist-based extension blocking (incomplete)
- Not checking file magic bytes/signatures
- No file size limits

### Path/Name Issues
- Using original filename without sanitization
- No directory isolation for uploads
- Storing files with predictable names

## Client-Side Attack Vectors
Even without server execution, uploads can enable:
- **Stored XSS**: HTML/SVG files with `<script>` tags
- **XXE**: XML-based files (DOCX, XLSX) parsed by server

## Safe Patterns (Verify Presence)

### Essential Protections
- Whitelist of allowed extensions
- MIME type verification against actual content (magic bytes)
- Filename sanitization (strip path components, generate random names)
- Size limits enforced
- Upload to non-executable directory
- Files served with `Content-Disposition: attachment`

### Strong Protections
- Separate domain/CDN for user uploads (same-origin isolation)
- File content scanning/validation
- Temporary storage with validation before final placement

## Severity Assessment

**CRITICAL:**
- Server-side script upload without execution prevention
- No extension validation
- Upload to web-accessible executable directory

**HIGH:**
- Bypassable extension validation (blacklist only)
- Content-Type trusted without content verification
- Path traversal possible in filename

**MEDIUM:**
- Missing file size limits
- Predictable upload paths enabling race conditions
- HTML/SVG upload allowing stored XSS

**LOW:**
- Minor MIME type inconsistencies
- Missing but non-exploitable validation gaps
