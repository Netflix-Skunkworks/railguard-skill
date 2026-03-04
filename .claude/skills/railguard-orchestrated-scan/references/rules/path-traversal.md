<!-- CANARY:RGS:rule:path-traversal -->

# Path Traversal Detection

## Prerequisites
- File system operations detected
- User input influences file paths
- File upload/download functionality

## Overview
Path traversal (directory traversal) occurs when user input is used to construct
file paths without proper sanitization, allowing attackers to access files outside
the intended directory. This can lead to:
- Reading sensitive configuration files
- Accessing source code
- Reading credentials and secrets
- Overwriting critical files
- Remote code execution (via file upload + traversal)

## Focus Areas

### 1. File Path Construction
Locations where user input becomes part of file paths:
- File download endpoints
- File upload destinations
- Template/view loading
- Configuration file loading
- Log file access
- Static file serving

### 2. Dangerous Sequences
Patterns that indicate traversal attempts:
- `../` (parent directory)
- `..\` (Windows)
- `....//` (filter bypass)
- URL encoded: `%2e%2e%2f`, `%2e%2e/`
- Double encoding: `%252e%252e%252f`
- Null bytes: `file.txt%00.jpg`

### 3. Absolute Path Injection
Direct absolute path usage:
- `/etc/passwd`
- `C:\Windows\System32\`
- `file:///` protocol

## Vulnerable Patterns

### Python - os.path / pathlib (CRITICAL)
```python
# VULNERABLE - direct concatenation
filename = request.args.get('file')
filepath = '/var/www/uploads/' + filename
with open(filepath, 'r') as f:  # Path traversal!
    return f.read()

# VULNERABLE - format string
filename = request.args.get('file')
filepath = f'/var/www/uploads/{filename}'
return send_file(filepath)

# VULNERABLE - os.path.join can be bypassed with absolute paths
filename = request.args.get('file')
filepath = os.path.join('/var/www/uploads', filename)
# If filename is '/etc/passwd', os.path.join returns '/etc/passwd'!
```

### JavaScript/Node.js - fs/path (CRITICAL)
```javascript
// VULNERABLE - direct concatenation
const filename = req.query.file;
const filepath = './uploads/' + filename;
fs.readFile(filepath, (err, data) => { ... });

// VULNERABLE - path.join can be bypassed
const filename = req.params.filename;
const filepath = path.join(__dirname, 'uploads', filename);
// path.join('../../../etc/passwd') = '../../../etc/passwd'

// VULNERABLE - res.sendFile
app.get('/files/:name', (req, res) => {
    res.sendFile(req.params.name, { root: './uploads' });
});
```

### Java - File/Path (CRITICAL)
```java
// VULNERABLE - direct path construction
String filename = request.getParameter("file");
File file = new File("/var/www/uploads/" + filename);
// Path traversal possible!

// VULNERABLE - Paths.get
String filename = request.getParameter("file");
Path path = Paths.get("/var/www/uploads", filename);
// Still vulnerable to ../ sequences
```

### Go - filepath (CRITICAL)
```go
// VULNERABLE - path concatenation
filename := r.URL.Query().Get("file")
filepath := "./uploads/" + filename
data, err := ioutil.ReadFile(filepath)

// VULNERABLE - filepath.Join doesn't prevent traversal
filename := r.FormValue("file")
filepath := filepath.Join("./uploads", filename)
// "../../../etc/passwd" still works
```

### PHP - file operations (CRITICAL)
```php
// VULNERABLE - direct include
$page = $_GET['page'];
include("pages/" . $page);  // LFI!

// VULNERABLE - file_get_contents
$file = $_GET['file'];
echo file_get_contents("uploads/" . $file);

// VULNERABLE - readfile
$file = $_GET['download'];
readfile("files/" . $file);
```

## Detection Patterns

### Dangerous Sinks
```regex
# Python
open\s*\(\s*[^)]*\+
send_file\s*\(
send_from_directory\s*\(
os\.path\.join\s*\([^)]*request
pathlib\.Path\s*\([^)]*request

# JavaScript/Node.js
fs\.(readFile|writeFile|readFileSync|writeFileSync|createReadStream)\s*\(
res\.(sendFile|download)\s*\(
path\.join\s*\([^)]*req\.

# Java
new\s+File\s*\([^)]*getParameter
Paths\.get\s*\([^)]*getParameter
FileInputStream\s*\([^)]*getParameter

# Go
(ioutil\.ReadFile|os\.Open|os\.ReadFile)\s*\(
filepath\.Join\s*\([^)]*r\.(URL|Form)

# PHP
(include|require|include_once|require_once)\s*\(
(file_get_contents|readfile|fopen|file)\s*\(
```

### User Input Patterns
```regex
\.\./
\.\.\\
%2e%2e%2f
%2e%2e/
\.\.%2f
%252e%252e%252f
```

## Safe Patterns

### Python - Secure Path Handling
```python
import os
from pathlib import Path

# SAFE - resolve and check containment
def safe_join(base_dir, filename):
    base = Path(base_dir).resolve()
    filepath = (base / filename).resolve()
    
    # Ensure resolved path is within base directory
    if not str(filepath).startswith(str(base)):
        raise ValueError("Path traversal detected")
    
    return filepath

# SAFE - allowlist filenames
ALLOWED_FILES = {'report.pdf', 'data.csv', 'image.png'}

def get_file(filename):
    if filename not in ALLOWED_FILES:
        raise ValueError("File not allowed")
    return open(f'/var/www/uploads/{filename}', 'rb')
```

### JavaScript/Node.js - Secure Path Handling
```javascript
const path = require('path');
const fs = require('fs');

// SAFE - resolve and verify
function safeJoin(baseDir, filename) {
    const base = path.resolve(baseDir);
    const filepath = path.resolve(path.join(baseDir, filename));
    
    if (!filepath.startsWith(base)) {
        throw new Error('Path traversal detected');
    }
    
    return filepath;
}

// SAFE - express static with restrictions
app.use('/files', express.static('uploads', {
    dotfiles: 'deny',
    index: false
}));
```

### Java - Secure Path Handling
```java
// SAFE - canonical path check
public File safeFile(String baseDir, String filename) throws IOException {
    File base = new File(baseDir).getCanonicalFile();
    File file = new File(base, filename).getCanonicalFile();
    
    if (!file.getPath().startsWith(base.getPath())) {
        throw new SecurityException("Path traversal detected");
    }
    
    return file;
}

// SAFE - Path normalization check
public Path safePath(String baseDir, String filename) {
    Path base = Paths.get(baseDir).toAbsolutePath().normalize();
    Path file = base.resolve(filename).toAbsolutePath().normalize();
    
    if (!file.startsWith(base)) {
        throw new SecurityException("Path traversal detected");
    }
    
    return file;
}
```

### Go - Secure Path Handling
```go
// SAFE - clean and verify
func safeJoin(baseDir, filename string) (string, error) {
    // Clean the input
    cleaned := filepath.Clean(filename)
    
    // Reject absolute paths
    if filepath.IsAbs(cleaned) {
        return "", errors.New("absolute paths not allowed")
    }
    
    // Join and resolve
    fullPath := filepath.Join(baseDir, cleaned)
    absBase, _ := filepath.Abs(baseDir)
    absPath, _ := filepath.Abs(fullPath)
    
    // Verify containment
    if !strings.HasPrefix(absPath, absBase) {
        return "", errors.New("path traversal detected")
    }
    
    return fullPath, nil
}
```

## Risk Assessment

### CRITICAL
- User-controlled filename in file read/write operations
- Template inclusion with user input (LFI leading to RCE)
- File upload with user-controlled destination path
- No path validation before file operations

### HIGH
- path.join/os.path.join without containment check
- File download endpoints with filename parameter
- Static file serving with user-controlled path component

### MEDIUM
- Partial path sanitization (blocking ../ but not encoded)
- Symlink-based traversal possibilities
- Chrooted environments with potential escape

### LOW
- Allowlist-based file access
- Files served from memory/database, not filesystem

## Bypass Techniques to Consider

### Encoding Bypasses
```text
../ → %2e%2e%2f
../ → %2e%2e/
../ → ..%2f
../ → %252e%252e%252f (double encoding)
../ → ....// (if ../ is stripped once)
../ → ..;/ (Tomcat)
```

### Null Byte Injection (older systems)
```text
../../etc/passwd%00.jpg
../../etc/passwd\x00.png
```

### OS-Specific
```text
# Windows
..\..\..\windows\win.ini
..\..\..\..\..\..\windows\win.ini

# Unix
../../../etc/passwd
....//....//....//etc/passwd
```

