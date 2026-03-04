<!-- CANARY:RGS:rule:xss-detection -->

# Cross-Site Scripting (XSS) Detection Rules

## R: Risk First

**Goal**: Identify XSS vulnerabilities through static code analysis by recognizing unsafe patterns and dangerous sinks
**Risk**: XSS enables client-side script execution leading to session hijacking, data theft, account impersonation, and malicious content injection
**Context**: Code analysis of web applications that render user-controlled data in browser contexts

## A: Attached Constraints

**CRITICAL ANALYSIS BOUNDARIES**:
- ALWAYS validate ALL user controlled variable outputs for XSS
- ALWAYS leverage a checklist for verification of user-controlled output variables
- NEVER assume framework defaults provide complete protection without verifying escape hatch usage
- ALWAYS trace data flow from user input sources to rendering sinks
- ALWAYS note user-specifiable variables for analysis, leverage a todo list to confirm they have each been traced
- NEVER ignore indirect paths through databases, caches, or file systems
- NEVER rely on function names alone - analyze actual implementation
- ALWAYS check for disabled auto-escaping or unsafe rendering modes
- NEVER overlook concatenation patterns that bypass framework protections

**ANALYSIS AWARENESS**:
- XSS vulnerabilities range from MEDIUM to HIGH based on context
- Framework escape hatches are primary vulnerability sources
- String concatenation often bypasses security features
- Template literal usage requires special attention
- Context-appropriate encoding is essential - HTML encoding won't protect in JavaScript contexts

## I: Interpretative Framing

**When examining output rendering**:
- Trace user input from entry points to output sinks
- Identify dangerous sink methods (innerHTML, document.write, eval)
- Look for string concatenation building HTML/JavaScript
- Check for framework-specific unsafe rendering methods

**When assessing XSS type**:
- **Stored XSS**: User input persisted in database, then rendered to other users (HIGH severity)
- **Reflected XSS**: User input immediately returned in response without encoding (HIGH severity)
- **DOM XSS**: Client-side JavaScript using untrusted data in dangerous sinks (MEDIUM-HIGH severity)

**When assessing code patterns**:
- Direct rendering of user input is highest risk
- Concatenation patterns often bypass protections
- Configuration options may disable security features
- Custom rendering functions may lack proper escaping

## L: Local Defaults

### Dangerous Sink Patterns

**Server-Side Sinks**:
- `render_template_string()` with user data
- `Markup()` / `mark_safe()` with user data
- Response without proper Content-Type with escaping
- Direct HTML string concatenation returned to client

**Client-Side DOM Sinks**:
```javascript
// DANGEROUS - Direct assignment to innerHTML
element.innerHTML = userInput;  // XSS vulnerability
document.getElementById('output').innerHTML = location.hash.substr(1);  // DOM XSS

// DANGEROUS - document.write family
document.write(userInput);
document.writeln(userInput);

// DANGEROUS - eval and related
eval(userInput);
new Function(userInput);
setTimeout(userInput, 1000);  // When userInput is a string
setInterval(userInput, 1000);  // When userInput is a string

// DANGEROUS - URL manipulation
location.href = userInput;
location.assign(userInput);
window.open(userInput);

// DANGEROUS - jQuery methods with user data
$(selector).html(userInput);
$(selector).append(userInput);
$(selector).prepend(userInput);
$(selector).after(userInput);
$(selector).before(userInput);
```

### Framework-Specific Escape Hatches

**React Unsafe Patterns**:
```jsx
// VULNERABLE - dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{__html: userInput}} />

// VULNERABLE - javascript: URLs
<a href={`javascript:${userInput}`}>Click</a>
<a href={userInput}>Click</a>  // If userInput could be javascript:

// SAFE - React auto-escapes this
<div>{userInput}</div>
```

**Angular Unsafe Patterns**:
```typescript
// VULNERABLE - bypassing security
this.sanitizer.bypassSecurityTrustHtml(userInput);
this.sanitizer.bypassSecurityTrustScript(userInput);
this.sanitizer.bypassSecurityTrustStyle(userInput);
this.sanitizer.bypassSecurityTrustUrl(userInput);
this.sanitizer.bypassSecurityTrustResourceUrl(userInput);

// VULNERABLE - innerHTML binding
<div [innerHTML]="userInput"></div>  // Without sanitization
```

**Vue.js Unsafe Patterns**:
```vue
<!-- VULNERABLE - v-html directive -->
<div v-html="userInput"></div>

<!-- SAFE - text interpolation -->
<div>{{ userInput }}</div>
```

**Django/Jinja2 Unsafe Patterns**:
```html
<!-- VULNERABLE - safe filter -->
{{ user_input|safe }}

<!-- VULNERABLE - mark_safe in Python -->
return HttpResponse(mark_safe(user_input))

<!-- VULNERABLE - autoescape off -->
{% autoescape off %}
  {{ user_input }}
{% endautoescape %}
```

**Flask Unsafe Patterns**:
```python
# VULNERABLE - Markup()
return Markup(user_input)

# VULNERABLE - render_template_string
return render_template_string(user_input)
```

**Express/EJS Unsafe Patterns**:
```ejs
<%# VULNERABLE - unescaped output %>
<%- user_input %>

<%# SAFE - escaped output %>
<%= user_input %>
```

### Output Encoding Requirements

**HTML Context Encoding**:
Apply HTML entity encoding when inserting user data between HTML tags:
- `&` → `&amp;`
- `<` → `&lt;`
- `>` → `&gt;`
- `"` → `&quot;`
- `'` → `&#x27;`

**HTML Attribute Context Encoding**:
When placing user data in HTML attribute values:
- Always quote attribute values with `"` or `'`
- Apply encoding for non-alphanumeric characters using `&#xHH;` format
- Avoid placing user data in event handler attributes

**JavaScript Context Encoding**:
- Only place user data in quoted JavaScript string values
- Use Unicode `\uXXXX` encoding for non-alphanumeric characters
- Verify Content-Type headers are `application/json` for JSON responses

**URL Context Encoding**:
- Apply URL encoding using `%HH` format for URL parameters
- When URLs in HTML attributes: URL encode first, then HTML attribute encode
- Validate URLs don't start with `javascript:` or `data:`

### Safe Sink Alternatives

**Instead of innerHTML**:
```javascript
// SAFE - textContent for text
element.textContent = userInput;

// SAFE - createTextNode for DOM insertion
const text = document.createTextNode(userInput);
element.appendChild(text);

// SAFE - setAttribute for safe attributes
element.setAttribute('class', userInput);  // Only for safe attributes
```

**Safe HTML Attributes** (can contain user data with encoding):
- align, alt, bgcolor, border, class, color, cols, colspan
- dir, height, lang, multiple, rows, rowspan, span
- summary, tabindex, title, valign, value, width

**Dangerous Contexts to Avoid**:
- Never place user data in script tags
- Never place user data in HTML comments
- Never place user data in CSS style blocks
- Never place user data in tag or attribute names
- Never place user data in event handlers (onclick, onerror, etc.)

### XSS Vulnerability Examples

**Reflected XSS**:
```python
# VULNERABLE - Flask
@app.route('/search')
def search():
    query = request.args.get('q')
    return f"<h1>Results for: {query}</h1>"  # XSS!

# SECURE
@app.route('/search')
def search():
    query = request.args.get('q')
    return render_template('search.html', query=query)  # Auto-escaped
```

**Stored XSS**:
```python
# VULNERABLE - Stored then rendered
comment = request.form['comment']
db.save_comment(comment)  # Stored without sanitization

# Later, rendered to other users without escaping
@app.route('/comments')
def show_comments():
    comments = db.get_comments()
    html = ''.join(f'<div>{c.text}</div>' for c in comments)  # XSS!
    return html
```

**DOM XSS**:
```javascript
// VULNERABLE - Hash-based DOM XSS
document.getElementById('output').innerHTML = location.hash.substr(1);

// VULNERABLE - URL parameter DOM XSS
const params = new URLSearchParams(window.location.search);
document.getElementById('name').innerHTML = params.get('name');
```

## G: Generative Path Checks

1. **User Input Identification**: Can user input reach HTML rendering contexts?
2. **Dangerous Sinks Detection**: Are innerHTML, document.write, or eval used with user data?
3. **Escaping Verification**: Is context-appropriate encoding applied before rendering?
4. **Framework Escape Hatches**: Are dangerouslySetInnerHTML, v-html, |safe filters used?
5. **String Concatenation**: Is HTML being built through string concatenation with user data?
6. **Indirect Data Paths**: Does user input flow through storage before rendering?
7. **Configuration Check**: Is auto-escaping disabled anywhere?
8. **Custom Rendering**: Do custom render functions implement proper escaping?
9. **Content-Type Headers**: Are response content-types set correctly?
10. **URL Validation**: Are href/src values validated for javascript: and data: protocols?

## U: Uncertainty Disclosure

**When uncertain about vulnerability presence**:
- If concatenation builds HTML/JS with user data, flag as likely XSS
- If framework escape hatches are used, assume vulnerable unless proven safe
- If custom rendering exists without escaping evidence, assume vulnerable
- Default to flagging with note about uncertainty

**When severity assessment is unclear**:
- Default to HIGH for XSS with unclear context
- Stored XSS (affects multiple users) = HIGH
- Reflected XSS (requires user interaction) = HIGH
- DOM XSS (client-side only) = MEDIUM-HIGH
- Consider authentication requirements as mitigating factors

## A: Auditability

**Required Analysis Comments**:
- DANGEROUS_SINK: Mark where user input reaches browser rendering
- DATA_FLOW: Document traced path from input to sink
- ESCAPE_BYPASS: Note where framework protections are bypassed
- XSS_TYPE: Classify as stored, reflected, or DOM-based

**Code Pattern Documentation**:
- Document user input entry points
- Map data flow through application
- Note all rendering locations
- Flag framework escape hatch usage
- Record encoding/sanitization presence or absence

## R+D: Revision + Dialogue

**Analysis Review Questions**:
- "Does user input reach dangerous browser sinks without encoding?"
- "Are framework security features being bypassed or disabled?"
- "Is HTML/JavaScript being built through string concatenation?"
- "Can user input flow indirectly through storage to rendering?"
- "Are all user-controlled output variables traced to their sinks?"
- "Is context-appropriate encoding applied at rendering time?"

**Core Analysis Principle**:
Identify all paths where user input can reach browser rendering contexts. Look for dangerous sinks (innerHTML, document.write, eval) and string concatenation patterns that bypass framework protections. Always trace complete data flow from input to output, including indirect paths through storage. Classify XSS type (stored, reflected, DOM) based on data persistence and attack vector.
