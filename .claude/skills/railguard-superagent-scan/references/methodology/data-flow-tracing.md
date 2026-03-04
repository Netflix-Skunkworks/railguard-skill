<!-- CANARY:RGS:methodology:data-flow-tracing -->
# Data Flow Tracing Methodology

Trace user-controllable inputs from their entry points to security-sensitive sinks.
Record every flow with accurate transform metadata. Do NOT assess vulnerability
exploitability during tracing — that is handled by the analysis passes that consume
these traces.

## Source Identification

Identify ALL user-controllable input entry points:

- **HTTP inputs**: query params, request body fields, path/route params, headers, cookies, uploaded files
- **API-specific inputs**: GraphQL resolver arguments, gRPC request fields
- **Non-HTTP inputs**: CLI arguments, WebSocket messages, message queue payloads, event bus data
- **Indirect inputs**: environment variables an attacker could influence, external config sources
- **Second-order inputs**: database reads of values that were originally user-supplied (flag as `database_read`)
- **Wrapped inputs**: data extracted by middleware, DTO/model binding, decorators, or utility functions — trace THROUGH the abstraction

### Input Type Taxonomy

| Type | Description | Examples |
|------|-------------|---------|
| `request_param` | URL query parameter (?key=value) | `request.args.get('id')`, `req.query.id`, `@QueryParam` |
| `request_body` | Request body (JSON, form data, multipart) | `request.json`, `req.body`, `@RequestBody` |
| `path_param` | URL path parameter / route segment | `request.view_args`, `req.params`, `@PathVariable` |
| `header` | HTTP request header value | `request.headers.get()`, `req.headers`, `@RequestHeader` |
| `cookie` | Cookie value | `request.cookies`, `req.cookies`, `@CookieValue` |
| `file` | Uploaded file (name, content, metadata) | `request.files`, `req.file`, `@RequestPart` |
| `url` | Full URL or URL fragment | URL components from request |
| `websocket` | WebSocket message payload | WebSocket message handlers |
| `graphql_arg` | GraphQL query / mutation argument | GraphQL resolver arguments |
| `grpc_field` | gRPC request message field | gRPC request objects |
| `cli_arg` | Command-line argument or flag | `sys.argv`, `process.argv`, `os.Args` |
| `env_var` | Environment variable (user-influenced) | `os.environ`, `process.env`, `System.getenv` |
| `message_queue` | Data from message queue or pub/sub | Queue/event bus payloads |
| `database_read` | Data read from DB that was originally user-supplied | Second-order input |

## Sink Type Taxonomy

These are the dangerous operations that user input can flow to:

### Critical Severity Sinks

| Sink Type | Description | What to look for |
|-----------|-------------|-----------------|
| `sql_query` | SQL query construction | `cursor.execute()`, `.query()`, `PreparedStatement` with string concat |
| `nosql_query` | NoSQL query construction | `.find()`, `.findOne()`, `$where`, `$regex` with user input |
| `command_exec` | OS command / shell execution | `subprocess.run()`, `child_process.exec()`, `Runtime.exec()` |
| `code_eval` | Dynamic code evaluation | `eval()`, `exec()`, `new Function()`, `vm.runInContext()` |
| `template_compile` | Template compilation with user input | `render_template_string()`, `Template(user_input)`, `ejs.render()` |
| `deserialization` | Object deserialization from untrusted data | `pickle.loads()`, `yaml.load()`, `ObjectInputStream.readObject()` |
| `file_execution` | Executable file handling / upload | `require()`, `import()`, `__import__()`, `dlopen()` |
| `reflection` | Dynamic class loading / method invocation | `Class.forName()`, `getattr()`, reflection APIs |

### High Severity Sinks

| Sink Type | Description | What to look for |
|-----------|-------------|-----------------|
| `html_output` | Direct HTML output without escaping | `|safe`, `Markup()`, unescaped template rendering |
| `dom_sink` | DOM manipulation sinks | `innerHTML`, `document.write()`, `insertAdjacentHTML()` |
| `http_request` | HTTP request URL or body construction | `requests.get(url)`, `fetch(url)`, `HttpClient` |
| `url_fetch` | URL fetching / downloading resources | URL download, remote resource fetch |
| `file_path` | File path construction | `os.path.join()`, `fs.readFile()`, `new File()` |
| `xml_parse` | XML parsing operations | `etree.parse()`, `DocumentBuilderFactory`, `DOMParser` |
| `xpath_query` | XPath query construction | XPath with user input |
| `ldap_query` | LDAP query construction | `ldap.search()`, `DirContext.search()` |

### Medium Severity Sinks

| Sink Type | Description |
|-----------|-------------|
| `redirect` | URL redirect / forward targets (open redirect risk) |
| `header_set` | HTTP response header value setting (header injection / CRLF) |
| `file_storage` | File storage location / write destination |
| `graphql_query` | Dynamic GraphQL query construction |
| `email_header` | Email header or body construction |
| `regex_compile` | Regular expression compilation with user input (ReDoS risk) |
| `crypto_input` | User input used as cryptographic key, IV, or seed |

### Low Severity Sinks

| Sink Type | Description |
|-----------|-------------|
| `log_output` | Log message construction (log injection / forging) |
| `sse_output` | Server-Sent Events or streaming output |

## Forward Tracing

For each confirmed source, trace data forward through:

1. Variable assignments and reassignments
2. Function call arguments -> into the function body -> through return values
3. Object/dict attribute setting -> later attribute access
4. Collection insertion -> later iteration or index access
5. String concatenation, interpolation, formatting (taint propagates through these)
6. Cross-file flows via imports and function calls
7. Async chains: callbacks, promises, await expressions
8. Stored-then-retrieved paths (user input -> DB write -> DB read -> sink)

## Transform Vocabulary

Use these exact values when recording transforms applied along a flow path:

| Transform | Description | Protects Against |
|-----------|-------------|-----------------|
| `escaped` | Generic escaping (language/framework default) | Context-dependent |
| `html_encoded` | HTML entity encoding (html.escape, he.encode) | XSS in HTML context |
| `url_encoded` | URL/percent encoding (encodeURIComponent, urllib.quote) | Injection in URL context |
| `sanitized` | HTML sanitization (DOMPurify, bleach.clean) | XSS |
| `parameterized` | Parameterized query / prepared statement binding | SQL injection |
| `prepared` | Prepared statement (synonym for parameterized) | SQL injection |
| `shell_escaped` | Shell argument escaping (shlex.quote) | Command injection |
| `path_validated` | Path traversal validation (realpath check, chroot) | Path traversal |
| `basename_only` | Filename extracted via basename / path.name | Path traversal |
| `url_validated` | URL scheme/host validation or allowlisting | SSRF |
| `allowlisted` | Value checked against explicit allowlist | Various |
| `type_cast` | Type coercion (parseInt, Number(), int()) | Type confusion |
| `length_checked` | Length or size constraint enforced | Various |
| `regex_validated` | Validated against a restrictive regex pattern | Various |
| `json_stringified` | JSON.stringify or equivalent serialization | Log/SSE injection |
| `none` | No transform applied | Nothing |
| `other` | Novel transform not in this list | Treat as non-protecting |

### When a Transform Protects

A transform protects ONLY in the correct context:
- `parameterized` protects SQL, NOT if concatenation happens elsewhere
- `html_encoded` protects HTML output, NOT SQL or OS commands
- `url_encoded` protects URL context, NOT HTML or SQL
- `type_cast` eliminates string injection for THAT value only
- `.trim()` / `.strip()` / `toString()` are NOT security transforms — do not record

A transform that is real but insufficient for the target sink should still be recorded
(so analysis passes see it) but should be noted as insufficient.

## Output Format

For each traced flow, record:

```
Source: <file>:<line> — <input_type> — <variable_name>
Sink: <file>:<line> — <sink_type>
Transforms: [<transform1>, <transform2>, ...] or [none]
Vulnerable: true/false (is the transform sufficient for the sink context?)
```

## Completeness Checklist

Before completing data flow tracing, verify:

- Every route handler / endpoint / entry point has been examined
- For each handler: params, body, headers, cookies, path segments, and files checked
- Each input traced through variable assignments, function calls, object attributes to every sink
- Sinks beyond SQL/XSS checked: command exec, redirects, file paths, headers, logs, templates, deserialization, regex, eval, reflection
- Transforms recorded accurately using the vocabulary above
