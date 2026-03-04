## Tool Usage Logging

When you use LSP or ast-grep during analysis, log each invocation for debugging.
This is a fire-and-forget append — do NOT wait for the command to complete or check
its output. Do NOT include log entries in your response stub.

After each LSP operation:
```bash
bash {{TOOL_LOG_SCRIPT}} {{REPO_PATH}} {{SCAN_ID}} {{AGENT_NAME}} lsp <operation> "<brief detail>"
```

After each ast-grep search:
```bash
bash {{TOOL_LOG_SCRIPT}} {{REPO_PATH}} {{SCAN_ID}} {{AGENT_NAME}} ast-grep run "<pattern used>"
```

Examples:
```bash
bash {{TOOL_LOG_SCRIPT}} {{REPO_PATH}} {{SCAN_ID}} database-injection lsp goToDefinition "cursor.execute in db/queries.py:42"
bash {{TOOL_LOG_SCRIPT}} {{REPO_PATH}} {{SCAN_ID}} database-injection ast-grep run "$X.execute(f\"$$$\")"
```

The log file persists at `{{REPO_PATH}}/scan-results/tool-usage-{{SCAN_ID}}.log` for
manual review. It is never cleaned up automatically.

To disable logging entirely, set `RAILGUARD_TOOL_LOG=0` in the environment before
the scan starts.
