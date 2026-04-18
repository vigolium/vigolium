# Code Anatomy: Team-02 (Agent Tool Execution + Approval System)

## Component Files

| File | Lines | Role |
|------|-------|------|
| x/tools/bash.go | 115 | BashTool implementation; direct bash -c execution |
| x/tools/webfetch.go | 168 | WebFetchTool; URL → ollama.com proxy with signing |
| x/tools/websearch.go | 181 | WebSearchTool; query → ollama.com search API |
| x/tools/registry.go | 132 | Tool registry; dispatch hub |
| x/agent/approval.go | ~650 | Approval gating logic; IsDenied, IsAllowed, AddToAllowlist, extractBashPrefix |
| x/agent/approval_unix.go | 28 | flushStdin (terminal raw mode helper) |
| x/agent/approval_windows.go | (stub) | Windows flushStdin stub |
| x/agent/approval_test.go | 542 | Test coverage for approval logic |
| x/cmd/run.go | ~580 | Agent chat loop; orchestrates tool dispatch + approval |

---

## Critical Function Inventory

### BashTool.Execute (x/tools/bash.go:53-114)
- Input: `args["command"]` (string, LLM-controlled)
- Action: `exec.CommandContext(ctx, "bash", "-c", command)` with 60s timeout
- Output: stdout + stderr, capped at 50000 bytes each
- Security notes: NO sanitization; bash interprets the full command including metacharacters, subshells, pipes, redirections; timeout is the only inherent limit

### WebFetchTool.Execute (x/tools/webfetch.go:74-167)
- Input: `args["url"]` (string, LLM-controlled)
- Validation: `url.Parse` only — accepts any parseable URL including `file://`, `data:`, etc.
- Action: sends `{"url": urlStr}` as JSON body to `https://ollama.com/api/web_fetch` with HMAC-signed Bearer token (user's `~/.ollama/id_ed25519` key)
- Concern: attaches user's Ollama signing credentials to LLM-directed requests; blanket tool approval means any URL is auto-approved after first approval

### Chat agent loop (x/cmd/run.go:163-514)
Key code paths:
1. LLM response received → `pendingToolCalls` appended (line 242)
2. For each tool call (line 369):
   a. `IsDenied` check (bash only) → blocks on pattern match (line 373)
   b. YoloMode check (line 400) → skips to execution
   c. `IsAllowed` check (line 404) → skips to execution if cached
   d. `RequestApproval` (line 405) → user prompt
   e. If `ApprovalAlways` → `AddToAllowlist` (line 428)
   f. `toolRegistry.Execute(call)` (line 436)
3. NOTE: `IsAutoAllowed` check is commented out (lines 391-394) — currently dead code

### IsDenied (x/agent/approval.go:175-193)
- Input: full command string
- Method: `strings.ToLower` then substring match against 22 patterns + 10 path patterns
- Gaps: tokenization-unaware; does not split on shell operators; does not parse quoted strings; checks only the literal command, not what bash will actually execute after expansion

### extractBashPrefix (x/agent/approval.go:204-300)
- Input: command string
- Method:
  1. Splits on `|` → takes `parts[0]`
  2. `strings.Fields` split (whitespace, no shell quoting)
  3. Checks `safeCommands` map: `{cat, ls, head, tail, less, more, file, wc, grep, find, tree, stat, sed}`
  4. Finds first non-flag, non-numeric arg that contains `/` or `\` or starts with `.`
  5. Rejects absolute paths, paths starting with `..` after Clean
  6. Returns `cmd:dir/` prefix
- Gaps:
  - Does NOT split on `;`, `&&`, `||` — only `|`
  - Does NOT handle shell quoting (uses `strings.Fields`)
  - Does NOT resolve symlinks (uses `path.Clean`, lexical only)
  - `sed` and `find` in `safeCommands` despite write/exec capabilities (`sed -i`, `find -exec`)
  - Prefix is computed from command args, not from what bash will actually expand

### IsAllowed (x/agent/approval.go:389-423)
- Input: toolName + args
- For bash: extracts prefix from current command, checks against stored prefixes hierarchically
- For non-bash: checks `a.allowlist[toolName]` — once ANY call approved, ALL future calls bypass
- Key path: `matchesHierarchicalPrefix` (line 427) uses `strings.HasPrefix(currentPath, storedPath)` — the stored prefix IS `tools/`, so `tools/` prefix match approves `tools/subdir/` etc.

### AddToAllowlist (x/agent/approval.go:459-478)
- For bash: calls `extractBashPrefix`; if non-empty stores to `a.prefixes`; fallback to exact command in `a.allowlist`
- For non-bash: stores toolName (NOT args) to `a.allowlist` — confirms blanket per-tool approval

### isCommandOutsideCwd (x/agent/approval.go:312-374)
- Splits on `|`, `;`, `&` (more thorough than extractBashPrefix)
- Checks each arg for `..` escape and absolute paths
- Does NOT handle `$()`, backticks, `${VAR}`, brace expansion
- Result is used ONLY for the visual warning in `RequestApproval`; does NOT block execution

---

## Data Flow Diagram (Text)

```
LLM Response JSON
  └── JSON deserialize → api.ToolCall{Function.Name, Function.Arguments}
        └── run.go:369 iterate pendingToolCalls
              ├── toolName == "bash"?
              │     ├── IsDenied(cmd) → BLOCK (substring pattern match)
              │     └── IsAutoAllowed(cmd) → skip approval [COMMENTED OUT]
              ├── YoloMode? → skip approval → Execute
              ├── IsAllowed(toolName, args)?
              │     ├── exact match in allowlist
              │     ├── bash: extractBashPrefix(cmd) → prefix in a.prefixes?
              │     │         → matchesHierarchicalPrefix(prefix)?
              │     └── non-bash: a.allowlist[toolName]
              ├── NO → RequestApproval → user prompt
              │           ├── ApprovalOnce → Execute
              │           ├── ApprovalAlways → AddToAllowlist → Execute
              │           └── ApprovalDeny → return deny message to LLM
              └── YES → Execute
                    └── toolRegistry.Execute(call)
                          ├── BashTool.Execute → exec("bash", "-c", command)
                          ├── WebFetchTool.Execute → HTTPS POST to ollama.com
                          └── WebSearchTool.Execute → HTTPS POST to ollama.com
```

---

## Security-Relevant State

| State Variable | Location | Populated By | Used By | Risk |
|---|---|---|---|---|
| `a.allowlist` | ApprovalManager | AddToAllowlist; non-bash = toolName only | IsAllowed | Blanket tool approval after 1 use |
| `a.prefixes` | ApprovalManager | AddToAllowlist; bash = extractBashPrefix | IsAllowed, matchesHierarchicalPrefix | Prefix over-approximation (pipe bypass, sed -i, find -exec) |
| `opts.YoloMode` | RunOptions | Caller (run command flag) | run.go:400 | Total approval bypass |
| `pendingToolCalls` | Chat loop | LLM response parsing | Tool dispatch | LLM directly populates the execution queue |

---

## Observed Test Gaps (from approval_test.go)

- No test for `cat tools/safe.go | tee /etc/cron.d/x` being allowed after `cat:tools/` is cached
- No test for `sed -i` after `sed tools/a.go` approval
- No test for `find tools/ -exec rm {} \;` after `find:tools/` approval
- No test for `cat tools/$(cat /etc/passwd)` command substitution bypass of `extractBashPrefix`
- No test for `;` or `&&` operator injection in `extractBashPrefix`
- No test for non-bash blanket approval (web_fetch URL scope)
- `IsAutoAllowed` tested but call site is commented out — dead code with live tests
