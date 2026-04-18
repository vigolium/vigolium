# Attack Surface Map: Group E — Agent / Tools / Privilege Transitions

## Entry Points

- `x/tools/bash.go:64` — `BashTool.Execute` — accepts arbitrary `command` string from LLM tool-call, passes it verbatim to `exec.CommandContext(ctx, "bash", "-c", command)`
- `x/agent/approval.go:154` — `IsAutoAllowed` — accepts LLM-supplied command string, matches against autoAllowPrefixes / autoAllowCommands
- `x/agent/approval.go:175` — `IsDenied` — accepts LLM-supplied command string, substring match against denyPatterns
- `x/agent/approval.go:204` — `extractBashPrefix` — accepts LLM-supplied command string, produces allowlist key for prefix matching
- `x/agent/approval.go:389` — `IsAllowed` — accepts toolName + args map from LLM output JSON
- `x/cmd/run.go:400` — agent loop dispatch — reads `opts.YoloMode` and `--experimental-yolo` flag to bypass all approval
- `x/tools/webfetch.go:79` — `WebFetchTool.Execute` — accepts arbitrary `url` string from LLM, passes to `url.Parse` then into HTTP POST body to `https://ollama.com/api/web_fetch`
- `x/tools/websearch.go:80` — `WebSearchTool.Execute` — accepts arbitrary `query` string from LLM
- `cmd/interactive.go:643` — `editInExternalEditor` — reads `OLLAMA_EDITOR`, `$VISUAL`, `$EDITOR` env vars; calls `exec.Command(args[0], args[1:]...)` with the editor name and args as binary path
- `cmd/launch/openclaw.go:771` — `ensureWebSearchPlugin` — calls `npm pack @ollama/openclaw-web-search` then `tar xzf <tgzPath> --strip-components=1 -C <pluginDir>` without path containment

## Trust Boundary Crossings

- **LLM output → shell**: `x/cmd/run.go:369-436` deserializes tool-call JSON from model response and routes `command` string directly to `bash -c`. The model is untrusted; the shell is trusted (user's process context). Approval gate sits in between but is bypassed by yolo mode, prefix-only matching, and shell metacharacters.
- **LLM output → HTTP request**: `x/tools/webfetch.go:90-130` takes LLM-supplied `url` and embeds it verbatim in a JSON POST to `ollama.com/api/web_fetch`. No scheme/host allowlist; `url.Parse` succeeds for `file://`, `javascript:`, internal IPs.
- **npm registry → filesystem**: `cmd/launch/openclaw.go:771-786` fetches npm tarball via `npm pack`, then extracts via `tar xzf` with `--strip-components=1 -C <dir>`. The tarball name comes from npm stdout (`tgzName := strings.TrimSpace(string(out))`). No digest verification; no path containment check on tar entries.
- **Environment variable → exec.Command binary path**: `cmd/interactive.go:656,677` takes `strings.Fields(editor)[0]` as the binary to execute, where `editor` is populated from `OLLAMA_EDITOR`, then `$VISUAL`, then `$EDITOR`. Attacker-controlled env means arbitrary binary execution.
- **Approval allowlist → second and subsequent commands**: Once a prefix like `cat:tools/` is in the session allowlist, any future command whose first path-like argument resolves to that prefix is automatically approved — including those with shell metacharacters after the first argument.

## Auth / AuthZ Decision Points

- `x/cmd/run.go:400-404` — yolo mode check — if `opts.YoloMode == true`, skips all approval for ALL tools for the entire session
- `x/agent/approval.go:175` — `IsDenied` — substring denylist, applied before approval check; easily bypassed by shell quoting
- `x/agent/approval.go:154` — `IsAutoAllowed` — currently dead (commented out in run.go:391-394), would have bypassed approval for `make`, `cargo build`, etc.
- `x/agent/approval.go:389` — `IsAllowed` — exact match + `extractBashPrefix`-based prefix match; does not parse shell syntax
- `x/agent/approval.go:480` — `RequestApproval` — user-facing interactive prompt; the only interactive gate before execution

## Validation / Sanitization Functions

- `x/agent/approval.go:204` — `extractBashPrefix` — extracts first path-like argument; rejects `..` escapes and absolute paths via `path.Clean` + sibling-escape check; does NOT parse shell metacharacters
- `x/agent/approval.go:175` — `IsDenied` — `strings.Contains(commandLower, pattern)` substring match; easily bypassed with quoting, `$'...'` syntax, empty-string insertion
- `x/tools/webfetch.go:85` — `url.Parse` — syntactic parse only; does not restrict scheme or host
- `cmd/interactive.go:656` — `exec.LookPath(name)` — checks binary existence but not that it is a safe executable

## Layer Trust Chain

| From Layer | To Layer | Trust Assumption | Holds for ALL paths? | Alternate Paths that Skip This Layer? |
|---|---|---|:---:|---|
| LLM model output | Approval gate (IsDenied) | LLM cannot craft strings that bypass substring denylist | NO | Shell quoting/escaping (`$'\x2f'`, `''` insertion, `${IFS}`) trivially defeats substring check |
| IsDenied check | extractBashPrefix prefix match | Only the first path-like arg determines the approval scope | NO | Second/third args, shell metacharacters after first arg, `find -exec`, redirection all bypass scope |
| Prefix allowlist | bash -c execution | Approved prefix covers the full semantic scope of the command | NO | `cat tools/file.go ; rm -rf ~` passes prefix check, full command sent to shell |
| ApprovalManager | bash -c execution | User interactively approved execution | NO | `--experimental-yolo` skips entire ApprovalManager for all tools/session |
| npm pack stdout | tar extraction path | tgzName from npm stdout is safe and the tarball contains no path-traversal entries | NO | npm pack stdout can be manipulated; tar entries with `../` components not filtered |
| tar extraction | pluginDir filesystem | `--strip-components=1 -C pluginDir` contains extraction to pluginDir | NO | No Go-level path containment; tar entries with absolute paths or `../` escape the dir on some platforms |
| $VISUAL/$EDITOR env | exec.Command binary | Binary name in VISUAL/EDITOR is the intended editor | NO | Attacker-controlled env injects arbitrary binary; `strings.Fields` splits on space, enabling flag injection |
| web_fetch url parameter | ollama.com proxy | URL is a valid http/https web URL | NO | `file://`, `ftp://`, `data:`, internal IP URLs pass `url.Parse`; forwarded to remote API |

## Trust Chain Gaps

- **Gap 1 (Shell metachar bypass)**: `extractBashPrefix` tokenizes only by `|`. All other shell control operators (`;`, `&&`, `||`, `$(...)`, backticks, `>`, `>>`, brace expansion, `find -exec`) are invisible to the approval logic. Any command whose first pipe-segment prefix matches an approved pattern executes arbitrary code after the first `|`. Commands not using pipes at all use `;`, `&&`, etc. which are completely unscanned.
- **Gap 2 (Multi-arg bypass)**: Only the first path-like argument to `extractBashPrefix` determines the approval key. All subsequent args are ignored by approval but passed to bash. Example: `cat tools/file.go /etc/shadow` → approved because prefix is `cat:tools/`.
- **Gap 3 (Denylist bypass)**: `IsDenied` is a case-folded substring match. Bash quoting (`/e''tc/passwd`, `$'\x2fetc\x2fpasswd'`, `${IFS}`) defeats it. The denylist provides false security assurance.
- **Gap 4 (Yolo session bypass)**: `--experimental-yolo` passed to `ollama run` disables ALL approval including denylist checking for the entire session. This is documented but the flag name obscures the security implication.
- **Gap 5 (ZipSlip/tar no containment)**: `ensureWebSearchPlugin` in `openclaw.go:782` runs `tar xzf <tgzPath> --strip-components=1 -C <pluginDir>` where `tgzPath` is derived from npm stdout. No Go-level path filtering of tar entries. Malicious or man-in-the-middle npm package with `../` entries can write files outside `~/.openclaw/extensions/openclaw-web-search/`.
- **Gap 6 ($VISUAL/$EDITOR arbitrary binary)**: `editInExternalEditor` (interactive.go:643-677) uses `OLLAMA_EDITOR` > `$VISUAL` > `$EDITOR` without validation. `strings.Fields` splitting enables flag injection. An env-level attacker executes an arbitrary binary as the ollama process user.
- **Gap 7 (web_fetch no scheme allowlist)**: `url.Parse` in webfetch.go:85 accepts any syntactically valid URL. `file://`, `ftp://`, and internal IP addresses all pass. The URL is forwarded to `ollama.com/api/web_fetch`; if the remote API follows the URL, this is SSRF via the cloud proxy.
