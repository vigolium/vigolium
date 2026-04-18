Phase: 8
Sequence: 024
Slug: non-bash-tool-blanket-approval
Verdict: VALID
Rationale: Tracer confirmed blanket tool approval with no argument scoping; Advocate raised server-side filtering as potential defense but it is external, unverifiable, and cannot be relied upon.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: check-2-ambiguous -- server-side filtering at ollama.com is unverifiable from local code
Debate: archon/chamber-workspace/chamber-B/debate.md

## Summary

Non-bash tools (web_fetch, web_search) are added to the session allowlist by tool name only (`a.allowlist[toolName] = true` at approval.go:477). After a user approves any invocation of `web_fetch`, all subsequent invocations with ANY URL are auto-approved. This enables the LLM to perform SSRF via the Ollama web fetch proxy (`ollama.com/api/web_fetch`), targeting cloud metadata endpoints, internal services, or arbitrary URLs with the user's Ollama signing credentials attached.

## Location

- `x/agent/approval.go:477` -- `a.allowlist[toolName] = true` stores tool name without arguments
- `x/agent/approval.go:417-419` -- `toolName != "bash" && a.allowlist[toolName]` returns true for any args
- `x/tools/webfetch.go:85` -- `url.Parse(urlStr)` accepts any scheme/host
- `x/tools/webfetch.go:109-115` -- Ollama signing key attached to all requests

## Attacker Control

The LLM controls the `url` parameter of web_fetch calls. After initial approval:
1. `web_fetch("http://169.254.169.254/latest/meta-data/")` -- AWS metadata
2. `web_fetch("http://169.254.169.254/computeMetadata/v1/")` -- GCP metadata
3. `web_fetch("file:///etc/passwd")` -- local file read (if server proxies file:// scheme)
4. `web_fetch("http://internal-service:8080/admin")` -- internal service access

## Trust Boundary Crossed

User approval boundary. The user approved web_fetch for a specific URL. The approval system extends this to all URLs, crossing the scope the user intended.

## Impact

- **SSRF**: Access to cloud metadata endpoints, internal services, localhost services
- **Credential exposure**: Ollama signing key (`~/.ollama/id_ed25519`) attached to all requests via Authorization header
- **Information disclosure**: Read arbitrary web content or potentially local files

## Evidence

1. `approval.go:477`: `a.allowlist[toolName] = true` -- no argument stored
2. `approval.go:417-419`: `if toolName != "bash" && a.allowlist[toolName]` -- returns true regardless of args
3. `webfetch.go:85`: `url.Parse(urlStr)` -- accepts any URL, no scheme/host validation
4. `webfetch.go:109-115`: Request signed with Ollama key and sent to `ollama.com/api/web_fetch`

## Reproduction Steps

1. Start agent session; LLM calls `web_fetch("https://docs.example.com/api")`
2. User approves with "Allow for this session" -- stores `a.allowlist["web_fetch"] = true`
3. LLM calls `web_fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/")`
4. `IsAllowed`: `a.allowlist["web_fetch"]` = true, returns true immediately
5. No approval prompt shown; request sent to ollama.com proxy with Ollama credentials
6. If ollama.com proxies the request, cloud metadata is returned to the LLM
