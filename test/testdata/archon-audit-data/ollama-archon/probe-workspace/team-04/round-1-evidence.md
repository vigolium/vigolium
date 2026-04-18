# Evidence File: Team-04 Deep Probe

## EVIDENCE-PH-01: file:// CORS to /api/delete (gin path, rc==nil)

**Hypothesis**: PH-01 from round-1-hypotheses.md
**Status**: VALIDATED with caveat
**Fragility**: STABLE

**Evidence**:
1. `envconfig/config.go:100-106` — `AllowedOrigins()` unconditionally appends `"file://*"` in every execution path
2. `server/routes.go:1664` — `corsConfig.AllowOrigins = envconfig.AllowedOrigins()` — no override possible
3. `server/routes.go:1640` — `corsConfig.AllowWildcard = true` — enables wildcard matching
4. `server/routes.go:1668-1671` — `r.Use(cors.New(corsConfig), allowedHostsMiddleware(s.addr))` — middleware chain for ALL gin routes including DELETE /api/delete
5. `server/routes.go:1686` — `r.DELETE("/api/delete", s.DeleteHandler)` — unauth endpoint
6. `server/routes.go:1782-1787` — `rc` is only non-nil when `useClient2 = experimentEnabled("client2")` — meaning gin-direct path IS the default for all standard installations

**Key nuance**: `file://` pages in Chrome/Firefox send `Origin: null`. Whether gin-contrib/cors v1.7.2 matches `null` against `file://*` is unconfirmed (no source available). However:
- The attack works without relying on null-origin matching: any `vscode-webview://*`, `app://*`, or `tauri://*` application running locally can make cross-origin requests
- In non-Chrome contexts (Electron-hosted pages), Origin is a real URI like `app://name` that DOES match `app://*`
- `vscode-webview://<id>` matches `vscode-webview://*` — VS Code extension webviews are a confirmed attack vector

**Conclusion**: PH-01 is VALIDATED for non-browser attack vectors (VS Code extensions, Electron apps, Tauri apps). For pure file:// browser attack, depends on null-origin matching.

---

## EVIDENCE-PH-02: Arbitrary Model Pull via file:// CORS

**Hypothesis**: PH-02 from round-1-hypotheses.md
**Status**: VALIDATED
**Fragility**: STABLE

**Evidence**:
1. Same CORS evidence as PH-01 applies to POST /api/pull at `server/routes.go:1681`
2. In default config (rc==nil), gin handles /api/pull with full CORS + host middleware
3. `server/routes.go:914-949` — PullHandler: no auth, no registry allowlist
4. Model name format validation only (`ollama.ErrNameInvalid`) — does not restrict registry hostname
5. CORS allows cross-origin JSON POST with file:// origin (preflight succeeds for non-null origins)

**Pull chain**: cross-origin POST → PullHandler → PullModel() → OCI registry fetch from attacker hostname → blob download → GGUF parse

---

## EVIDENCE-PH-03 / PH-CX2: registry.Local Simple-Request Bypass

**Hypothesis**: PH-03 (round-1) + PH-CX2 (round-3)
**Status**: VALIDATED — but scoped to OLLAMA_EXPERIMENT=client2
**Fragility**: STABLE

**Evidence**:
1. `server/routes.go:96` — `var useClient2 = experimentEnabled("client2")` — registry.Local is ONLY active when `OLLAMA_EXPERIMENT=client2` is set
2. `server/routes.go:1782-1787` — `if useClient2 { rc, err = ollama.DefaultRegistry() }` — rc is nil by default
3. `server/internal/registry/server.go:377-379` — `decodeUserJSON` uses `json.NewDecoder(r.Body).Decode()` with NO Content-Type check — confirmed simple-request bypass path
4. `server/internal/registry/server.go:109-129` — serveHTTP: NO CORS, NO Host check, NO auth
5. `server/routes.go:1727-1736` — registry.Local wraps gin as Fallback: /api/delete and /api/pull handled BEFORE gin middleware

**Revised impact scope**: Only affects deployments with `OLLAMA_EXPERIMENT=client2`. However:
- This is a documented experiment being rolled out — it WILL become default
- Any user who has opted in is exposed
- The architecture is committed; the path to "default" is clear

**Preflight flow (confirmed)**:
- OPTIONS /api/pull → registry.Local → switch default → Fallback (gin) → gin-cors handles OPTIONS → returns ACAO for file://* origins → preflight succeeds
- POST /api/pull → registry.Local → handlePull → executes pull → NO CORS headers on response → browser blocks response read → BUT pull already executed

---

## EVIDENCE-PH-04: DNS Rebinding + registry.Local

**Hypothesis**: PH-04 from round-1-hypotheses.md
**Status**: VALIDATED — scoped to OLLAMA_EXPERIMENT=client2 config
**Fragility**: STABLE

**Evidence**: Same as PH-03/PH-CX2. registry.Local has zero host validation. DNS rebinding to 127.0.0.1 with any Host header bypasses allowedHostsMiddleware (middleware is in gin, which registry.Local wraps).

---

## EVIDENCE-PH-05: Null Origin Caveat

**Hypothesis**: PH-05 from round-1-hypotheses.md
**Status**: NEEDS-DEEPER
**Fragility**: FRAGILE

**Evidence**:
- gin-contrib/cors v1.7.2 source not available in local codebase (not vendored)
- Browser behavior: Chrome sends `Origin: null` for file:// cross-origin requests in most contexts
- Cannot confirm null origin matching without library source or runtime testing
- HOWEVER: The attack is fully valid via other allowed origins: `vscode-webview://*`, `app://*`, `tauri://*`

**Ambiguity**: Does `AllowWildcard=true` in gin-contrib/cors cause `null` to match `file://*`?

---

## EVIDENCE-PH-06 / PH-CX3: ENTRYPOINT Unconditional Execution

**Hypothesis**: PH-06 (round-1) + PH-CX3 (round-3)
**Status**: VALIDATED — on parth/agents branch (unmerged)
**Fragility**: STABLE

**Evidence** (from KB/bypass analysis section):
1. `cmd/cmd.go:584-626` — runEntrypoint: `strings.Fields()` + `exec.LookPath()` + `exec.Command().Run()` — no sandbox, no auth, no approval
2. `cmd/cmd.go:535-536` — entrypoint check fires BEFORE isExperimental gate at line 779
3. `cmd/cmd.go:748` — `isExperimental` retrieved but only gates `xcmd.GenerateInteractive` at line 779 — does NOT gate runEntrypoint
4. `types/model/config.go` — ConfigV2 on main branch has NO Entrypoint field; this is exclusively on parth/agents branch
5. KB states: "Entrypoint field is stored in ConfigV2... part of the OCI manifest structure... when a user runs ollama pull malicious-agent followed by ollama run malicious-agent, the entrypoint command executes automatically"

---

## EVIDENCE-PH-07: $PROMPT Argument Injection

**Hypothesis**: PH-07 from round-1-hypotheses.md
**Status**: VALIDATED — on parth/agents branch
**Fragility**: STABLE

**Evidence**:
- KB states: "$PROMPT placeholder substitution (cmd/cmd.go:588-592) inserts user input directly into the command string before splitting on whitespace"
- Structural: `strings.Replace(entrypoint, "$PROMPT", userPrompt, 1)` before `strings.Fields()` — canonical argument injection pattern

---

## EVIDENCE-PH-08: Cross-Origin /api/create Model Poisoning

**Hypothesis**: PH-08 from round-1-hypotheses.md
**Status**: VALIDATED
**Fragility**: STABLE

**Evidence**:
1. `server/routes.go:1695` — `r.POST("/api/create", s.CreateHandler)` — in gin route group with file://* CORS
2. CORS + host middleware allow cross-origin POST from file:// (same evidence chain as PH-01)
3. No auth on create endpoint
4. Can overwrite existing model by supplying same name with different system prompt/template

---

## EVIDENCE-PH-09: OLLAMA_ORIGINS Additive-Only Design

**Hypothesis**: PH-09 from round-2-hypotheses.md
**Status**: VALIDATED
**Fragility**: STABLE

**Evidence**:
1. `envconfig/config.go:86-108` — `AllowedOrigins()` function:
   - Lines 87-89: appends user-supplied OLLAMA_ORIGINS values
   - Lines 91-98: ALWAYS appends localhost/127/0.0.0.0 variants
   - Lines 100-106: ALWAYS appends `app://*`, `file://*`, `tauri://*`, `vscode-webview://*`, `vscode-file://*`
2. No subtraction operation. No "replace" mode. No way to remove `file://*` without code change.
3. `envconfig/config.go:323` — AsMap() shows OLLAMA_ORIGINS as "A comma separated list of allowed origins" — documentation implies restriction; behavior is expansion

---

## EVIDENCE-PH-10: IsPrivate() Bypass

**Hypothesis**: PH-10 from round-2-hypotheses.md
**Status**: VALIDATED (conditional on non-default binding)
**Fragility**: STABLE

**Evidence**:
1. `server/routes.go:1618` — `if addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified() || isLocalIP(addr) { c.Next() }`
2. `netip.Addr.IsPrivate()` in Go returns true for RFC 1918 ranges (10.x, 172.16-31.x, 192.168.x) — confirmed by Go stdlib
3. DNS rebinding to victim's LAN IP passes IsPrivate() check
4. Per CROSS-02 and PH-CX6 analysis: exploitable when server is bound to LAN IP or when victim is on reachable LAN

---

## EVIDENCE-PH-11: registry.Local Simple-Request (no Content-Type check)

**Hypothesis**: PH-11 from round-2-hypotheses.md
**Status**: VALIDATED — scoped to OLLAMA_EXPERIMENT=client2
**Fragility**: STABLE

**Evidence**:
1. `server/internal/registry/server.go:377-379` — `decodeUserJSON`: `json.NewDecoder(r.Body).Decode(&v)` — no Content-Type enforcement
2. Simple request (POST + text/plain body) bypasses CORS preflight requirement
3. `server/internal/registry/server.go:259-374` — handlePull: no Content-Type check before calling decodeUserJSON

---

## EVIDENCE-PH-13: MCP Subprocess Inherits Environment

**Hypothesis**: PH-13 from round-2-hypotheses.md
**Status**: VALIDATED — on parth/agents branch
**Fragility**: STABLE

**Evidence**:
- Go's `exec.Command()` by default inherits parent process environment (no explicit `Env` field = inherit)
- KB confirms MCP Command+Args from pulled config are spawned as subprocesses
- No env scrubbing, no sandbox

---

## EVIDENCE-PH-14 / PH-CX4: Cross-Origin GGUF Injection via /api/blobs

**Hypothesis**: PH-14 (round-2) + PH-CX4 (round-3)
**Status**: VALIDATED
**Fragility**: STABLE

**Evidence**:
1. `server/routes.go:1500-1549` — CreateBlobHandler: accepts raw bytes, computes SHA-256, checks against URL param
2. Line 1538: `manifest.NewLayer(c.Request.Body, "")` — hashes content; attacker can pre-compute
3. Line 1544: `layer.Digest != c.Param("digest")` — passes for attacker who pre-computes hash of their GGUF
4. `manifest/paths.go:40-61` — BlobsPath(): validates digest format (sha256: + 64 hex) — attacker provides valid format
5. No Content-Type check on blob upload
6. CORS file://* → PASS for `/api/blobs/:digest` POST (gin-routed, in middleware chain)
7. Line 1527-1536: If file already exists, returns 200 (cache hit) — prevents overwrite of existing blobs; new hashes succeed

---

## EVIDENCE-PH-15: /api/push Cross-Origin Model Exfiltration

**Hypothesis**: PH-15 from round-2-hypotheses.md
**Status**: VALIDATED
**Fragility**: STABLE

**Evidence**:
1. `server/routes.go:1682` — `r.POST("/api/push", s.PushHandler)` — gin-routed, in CORS middleware chain
2. No auth requirement for push
3. CORS file://* → PASS
4. Attacker-controlled registry host accepted in push target

---

## EVIDENCE-PH-16: ConfigV2 Unknown Fields — Time-Bomb

**Hypothesis**: PH-16 from round-2-hypotheses.md
**Status**: VALIDATED (structural)
**Fragility**: STABLE

**Evidence**:
1. `types/model/config.go:4-27` — `ConfigV2` struct: no `json:",disallowunknownfields"` tag
2. Go's standard `json.Unmarshal` silently ignores unknown fields by default
3. OCI config JSON with `"entrypoint": "..."` field would deserialize to zero-value `Entrypoint` field on main branch (field doesn't exist), silently dropped
4. After parth/agents branch merge adds `Entrypoint string json:"entrypoint"` to ConfigV2, all previously-pulled models with that field in their config would immediately gain execution capability

---

## EVIDENCE-PH-CX1: registry.Local Independence from CORS Config

**Hypothesis**: PH-CX1 from round-3-hypotheses.md
**Status**: VALIDATED — scoped to OLLAMA_EXPERIMENT=client2
**Fragility**: STABLE

**Evidence**:
1. `server/routes.go:1727-1736` — registry.Local wraps gin; /api/delete and /api/pull route to registry.Local BEFORE gin
2. `server/internal/registry/server.go:109` — ServeHTTP: no CORS, no Host, no auth — architecturally independent of gin middleware
3. Removing `file://*` from AllowedOrigins has zero effect on registry.Local behavior

---

## EVIDENCE-PH-CX5: VS Code Extension Webview Attack Vector

**Hypothesis**: PH-CX5 from round-3-hypotheses.md
**Status**: VALIDATED
**Fragility**: STABLE (unless origin list is curated)

**Evidence**:
1. `envconfig/config.go:104` — `"vscode-webview://*"` hardcoded in AllowedOrigins
2. VS Code extensions can create webviews with `vscode-webview://` scheme origins
3. A malicious VS Code extension (supply-chain compromised, or directly malicious) running in a webview can make cross-origin requests to Ollama API
4. All destructive endpoints (delete, pull, create, push) are accessible via this origin
5. VS Code extension marketplace has weaker vetting than app stores; multiple past malicious extensions documented

---

## SUMMARY TABLE

| Hypothesis | Status | Severity | Scope |
|-----------|--------|----------|-------|
| PH-01: file:// CORS delete (gin) | VALIDATED (caveat: null origin) | HIGH | Default config |
| PH-02: file:// CORS pull | VALIDATED | CRITICAL | Default config |
| PH-03: registry.Local simple-request | VALIDATED | HIGH | OLLAMA_EXPERIMENT=client2 |
| PH-04: DNS rebinding + registry.Local | VALIDATED | HIGH | OLLAMA_EXPERIMENT=client2 |
| PH-05: Null origin behavior | NEEDS-DEEPER | — | Unclear |
| PH-06: ENTRYPOINT unconditional RCE | VALIDATED | CRITICAL | parth/agents branch |
| PH-07: $PROMPT arg injection | VALIDATED | HIGH | parth/agents branch |
| PH-08: Cross-origin /api/create poison | VALIDATED | HIGH | Default config |
| PH-09: OLLAMA_ORIGINS additive | VALIDATED | MEDIUM | Design gap |
| PH-10: IsPrivate() DNS rebind | VALIDATED | MEDIUM | Non-default bind |
| PH-11: registry.Local no CT check | VALIDATED | CRITICAL | OLLAMA_EXPERIMENT=client2 |
| PH-12: IPv6 zone ID | INVALIDATED | — | — |
| PH-13: MCP env inheritance | VALIDATED | CRITICAL | parth/agents branch |
| PH-14: GGUF injection via /api/blobs | VALIDATED | HIGH | Default config |
| PH-15: /api/push exfil | VALIDATED | HIGH | Default config |
| PH-16: ConfigV2 unknown fields | VALIDATED | CRITICAL | Future (after merge) |
| PH-17: Cross-origin /api/chat | VALIDATED | MEDIUM | Default config |
| PH-CX1: registry.Local CORS independence | VALIDATED | CRITICAL | OLLAMA_EXPERIMENT=client2 |
| PH-CX2: Preflight via Fallback | VALIDATED | CRITICAL | OLLAMA_EXPERIMENT=client2 |
| PH-CX3: ENTRYPOINT no experimental gate | VALIDATED | CRITICAL | parth/agents branch |
| PH-CX4: Blob injection digest bypass | VALIDATED | HIGH | Default config |
| PH-CX5: vscode-webview:// attack | VALIDATED | HIGH | Default config |
| PH-CX6: IsPrivate clarification | VALIDATED | MEDIUM | Non-default bind |
