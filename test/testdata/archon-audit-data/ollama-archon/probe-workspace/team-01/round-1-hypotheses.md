# Round 1 Hypotheses: Backward Reasoner (Pre-Mortem / Abductive)

Reasoning approach: Start from known-bad outcomes (RCE, model deletion, DoS, data exfil), then reason backward to find the code path that enables each outcome.

---

## PH-01: DNS Rebinding Reaches /api/pull via registry.Local, Triggering Attacker Model Pull

**Reasoning model**: Pre-Mortem
**Outcome assumed**: Attacker pulls a model onto victim's machine without victim consent, via DNS rebinding attack
**Backward path**:
- Outcome requires: `/api/pull` handling attacker-chosen model name with no auth/host check
- Working backward: `registry.Local.handlePull` calls `s.Client.Pull(r.Context(), p.model())` with no Host check
- Working backward: `registry.Local.serveHTTP` intercepts path `/api/pull` BEFORE gin middleware fires
- Working backward: attacker controls DNS to rebind victim's hostname to attacker IP; victim's browser sends request to `http://victim-hostname:11434/api/pull`
- Working backward: `allowedHostsMiddleware` is never called for this path

**Target**: `server/internal/registry/server.go:118-121` — `serveHTTP` switch case
**Attack input**: DNS-rebinding HTTP request with `Host: victim-hostname`, body `{"model":"attacker.com/malicious:latest"}`
**Code path**: DNS rebind → `registry.Local.ServeHTTP:108` → `serveHTTP:113` → case `/api/pull`:121 → `handlePull:259` → `s.Client.Pull` [no Host validation]
**Sanitizers on path**: None. `allowedHostsMiddleware` never called. `handlePull` only checks `r.Method == "POST"`.
**Security consequence**: Attacker-controlled model is downloaded onto victim machine; if ENTRYPOINT present (parth/agents branch), RCE follows. Even without, malicious GGUF can be loaded leading to parser exploitation.
**Severity estimate**: HIGH
**Status**: VALIDATED — code confirms bypass path is real on main branch

---

## PH-02: file:// Origin Reaches /api/delete via CORS + gin Route (No registry.Local Bypass Needed)

**Reasoning model**: Pre-Mortem
**Outcome assumed**: Victim opens malicious HTML file; JavaScript deletes all local models
**Backward path**:
- Outcome requires: DELETE `/api/delete` to succeed with no auth
- Working backward: CORS check passes because `file://*` is in `AllowedOrigins()`
- Working backward: Host check passes because request goes to `localhost:11434` (loopback)
- Working backward: `DeleteHandler` has no auth check
- Working backward: Also, `registry.Local.handleDelete` intercepts `/api/delete` before gin — but both paths lead to deletion

**Target**: `envconfig/config.go:99` — `AllowedOrigins` hardcodes `file://*`
**Attack input**: Malicious HTML `<script>fetch('http://localhost:11434/api/delete',{method:'DELETE',body:JSON.stringify({model:'llama3'})})</script>`
**Code path**: Browser fetch → CORS preflight passes (file:// origin) → Host check passes (localhost) → gin DeleteHandler OR registry.Local.handleDelete → model deleted
**Sanitizers on path**: CORS (passes), allowedHostsMiddleware (passes for loopback). No auth.
**Security consequence**: All local models deleted; model data loss; combined with PH-01 (pull arbitrary replacement model), leads to supply chain poisoning
**Severity estimate**: HIGH
**Status**: VALIDATED — AllowedOrigins confirmed at config.go:99, no auth on any handler

---

## PH-03: GGUF Unbounded String Allocation DoS via /api/create Blob Upload

**Reasoning model**: Abductive
**Hypothesis**: A crafted GGUF with a string KV value claiming length 2^63-1 causes OOM process termination
**Backward path**:
- Outcome: `ollama serve` process runs out of memory and terminates (DoS)
- Working backward: `readGGUFString` at line 361 does `make([]byte, length)` with no upper bound
- Working backward: `length` is `int(llm.ByteOrder.Uint64(buf))` — directly from 8 bytes in the file
- Working backward: attacker uploads crafted GGUF via `POST /api/blobs/:digest`, then calls `POST /api/create`

**Target**: `fs/ggml/gguf.go:359-361` — `readGGUFString`
**Attack input**: GGUF file with valid magic/version, numKV=1, key="x", type=ggufTypeString(8), string_length=0x7FFFFFFFFFFFFFFF (9223372036854775807)
**Code path**: `POST /api/blobs/:digest` → blob stored → `POST /api/create` → model creation triggers GGUF parse → `gguf.Decode` → `readGGUFString` → `make([]byte, 9223372036854775807)` → OOM → panic/crash
**Sanitizers on path**: `manifest.BlobsPath` validates digest format only (not blob content). No GGUF content validation at upload time.
**Security consequence**: `ollama serve` process crash; DoS; all ongoing inference sessions terminated
**Severity estimate**: HIGH
**Status**: VALIDATED — `readGGUFString:361` confirmed to have no bound check before `make`

---

## PH-04: GGUF ggufPadding Divide-by-Zero via general.alignment=0

**Reasoning model**: Abductive
**Hypothesis**: A GGUF with KV key `general.alignment` set to 0 causes a Go runtime panic (divide-by-zero)
**Backward path**:
- Outcome: ollama process panics/crashes
- Working backward: `ggufPadding(offset, int64(alignment))` at line 245 → `(align - offset%align) % align` → if align=0, this is `offset % 0` → Go runtime panic: integer divide by zero
- Working backward: `alignment := llm.kv.Uint("general.alignment", 32)` — default is 32, but if KV contains key `general.alignment` with value 0, that overrides the default
- Working backward: KV values are set in the loop at lines 143-191; any uint value can be stored

**Target**: `fs/ggml/gguf.go:238-245` — alignment read from KV then passed to `ggufPadding`
**Attack input**: GGUF file with `general.alignment` KV key set to uint32/uint64 value 0
**Code path**: GGUF parse → `gguf.Decode` → line 238: `alignment = kv.Uint("general.alignment", 32)` returns 0 → line 245: `ggufPadding(offset, 0)` → `offset % 0` → panic
**Sanitizers on path**: None. KV value is used directly. The default of 32 is only used when key is absent, not when key is present with value 0.
**Security consequence**: `ollama serve` panic and crash; DoS
**Severity estimate**: HIGH
**Status**: VALIDATED — ggufPadding:688 `(align - offset%align) % align` with align=0 is a divide-by-zero; `kv.Uint` with default 32 only applies when key is missing

---

## PH-05: Blob Cache Poisoning via TOCTOU — Same-Size Malicious GGUF Bypasses Integrity Check

**Reasoning model**: Pre-Mortem
**Outcome assumed**: Malicious GGUF is loaded by ollama without integrity check
**Backward path**:
- Outcome: poisoned model loaded
- Working backward: `copyNamedFile` (cache.go:458) skips hash verification when `info.Size() == size` — size match is treated as cache hit
- Working backward: attacker replaces blob file with same-size malicious GGUF on local filesystem (blob dir is 0o777 in new cache)
- Working backward: next model pull/load calls cache check, gets size match, skips verification
- Working backward: blob directory `0o777` permissions (cache.go:85) allow any local user to write

**Target**: `server/internal/cache/blob/cache.go:458-465` — `copyNamedFile` size-match shortcut
**Attack input**: Attacker on same system writes crafted GGUF (same byte count as legitimate model blob) to the blob path
**Code path**: Attacker writes malicious blob → victim runs `ollama run model` → `downloadBlob` returns cacheHit=true (os.Stat succeeds) → `verifyBlob` skipped → malicious GGUF loaded by GGUF parser
**Sanitizers on path**: `manifest.BlobsPath` validates path format only. No content hash at load time.
**Security consequence**: Arbitrary GGUF injected into model pipeline; can trigger all 9 GGUF CVE classes; on shared systems enables privilege escalation via parser exploit
**Severity estimate**: HIGH (multi-user systems); MEDIUM (single-user)
**Status**: VALIDATED — both old (`download.go:491`) and new (`copyNamedFile:458`) cache paths confirmed to skip hash on existence/size match

---

## PH-06: SSRF via /api/pull with Internal URL as Model Name

**Reasoning model**: Abductive
**Hypothesis**: Model name resolving to an internal URL causes the ollama server to make an outbound HTTP request to an internal service
**Backward path**:
- Outcome: SSRF — ollama makes request to attacker-controlled or internal network target
- Working backward: `PullModel` calls `pullModelManifest` which calls `makeRequestWithRetry` with a URL derived from the model name
- Working backward: `n.BaseURL()` constructs the registry URL from the model name's host component
- Working backward: model name like `192.168.1.1:8080/model:tag` would target an internal IP

**Target**: `server/images.go:835-840` — `pullModelManifest` constructs URL from model name
**Attack input**: `POST /api/pull` body `{"model":"192.168.1.1:8080/internal-service/model:latest"}`
**Code path**: `PullHandler` → `PullModel` → `pullModelManifest` → `n.BaseURL().JoinPath("v2", ...)` → HTTP GET to `http://192.168.1.1:8080/v2/internal-service/model/manifests/latest`
**Sanitizers on path**: `parseNormalizePullModelRef` validates model name format but does NOT restrict to specific registries. The host component of the model name becomes the HTTP target directly.
**Security consequence**: SSRF to internal network services; potential data exfiltration via timing or response reflection; metadata service access (169.254.169.254)
**Severity estimate**: HIGH
**Status**: VALIDATED — model name host component used directly in outbound HTTP; no IP allowlist or SSRF protection

---

## PH-07: registry.Local.handlePull Lacks Model Name Normalization — Potential Injection via DeprecatedName Field

**Reasoning model**: Abductive
**Hypothesis**: The `DeprecatedName` field in registry.Local's `params` struct allows model name inputs that `PullHandler` would reject via `parseNormalizePullModelRef`, enabling bypass of name validation
**Backward path**:
- Outcome: registry.Local.handlePull processes a model name that PullHandler would reject
- Working backward: `params.model()` returns `cmp.Or(p.Model, p.DeprecatedName)` — uses DeprecatedName if Model is empty
- Working backward: `handlePull` calls `s.Client.Pull(r.Context(), p.model())` directly
- Working backward: `PullHandler` calls `parseNormalizePullModelRef` for validation — `handlePull` does not
- Hypothesis: crafted input with empty `model` field but populated `name` (DeprecatedName) field bypasses validation

**Target**: `server/internal/registry/server.go:259-278` — `handlePull` model name handling
**Attack input**: `POST /api/pull` body `{"name":"../../../etc/model:tag"}` (via registry.Local path)
**Code path**: registry.Local.serveHTTP → handlePull → `p.model()` returns "../../../etc/model:tag" → `s.Client.Pull` with unsanitized name
**Sanitizers on path**: Only `ollama.Registry.Pull` internals validate the name — unclear if equivalent to `parseNormalizePullModelRef`
**Security consequence**: Depends on `ollama.Registry.Pull` validation. If weaker, enables name confusion/injection attacks.
**Severity estimate**: MEDIUM (validation gap; impact depends on downstream handling)
**Status**: NEEDS-DEEPER — requires tracing `ollama.Registry.Pull` validation logic

---

## PH-08: OLLAMA_HOST=0.0.0.0 + file:// CORS Enables Full Unauthenticated Network API Access

**Reasoning model**: Pre-Mortem
**Outcome assumed**: Remote attacker accesses the full Ollama API from any network position
**Backward path**:
- Outcome: any network client can call all API endpoints
- Working backward: `allowedHostsMiddleware` returns `c.Next()` immediately when server addr is non-loopback (line 1607)
- Working backward: `OLLAMA_HOST=0.0.0.0` is common in Docker/remote deployments
- Working backward: CORS still applies for browser requests, but `0.0.0.0` with wildcard port is in default origins
- Working backward: non-browser direct HTTP clients bypass CORS entirely

**Target**: `server/routes.go:1607-1609` — non-loopback skip in `allowedHostsMiddleware`
**Attack input**: Direct HTTP request from attacker's machine to `http://victim-ip:11434/api/delete`
**Code path**: TCP connection → HTTP request → `registry.Local.ServeHTTP` (intercepts /api/delete before gin) → `handleDelete` → model deleted, OR gin router → `allowedHostsMiddleware` returns immediately (non-loopback) → handler → model deleted
**Sanitizers on path**: None when OLLAMA_HOST=0.0.0.0
**Security consequence**: Full unauthenticated API access from network; model deletion, arbitrary model pull, inference exfiltration
**Severity estimate**: CRITICAL (in Docker deployments)
**Status**: VALIDATED — code path confirmed; extremely common deployment pattern
