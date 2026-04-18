# Evidence File: Team-01 All Rounds

## Evidence for PH-01 (DNS Rebinding → registry.Local → /api/pull without Host check)
- `server/routes.go:1727-1736`: `if rc != nil` wraps gin router as `Fallback`; `registry.Local` is the returned root handler
- `server/internal/registry/server.go:116-128`: `serveHTTP` switch case `/api/pull` → `handlePull`, never calls `Fallback`
- `server/routes.go:1670-1671`: `r.Use(cors.New(corsConfig), allowedHostsMiddleware(s.addr))` applied to `r` (gin) — never reached for `/api/pull` when `rc != nil`
- **Fragility**: ROBUST — structural bypass, not configuration-dependent
- **Status**: VALIDATED

## Evidence for PH-02 (file:// CORS reaches /api/delete)
- `envconfig/config.go:99`: `"file://*"` appended unconditionally in `AllowedOrigins()`
- `server/routes.go:1664`: `corsConfig.AllowOrigins = envconfig.AllowedOrigins()` — no route group separation
- `server/routes.go:1686`: `r.DELETE("/api/delete", s.DeleteHandler)` — no auth middleware
- **Fragility**: ROBUST — hardcoded default, irremovable via config
- **Status**: VALIDATED

## Evidence for PH-03 (GGUF unbounded string allocation)
- `fs/ggml/gguf.go:359-361`: `length := int(llm.ByteOrder.Uint64(buf))` then `if length > len(llm.scratch) { buf = make([]byte, length) }` — no upper bound
- `fs/ggml/gguf.go:97`: `scratch [16 << 10]byte` — 16KB threshold, above which unbounded allocation occurs
- **Fragility**: ROBUST — arithmetic path always taken; no guard
- **Status**: VALIDATED

## Evidence for PH-04 (GGUF ggufPadding divide-by-zero)
- `fs/ggml/gguf.go:238`: `alignment := llm.kv.Uint("general.alignment", 32)` — default 32 only for missing key
- `fs/ggml/gguf.go:245`: `padding := ggufPadding(offset, int64(alignment))`
- `fs/ggml/gguf.go:687-688`: `func ggufPadding(offset, align int64) int64 { return (align - offset%align) % align }` — divide-by-zero if align=0
- Gin's recovery middleware at `gin.Default()` (routes.go:1666) catches the panic → 500 response, not process crash
- **Fragility**: ROBUST for DoS per-request; gin recovery prevents full process crash
- **Status**: VALIDATED (revised to per-request DoS)

## Evidence for PH-05 (Blob cache poisoning, same-size replacement)
- `server/download.go:478`: `os.Stat(fp)` — existence only, no hash
- `server/download.go:491`: `return true, nil` on `os.Stat` success — `cacheHit=true`
- `server/images.go:640`: `if skipVerify[layer.Digest] { continue }` — skips `verifyBlob`
- `server/internal/cache/blob/cache.go:79,85`: `os.MkdirAll(dir, 0o777)` — world-writable blob directory
- `server/internal/cache/blob/cache.go:457-464`: `copyNamedFile` size-match skip with comment `// TODO: Do the hash check`
- **Fragility**: ROBUST — two independent code paths (old + new) both skip hash on cache hit
- **Status**: VALIDATED

## Evidence for PH-06 (SSRF via pull URL)
- `server/images.go:835-836`: `requestURL := n.BaseURL().JoinPath("v2", n.DisplayNamespaceModel(), "manifests", n.Tag)` — model name host becomes HTTP target
- `server/routes.go:952-953`: `regOpts := &registryOptions{Insecure: req.Insecure}` — no allowlist on target host
- `server/images.go:597`: HTTP scheme check only when `!regOpts.Insecure` — HTTPS default, but HTTP allowed with flag
- **Fragility**: ROBUST — no SSRF protection, no IP allowlist
- **Status**: VALIDATED

## Evidence for PH-08 (OLLAMA_HOST=0.0.0.0 disables all host checks)
- `server/routes.go:1607-1609`: `if addr, err := netip.ParseAddrPort(addr.String()); err == nil && !addr.Addr().IsLoopback() { c.Next(); return }` — unconditional skip for non-loopback
- `envconfig/config.go:21-58`: `OLLAMA_HOST=0.0.0.0` produces non-loopback addr
- **Fragility**: ROBUST — by-design skip for non-loopback
- **Status**: VALIDATED

## Evidence for PH-09 (AllowedOrigins immutability)
- `envconfig/config.go:86-107`: `OLLAMA_ORIGINS` prepended, then dangerous defaults always appended — cannot override
- **Status**: VALIDATED

## Evidence for PH-10 (registry.Local split security model)
- `server/routes.go:1681,1686`: gin registers `/api/pull` and `/api/delete` — dead code when `rc != nil`
- `server/routes.go:1727-1736`: registry.Local is root handler, gin is Fallback only
- **Status**: VALIDATED

## Evidence for PH-11 (Symlink attack on blob cache)
- `server/download.go:478`: `os.Stat(fp)` — follows symlinks
- `server/internal/cache/blob/cache.go:259`: `DiskCache.Get` — `os.Stat(name)` follows symlinks
- No `os.Lstat` call anywhere in blob path (verified via grep)
- No `O_NOFOLLOW` on any blob file open
- **Fragility**: ROBUST — `os.Stat` is symlink-following by definition
- **Status**: VALIDATED

## Evidence for PH-12 (numKV/numTensor unbounded loop)
- `fs/ggml/gguf.go:143`: `for i := 0; uint64(i) < llm.numKV(); i++` — no max guard
- `fs/ggml/gguf.go:130-138`: `numKV()` returns raw uint64 from file header
- Bounded by EOF hits, not unbounded CPU — revised down from CRITICAL
- **Status**: VALIDATED (MEDIUM DoS)

## Evidence for PH-15 (HTTP pull without insecure flag via registry.Local)
- `server/internal/client/ollama/registry.go:1105-1108`: `supportedSchemes = ["http", "https", "https+insecure"]` — HTTP is valid
- `registry.go:1126`: `scheme = cmp.Or(scheme, "https")` — default is https, but explicit `http://` passes
- `server/images.go:597-599`: old path has `if n.ProtocolScheme == "http" && !regOpts.Insecure { return errInsecureProtocol }` — absent from new path
- **Status**: VALIDATED

## Evidence for PH-19 (Unconditional middleware bypass — causal confirmation)
- Full call chain traced: request → `registry.Local.ServeHTTP:108` → `serveHTTP:113` → switch `/api/pull` → `handlePull:259` → returns — gin middleware NEVER called
- Intervention test: `r.Use(newMiddleware)` — protection on `r` never applies to these paths
- **Status**: VALIDATED

## Evidence for PH-20 / PH-23 / PH-24 (Symlink extends to all pull paths)
- Old path: `download.go:478` `os.Stat` — no size check
- New path: `registry.go:515-518` `c.Get(l.Digest)` → `os.Stat` + size check — symlink with matching-size target bypasses
- x/transfer path: `transfer/download.go:57-58` `os.Stat` + size check — same pattern
- All three paths have `os.Stat` (symlink-following) as the cache-hit gate
- **Status**: VALIDATED

## Evidence for PH-21 (ggufPadding panic revised to per-request DoS)
- `fs/ggml/gguf.go:687-688`: divide-by-zero confirmed
- `server/routes.go:1666`: `gin.Default()` includes panic recovery middleware
- Per-request DoS confirmed; full process crash prevented by gin recovery
- **Status**: VALIDATED (MEDIUM-HIGH DoS)

## Evidence for PH-22 (Unbounded string allocation — OOM DoS)
- `fs/ggml/gguf.go:359-361`: no bound check before `make([]byte, length)`
- `length` is `int(llm.ByteOrder.Uint64(buf))` — attacker controls 8 bytes
- Gin recovery middleware catches OOM panic — per-request DoS, not process crash
- **Status**: VALIDATED (HIGH DoS)

## Evidence for PH-25 (HTTP pull without insecure flag)
- `registry.go:1105-1108`: scheme `"http"` in `supportedSchemes`
- `images.go:597`: TLS check only in old `PullModel` path
- `server/internal/registry/server.go:271`: `s.Client.Pull(r.Context(), p.model())` — no insecure check applied
- **Status**: VALIDATED (HTTP pull accepted without insecure flag via registry.Local)
