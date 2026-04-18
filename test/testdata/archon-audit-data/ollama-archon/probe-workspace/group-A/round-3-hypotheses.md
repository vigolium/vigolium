# Round 3 Hypotheses — Causal Verifier

Reasoning model: Counterfactual / Causal Intervention (what intervention would prevent/confirm each finding; test whether protection assumption holds)

## PH-15: Causal verification of PH-01 — confirm no validation exists between manifest.Layer.Digest and digestToPath

**Intervention test**: If `manifest.BlobsPath(layer.Digest)` were called in `pullWithTransfer` before populating `transfer.Blob.Digest`, would the path traversal be blocked?

**Trace**:
1. `PullModel` at `server/images.go:633-638`:
   ```go
   if hasTensorLayers(layers) {
       if err := pullWithTransfer(ctx, n, layers, manifestData, regOpts, fn); err != nil {
   ```
   `layers` is `[]manifest.Layer` directly from `pullModelManifest` response.

2. `pullWithTransfer` at `images.go:722-727`:
   ```go
   blobs := make([]transfer.Blob, len(layers))
   for i, layer := range layers {
       blobs[i] = transfer.Blob{
           Digest: layer.Digest,   // ← direct copy, no BlobsPath call
           Size:   layer.Size,
       }
   }
   ```
   CONFIRMED: No `manifest.BlobsPath` call. The `BlobsPath` function would have matched `^sha256[:-][0-9a-fA-F]{64}$` and rejected `"sha256:../../../etc/cron.d/evil"`.

3. `transfer.Download` → `downloader.download` → `downloader.downloadOnce` → `downloader.save`:
   ```go
   dest := filepath.Join(d.destDir, digestToPath(blob.Digest))
   ```
   With `blob.Digest = "sha256:../../../etc/cron.d/evil"`:
   - `digestToPath("sha256:../../../etc/cron.d/evil")` → `"sha256-../../../etc/cron.d/evil"` (since `digest[6] == ':'`)
   - `filepath.Join("/home/user/.ollama/models/blobs", "sha256-../../../etc/cron.d/evil")` → `/etc/cron.d/evil`

4. For `blob.Size = 100_000_000` (>= 64MB): `os.Create(dest + ".tmp")` → file created at `/etc/cron.d/evil.tmp`. Hash mismatch (since hash of downloaded bytes != `blob.Digest`). `os.Remove(tmp)` is skipped (size >= resumeThreshold). Partial file at `/etc/cron.d/evil.tmp` persists with up to 100MB of attacker-supplied bytes.

**Counterfactual**: If `digestToPath` called `regexp.MatchString("^sha256[:-][0-9a-fA-F]{64}$", digest)` and returned an error on mismatch, the `downloadOnce` function would abort before any file system operation. This is the fix path.

**Causal verdict**: CONFIRMED. The absence of validation at the `pullWithTransfer` → `transfer.Blob` boundary is the single causal condition. The protection at `manifest.BlobsPath` exists but is not on this code path.

**Severity**: CRITICAL — arbitrary file write (partial content) as ollama service user on any manifest with a tensor layer.

---

## PH-16: Causal verification of CROSS-01 — confirm pull-then-push exfiltration chain

**Intervention test**: Does `pushWithTransfer` read blob file contents using the unvalidated digest-to-path conversion?

**Trace**:
1. `pushWithTransfer` at `images.go:797-803`:
   ```go
   blobs := make([]transfer.Blob, len(layers))
   for i, layer := range layers {
       blobs[i] = transfer.Blob{
           Digest: layer.Digest,  // ← direct copy
           Size:   layer.Size,
           From:   layer.From,
       }
   }
   ```
   `srcDir, err := manifest.BlobsPath("")` — gets the blobs directory.

2. `transfer.Upload` → `uploader.uploadOnce` → `os.Open(filepath.Join(u.srcDir, digestToPath(blob.Digest)))` at `upload.go:181`.

3. `digestToPath("sha256:../../../etc/shadow")` → `"sha256-../../../etc/shadow"`.
   `filepath.Join("/home/user/.ollama/models/blobs", "sha256-../../../etc/shadow")` → `/etc/shadow`.

4. `os.Open("/etc/shadow")` — if process has read permissions (e.g., running as root or shadow group), the contents are read and uploaded to the attacker's registry.

**Precondition**: The manifest passed to `pushWithTransfer` contains a layer with traversal digest. This manifest must be in `$OLLAMA_MODELS/manifests/`. This manifest can be planted by:
- PH-01 path traversal write → write a crafted manifest file to `$OLLAMA_MODELS/manifests/<host>/<ns>/<model>/<tag>`
- OR: the malicious registry returns a manifest that gets written by `pullWithTransfer` at `images.go:787-792`

5. Looking at the manifest write in `pullWithTransfer` at lines `776-792`: the manifest is `manifestData` — the raw bytes from `pullModelManifest`. The manifest contains `layer.Digest = "sha256:../../../etc/shadow"`. This manifest IS written to disk at `$OLLAMA_MODELS/manifests/<model>`.

6. On subsequent `POST /api/push {"name":"<same model>"}`, `PushModel` → `pushWithTransfer` reads back the manifest from disk, extracts `layer.Digest = "sha256:../../../etc/shadow"`, passes to upload, reads `/etc/shadow`.

**Causal verdict**: CONFIRMED with conditions. The chain requires: (1) ollama user has read access to the target file, (2) manifest written from pull persists on disk. The manifest written in step 5 above IS the malicious manifest — it contains the traversal digest as-written by the attacker. On subsequent push, this manifest drives a file-read at the traversal path.

**Severity**: HIGH — arbitrary file read + exfiltration to attacker registry, chained from pull.

---

## PH-17: Causal verification of PH-03 SSRF — confirm isValidPart permits IP addresses including link-local

**Trace**:
1. `parseNormalizePullModelRef` at `routes.go:931` → `model_resolver.go:57` → `model.ParseName(normalizedName)` → `isValidPart(kindHost, host)`.
2. `isValidPart(kindHost, "169.254.169.254")`: characters are alphanumerics and `.`; `.` is allowed for `kindHost` (the check `if kind == kindNamespace { return false }` means `.` is forbidden only for namespace, NOT for host). Length check: max host length is not visible in the excerpt — need to verify.
3. `n.BaseURL()` at `types/model/name.go:317` returns `&url.URL{Scheme: n.ProtocolScheme, Host: n.Host}`. For `n.Host = "169.254.169.254"`, this produces `https://169.254.169.254`.
4. With `Insecure: true` in the request, `makeRequest` at `images.go:952` sets scheme to `http`: `requestURL.Scheme = "http"`.
5. `http.DefaultClient` (used by `makeRequest` through `c.Do`) connects to `http://169.254.169.254:80/v2/...`. On AWS EC2, this reaches IMDS at port 80. The response body is reflected in the error message at `images.go:622`.

**Counterfactual**: If `PullModel` checked the resolved IP against RFC5735 special-use ranges (loopback, link-local, private) before issuing the HTTP request, the SSRF would be blocked. No such check exists.

**Causal verdict**: CONFIRMED. `isValidPart` permits `.` in host names, allowing IP addresses. The `Insecure: true` parameter enables HTTP. Combined: full SSRF to link-local endpoints.

**Severity**: HIGH — SSRF to IMDS/169.254.169.254 in cloud environments; also reaches any RFC1918 internal endpoint.

---

## PH-18: Causal verification of PH-04 + PH-14 — confirm sequential double io.ReadAll without size cap

**Trace**:
1. `PullHandler` at `routes.go:914` → `PullModel` at `images.go:595`.
2. `pullModelManifest(ctx, n, regOpts)` at `images.go:621` → `makeRequestWithRetry` → on 401:
   - `getAuthorizationToken(ctx, challenge, requestURL.Host)` at `images.go:907`
   - Inside `getAuthorizationToken` at `auth.go:75`: `makeRequest(ctx, http.MethodGet, redirectURL, headers, nil, ...)` → `c.Do(req)`
   - `body, err := io.ReadAll(response.Body)` at `auth.go:81` — **no LimitReader**
3. If auth succeeds, loop continues: `makeRequest` again for the manifest.
4. `pullModelManifest` returns, line 864: `data, err := io.ReadAll(resp.Body)` — **no LimitReader**.

**Causal condition**: Two independent `io.ReadAll` calls, either of which can OOM the server. The auth token call happens on 401 from the registry — the attacker's registry returns 401 with a huge token endpoint response. The manifest call happens if auth succeeds — the registry returns 200 with a huge body.

**Counterfactual**: `io.LimitReader(response.Body, 10<<20)` (10MB limit) at both call sites would prevent OOM.

**Causal verdict**: CONFIRMED. Both `auth.go:81` and `images.go:864` lack `io.LimitReader`.

**Severity**: HIGH — one pull request can OOM the server via either the auth or manifest response. Reachable from DNS rebind (localhost access).

---

## PH-19: Causal verification of PH-09 (realm HTTP downgrade) — confirm auth token sent over HTTP when realm is same-host but HTTP scheme

**Trace**:
1. Registry returns `WWW-Authenticate: Bearer realm="http://registry.ollama.ai/token",service="registry",scope="..."`.
2. `parseRegistryChallenge` at `images.go:1018` extracts `Realm = "http://registry.ollama.ai/token"`.
3. `getAuthorizationToken(ctx, challenge, "registry.ollama.ai")` at `auth.go:53`:
   - `redirectURL.Host = "registry.ollama.ai"` — matches `originalHost`
   - Realm host check PASSES (host matches)
   - `makeRequest(ctx, http.MethodGet, redirectURL, headers, nil, ...)` — `redirectURL.Scheme = "http"`
   - At `images.go:952`: `if requestURL.Scheme != "http" && regOpts != nil && regOpts.Insecure { ... }` — the scheme IS already "http" so no override needed; `regOpts` here is `&registryOptions{}` (empty, `Insecure=false`)
   - The `makeRequest` function does NOT reject HTTP schemes when the caller passed an empty `regOpts`
   - The ed25519-signed `Authorization` header is sent over HTTP to `http://registry.ollama.ai/token`

**Counterfactual**: If `getAuthorizationToken` checked `redirectURL.Scheme == "https"` before making the request, the HTTP downgrade would be rejected.

**Causal verdict**: CONFIRMED. `getAuthorizationToken` at `auth.go:53-100` checks `redirectURL.Host == originalHost` but does NOT check `redirectURL.Scheme`. A malicious registry that controls DNS for its own hostname can serve a 301 redirect to `http://` or directly return `WWW-Authenticate` with an HTTP realm URL.

**Severity**: HIGH — ed25519-signed auth token sent over plaintext HTTP; MITM on the network path reads the signed token and can replay it.

---

## PH-20: Causal verification of size-only cache-hit bypass — confirm no hash in either fast or legacy path

**Intervention test**: If a file exists at the expected blob path with the correct SIZE but wrong CONTENT, does either code path re-hash it?

**Fast path** (`transfer/download.go:56-68`):
```go
if fi, _ := os.Stat(filepath.Join(opts.DestDir, digestToPath(b.Digest))); fi != nil && fi.Size() == b.Size {
    // skip download
    continue
}
```
No hash. CONFIRMED.

**Legacy path** (`server/download.go:478-491`):
```go
fi, err := os.Stat(fp)
switch {
case errors.Is(err, os.ErrNotExist):
case err != nil:
    return false, err
default:
    // report progress and return cacheHit=true
    return true, nil
}
```
No hash. CONFIRMED.

**Downstream**: `PullModel` at `images.go:641-653`:
```go
cacheHit, err := downloadBlob(...)
skipVerify[layer.Digest] = cacheHit
```
When `cacheHit=true`, the subsequent `verifyBlob` loop at lines `656-673` skips verification via `skipVerify[layer.Digest]`. So even on the legacy path with `verifyBlob` active, a cache hit bypasses re-verification.

**Counterfactual**: If `downloadBlob` computed sha256 of the existing file and compared to `opts.digest` before returning `cacheHit=true`, the bypass would be closed.

**Causal verdict**: CONFIRMED on both paths. The size-only check and the `skipVerify` map both contribute to the bypass.

**Severity**: HIGH — model substitution possible for any co-tenant or prior attacker who can write a correctly-sized file to the blob store.
