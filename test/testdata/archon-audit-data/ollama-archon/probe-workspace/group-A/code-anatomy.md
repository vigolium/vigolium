# Code Anatomy: Group A — Registry / Download / Blob Store

## File Inventory

| File | LOC | Primary Role |
|------|-----|-------------|
| `server/images.go` | 1048 | PullModel/PushModel orchestration, pullWithTransfer, pullModelManifest, hasTensorLayers, GetModel, verifyBlob |
| `server/download.go` | 509 | blobDownload struct, Prepare/run/downloadChunk, blobDownloadManager sync.Map |
| `server/upload.go` | 405 | blobUpload struct, Prepare/Run upload pipeline |
| `server/fixblobs.go` | 26 | filepath.Walk to rename sha256: → sha256- blobs |
| `server/model.go` | 130 | parseFromModel, detectChatTemplate, detectContentType |
| `server/internal/registry/server.go` | 417 | Local http.Handler, handlePull, handleDelete, decodeUserJSON |
| `server/internal/client/ollama/registry.go` | 1197 | Registry struct, Pull, Push, Resolve, ResolveLocal, send, chunksums, makeAuthToken |
| `manifest/layer.go` | 147 | NewLayer, NewLayerFromLayer, Open, Remove, touchLayer |
| `manifest/paths.go` | 95 | BlobsPath (regex gate), PathForName, Path, PruneDirectory |
| `manifest/manifest.go` | ~200 | ParseNamedManifest, Manifests |
| `x/imagegen/transfer/transfer.go` | ~230 | Download, Upload, digestToPath, parseAuthChallenge, backoff |
| `x/imagegen/transfer/download.go` | ~397 | downloader struct, download, downloadOnce, save, copy, resolve, speedTracker |
| `x/imagegen/transfer/upload.go` | ~300 | uploader struct, upload, uploadOnce, exists, initUpload, put, pushManifest |

## Critical Function Call Graphs

### Pull Pipeline (Legacy Path)
```
PullHandler (routes.go:914)
  └─ PullModel (images.go:595)
       ├─ makeRequestWithRetry → pullModelManifest (images.go:853) [io.ReadAll, no LimitReader]
       ├─ hasTensorLayers (images.go:711) [checks MediaType == "application/vnd.ollama.image.tensor"]
       │     TRUE → pullWithTransfer (images.go:721) [BYPASS: no BlobsPath validation on digests]
       │              └─ transfer.Download → downloader.download → downloader.downloadOnce
       │                   └─ downloader.save [inline sha256 hash; digestToPath has NO validation]
       │     FALSE → downloadBlob loop (images.go:643)
       │              ├─ manifest.BlobsPath(digest) [VALIDATED]
       │              ├─ os.Stat(fp) → cacheHit=true [NO hash on cache hit]
       │              └─ blobDownload.run → downloadChunk [Range header; no 206/Content-Range validation]
       └─ verifyBlob loop [only for non-cache-hit blobs; dead code path when streaming hash active]
```

### Transfer Fast Path — digestToPath
```
pullWithTransfer (images.go:721)
  layer.Digest (attacker-controlled from manifest)
  → transfer.Blob{Digest: layer.Digest}  [NO BlobsPath call]
  → transfer.Download → downloader.downloadOnce
      → dest = filepath.Join(d.destDir, digestToPath(blob.Digest))
           digestToPath: if digest[6] == ':' → digest[:6] + "-" + digest[7:]
           else → digest verbatim
           [NO regex, NO filepath.IsLocal, NO length check]
      → os.MkdirAll(filepath.Dir(dest), 0o755)  [creates attacker-chosen directories]
      → os.Create(dest + ".tmp")               [creates attacker-chosen .tmp file]
      → sha256 hash check: if "sha256:"+hex != blob.Digest → os.Remove(tmp)
        [.tmp NOT removed if blob.Size >= 64MB — resumable partial file persists]
      → os.Rename(tmp, dest)  [only runs if hash matches — but .tmp persists regardless for large blobs]
```

### Transfer Cache Hit Check
```
downloader.download (transfer/download.go:56)
  → os.Stat(filepath.Join(opts.DestDir, digestToPath(b.Digest)))
  → if fi != nil && fi.Size() == b.Size → SKIP (no hash check)
  [size-only check: attacker-planted file of correct size accepted without hash]
```

### Registry.Pull (client2 path)
```
registry.Local.handlePull (registry/server.go:259)
  [DISPATCHED BEFORE GIN MIDDLEWARE — allowedHostsMiddleware NEVER RUNS]
  → s.Client.Pull (ollama/registry.go:464)
       → r.Resolve → io.ReadAll(res.Body) [no LimitReader on manifest]
       → c.Get(l.Digest) → if info.Size == l.Size → ErrCached [size-only cache check]
       → r.chunksums → download range chunks to blob.Chunked writer
            → req.Header.Set("Range", ...) [sent, response Content-Range NOT validated]
```

### makeRequestWithRetry → WWW-Authenticate
```
makeRequestWithRetry (images.go:888)
  on 401:
    → parseRegistryChallenge(resp.Header.Get("www-authenticate"))
    → getAuthorizationToken(ctx, challenge, requestURL.Host)
         [server/auth.go:53 — realm host == originalHost check PRESENT here]
         → io.ReadAll(response.Body) [NO LimitReader — token bomb DoS]
```

### transfer.parseAuthChallenge path
```
downloader.resolve (transfer/download.go:326)
  on 401:
    → transfer.parseAuthChallenge(resp.Header.Get("WWW-Authenticate"))
    → d.getToken(ctx, ch)  [callback = getAuthorizationToken in images.go:755]
         → getAuthorizationToken(ctx, registryChallenge{...}, base.Host)
              [server/auth.go version — realm host check IS present]
  [realm check is present via callback; parseAuthChallenge in transfer has no check but
   the CHECK happens in the callback, not in parseAuthChallenge]
```

## Security-Relevant Data Types

| Type | Where | Notes |
|------|-------|-------|
| `manifest.Layer.Digest` | `manifest/layer.go:14` | string, attacker-controlled from registry JSON; only validated in `BlobsPath` |
| `manifest.Layer.Size` | same | int64, used for partial-file size check; attacker-controlled |
| `manifest.Layer.MediaType` | same | string, dispatches fast-path; attacker sets to `MediaTypeImageTensor` |
| `transfer.Blob.Digest` | `x/imagegen/transfer/transfer.go:39` | string copy of above; never validated |
| `blobDownload.Parts[].Offset` | `server/download.go:58` | int64, read from persisted JSON sidecar; trusted completely |
| `blobDownload.Parts[].Completed` | same | atomic.Int64; if persisted sidecar has Completed==Size, part is trusted without re-hash |
| `registryChallenge.Realm` | `server/images.go:1018` | string from `WWW-Authenticate` header; realm-host check in `getAuthorizationToken` |

## Key Constants / Invariants

- `manifest.MediaTypeImageTensor = "application/vnd.ollama.image.tensor"` — single true layer flips ALL layer digests to unvalidated path
- `transfer.resumeThreshold = 64 << 20` (64 MB) — blobs >= 64MB preserve `.tmp` file on failure; the persistent partial file is the write primitive for path traversal
- `numDownloadParts = 16`, `maxDownloadPartSize = 1000 MB` — up to 16 concurrent goroutines write to different offsets of one `*os.File`
- `maxRetries = 6` — download retried up to 6 times; each retry from `part.StartsAt()` NOT `part.Offset` (current tree) vs pre-patch all-start-from-0 behavior

## Missing Guards (Code-Level)

1. `x/imagegen/transfer/transfer.go:165` `digestToPath` — NO `regexp.MatchString`, NO `filepath.IsLocal`, NO length bound
2. `x/imagegen/transfer/download.go:58` cache-hit — `fi.Size() == b.Size` only; no sha256 verification
3. `server/download.go:478-491` cache-hit — `os.Stat` only; no hash; `cacheHit=true` returns immediately
4. `server/images.go:864` `pullModelManifest` — `io.ReadAll(resp.Body)` with no `io.LimitReader`
5. `server/auth.go:81` `getAuthorizationToken` — `io.ReadAll(response.Body)` with no `io.LimitReader`
6. `server/download.go:334-345` `downloadChunk` — no `resp.StatusCode == 206` check; no `Content-Range` validation
7. `server/internal/registry/server.go:114` dispatch — precedes gin chain; `allowedHostsMiddleware` skipped
8. `server/images.go:952` `makeRequest` — `regOpts.Insecure` can force HTTP; redirect target scheme is not re-checked

## Test Coverage Gaps

- `x/imagegen/transfer/transfer_test.go:724` `TestDigestToPath` — tests only `sha256:abc123→sha256-abc123`; NO traversal corpus
- No test for `pullWithTransfer` with malformed digest
- No test for `downloader.download` cache-hit with wrong-content file of correct size
- No test for `downloadChunk` with 200-response (not 206)
