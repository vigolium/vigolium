# Bypass Analysis: 2aee6c17 — Streaming Hash Verification

- **Commit**: `2aee6c172b019bfe3f3b5a54b4feaa84bcf89dd6`
- **Branch**: `origin/jmorganca/download-stream-hash` (NOT YET MERGED to main as of HEAD `57653b8e`)
- **Author / Date**: jmorganca@gmail.com / 2025-12-20
- **Files**: `server/download.go`, `server/images.go`, `server/sparse_common.go`, `server/sparse_windows.go`, `server/download_test.go` (new)
- **Type**: undisclosed-fix / control-weakening (silent removal of explicit integrity check)
- **Cluster ID**: `cluster-blob-integrity` (related: `bf198c39` introduced the removed `verifyBlob`; PullModel pipeline)

## Patch summary

The pre-patch design ran a two-stage check:
1. `blobDownload.run()` downloaded N parts in parallel with `io.CopyN` into per-offset writers, with no integrity guarantee on the bytes.
2. `PullModel` then ran a serial loop calling `verifyBlob(layer.Digest)` over every layer, which re-opened each on-disk file and computed sha256 over its entire contents (`server/images.go:1030-1048`). On mismatch, the file was deleted and the pull failed (`server/images.go:660-680` pre-patch).

Post-patch, that loop is deleted from `images.go` (the `skipVerify` map and the entire `verifying sha256 digest` stage are removed; only a comment remains saying "Digest verification now happens inline during download in blobDownload.run() via the orderedWriter, so no separate verification pass is needed"). The integrity guarantee is now meant to come from `streamHasher` running concurrently with the part downloaders inside `run()`. The hasher waits on per-part `MarkComplete` signals via a `sync.Cond`, reads the written bytes back from disk via `ReadAt`, and finally `run()` compares `sh.Digest()` against `b.Digest`.

The intent is sound for the happy path. The problem is that the hash-check is no longer a *post-condition* of "blob exists in the blob store"; it is now coupled to a single code path inside `run()`. Several real and theoretical bypasses follow.

---

## Bypass verdict: **bypassable / relocated** (multiple distinct issues, varying severity)

The dominant pre-existing bypass (`cacheHit` short-circuit) is *worsened* because the second-line defence is gone. Several new failure modes are introduced by the streaming design.

---

## Finding 1 — `cacheHit` short-circuit no longer covered by a second-line check (HIGH)

**Path**: `server/download.go:714-727` in the post-patch tree.

```go
fi, err := os.Stat(fp)
switch {
case errors.Is(err, os.ErrNotExist):
case err != nil:
    return false, err
default:
    opts.fn(api.ProgressResponse{...})
    return true, nil    // <-- short-circuit, no hash check, ever
}
```

If a file exists at `GetBlobsPath(opts.digest)`, `downloadBlob` returns `cacheHit=true` without ever opening or hashing the file. Pre-patch, this was already the behaviour, but `PullModel` then called `verifyBlob(layer.Digest)` for any layer where `skipVerify[layer.Digest] == false`. Crucially, `cacheHit==true` set `skipVerify[layer.Digest] = true`, so even pre-patch the cache-hit branch *also* skipped verification. So this particular bypass is not new, but the patch deletes the only call-site of `verifyBlob` in the production pull path, eliminating the option to ever re-validate later — there is now no production caller of `verifyBlob` left.

Attack: any adversary with file-system write access to `$OLLAMA_MODELS/blobs/sha256-<digest>` (e.g., a co-tenant on a shared host, a malicious init container, a backup-restore pipeline, a misconfigured shared NFS mount) can pre-stage an arbitrary file under the expected blob name, and the next `ollama pull` referencing that digest will accept it untouched. Because Ollama treats blob files as model weights and as content-addressed Modelfile layers, this can lead to model substitution and, depending on layer type (e.g., `application/vnd.ollama.image.template`), code-influencing content swap.

**Bypass severity**: high in shared-storage scenarios; this was the original gap `verifyBlob` (commit `bf198c39`) was meant to backstop, and the patch silently removes that backstop. Recommend the cache-hit branch hash the file (or maintain a verified-blobs marker file) before returning success.

---

## Finding 2 — Hash check is gated by `g.Wait()` succeeding; failure paths short-circuit the hash check but leave the partial file resumable (HIGH)

**Path**: `server/download.go:484-500` post-patch.

```go
if err := g.Wait(); err != nil {
    close(progressDone)
    sh.Stop()
    return err     // <-- early return, never reaches digest comparison
}
<-hashDone
close(progressDone)
if err := sh.Err(); err != nil { return err }
if computed := sh.Digest(); computed != b.Digest {
    return fmt.Errorf("digest mismatch: got %s, want %s", computed, b.Digest)
}
// rename to final blob path
```

Important corollary: if `g.Wait()` returns an error, the function returns *before* the rename, so the partial file is not promoted to the final blob path on this run — but the bytes (and the per-part JSON sidecars in `b.Name + "-partial-N"`) are NOT deleted. The next call to `Prepare` (`server/download.go:265-282` post-patch) reads the surviving `*-partial-*` JSON files and *trusts* their `Completed` counter as the prefix already on disk. Specifically, `Prepare` does:

```go
b.Total += part.Size
b.Completed.Add(part.Completed.Load())
```

and then `run()` skips any part where `part.Completed.Load() == part.Size` (line 447) and only `MarkComplete`s those parts for the hasher. *No* re-hash of any byte that is "claimed complete" in the persisted JSON ever happens. This is also true pre-patch, but pre-patch the post-pull `verifyBlob` would catch a tampered prefix; post-patch nothing does, because the streaming hasher only consumes bytes for parts it sees marked complete during *this* run, not bytes already on disk before the run started.

Attack: an attacker with momentary write access to `$OLLAMA_MODELS/blobs/sha256-<digest>-partial` and `…-partial-<N>` JSON sidecars between two pull attempts (e.g. crash-resume scenario, stalled download) can supply attacker-controlled bytes for any prefix part with `Completed == Size` in the sidecar, and the next resume will accept those bytes unverified. The streaming hasher will only hash the *re-downloaded* tail; the prefix flows straight into `sh.Digest()` via `ReadAt` — so actually the digest WOULD catch this if the entire stream were read. Re-reading the code: `streamHasher.Run()` iterates all parts, waiting for each to be `completed[i]`, and `MarkComplete` is called both for already-complete parts at line 448 (`if part.Completed.Load() == part.Size { sh.MarkComplete(part.N); continue }`) and after a successful download at line 476. Then `Run()` reads from offset 0 forward, so the *prefix from disk* IS hashed. Good — this particular vector is closed by the streaming hasher.

However: the streaming hasher reads via `file.ReadAt(buf[:n], offset)` where `file` was opened with `os.OpenFile(b.Name+"-partial", os.O_CREATE|os.O_RDWR, 0o644)`. There is a TOCTOU window between the moment `MarkComplete` is signalled and the moment `ReadAt` actually reaches that offset (the hasher follows behind the writers; with 48 concurrent downloaders by default and 64 MB parts, the spread can reach gigabytes — the patch itself logs a "page cache pressure" warning at >4 GB). A second writer to the same fd (e.g., another `downloadChunkToDisk` goroutine handling a *retry* of a slow part) can clobber a region after `MarkComplete` but before the hasher reads it. See Finding 3.

**Bypass severity**: medium-high. The dominant bypass is the cache-hit case (Finding 1); the resume-prefix case is closed by the new design *if* the hasher actually reaches every byte before being told to stop.

---

## Finding 3 — Slow/stall retries reuse the same on-disk offset and can race the hasher (HIGH, novel)

**Path**: `server/download.go:452-481` post-patch.

The retry loop wraps `downloadChunkToDisk` in `for try := 0; try < maxRetries; try++`, and on `errPartSlow` or `errPartStalled` it calls the function *again* for the same `part`. Inside `downloadChunkToDisk`:

```go
w := io.NewOffsetWriter(file, part.Offset)   // always restarts at part.Offset (NOT part.Offset + Completed)
buf := make([]byte, 32*1024)
var written int64
for written < part.Size { ... }
```

Critically, every retry re-issues `Range: bytes=part.Offset .. part.Offset+part.Size-1` (line 533) and re-writes from `part.Offset` (line 540). Pre-patch, `downloadChunk` resumed at `part.StartsAt() == part.Offset + part.Completed.Load()` and used `io.CopyN(w, ..., part.Size - part.Completed.Load())`. Post-patch, the resume-within-a-part semantics have been removed and every retry starts from byte 0 of that part.

Race: assume part 5 finishes successfully at T0 and `sh.MarkComplete(5)` is called. The hasher goroutine is far behind — it is currently working on part 2. Meanwhile part 6's first attempt is flagged `errPartSlow` at T1, and a fresh `downloadChunkToDisk` for part 6 begins, which opens an `io.NewOffsetWriter(file, parts[6].Offset)` and starts streaming bytes. By the time the hasher reaches part 5's offset range, the bytes there are still correct, so this particular race is benign for *part 5*.

But consider the slow-retry case for *the same part*: part 5's first attempt got `errPartSlow` after writing 30 MB of its 64 MB. The slow detector returned `errPartSlow`. The retry loop calls `downloadChunkToDisk` again for part 5, which opens `io.NewOffsetWriter(file, parts[5].Offset)` and starts overwriting from byte 0 of part 5. The first attempt's HTTP body goroutine, however, is still alive: errgroup.WithContext returns when *any* goroutine errors, but the slow-watchdog returning `errPartSlow` does not actually cancel the context until `g.Wait()` in `downloadChunkToDisk` returns — and the watchdog's return only propagates the error up through `g.Wait()`. The fetcher goroutine should see ctx.Done because errgroup.WithContext cancels its derived context when any worker returns non-nil. Good — the fetcher is cancelled. But `resp.Body.Read(buf)` can race: the goroutine may have a buffered chunk in flight, do one more `w.Write(buf[:n])` to the *old* offset writer, and then exit. That stray write can land *into the same byte range that the retry's writer is now actively rewriting* with new bytes from a different HTTP response. With concurrent writes from two `io.NewOffsetWriter`s targeting overlapping ranges of the shared `*os.File` fd, the order of the two `pwrite` syscalls determines who wins.

A malicious origin (or a MITM on a non-TLS mirror — recall download.go has the `if mp.ProtocolScheme == "http" && !regOpts.Insecure { return errInsecureProtocol }` check in `images.go`, but `regOpts.Insecure` defaults to false only at top-level; the `directURL` follow-redirect chain does not re-check scheme on the redirect target) that wants to corrupt a small prefix can deliberately stall after sending the first 30 MB, win the post-cancel race for the last write, and the hasher will then read those attacker bytes.

**The streaming hasher will catch any final-state mismatch** because it reads from page cache after writes settle, *unless* the read happens *before* the late-arriving stray write. The hasher waits for `MarkComplete(part.N)`, which is only called on the `default:` branch (line 476) after the retry succeeded, so the hasher won't read part 5 until the *successful* attempt's `part.Completed.Store(part.Size)` and `b.writePart(...)` returned. After that, additional writes from a leaked-goroutine first-attempt fetcher could land *after* the hasher read.

Concretely: if the hasher reads bytes [parts[5].Offset .. parts[5].Offset+Size) at time T_h, and a stray late `pwrite` from the abandoned first attempt lands at time T_w > T_h within that range, the hasher computed the digest over the "correct" (second-attempt) bytes, the digest matches `b.Digest`, but the on-disk bytes that are subsequently `os.Rename`d into place are corrupted. The next process to read the blob (e.g., `llm.Server` mmap'ing the GGUF) sees attacker bytes.

**Severity**: high-leverage but constrained to (a) attacker-controlled origin or MITM on insecure registry, plus (b) winning a goroutine-cancellation race. Mitigation: the inner errgroup should `wait` for both goroutines including the cancelled fetcher before returning, OR the writer should use a per-attempt buffer that is `pread`-validated before being treated as "this attempt's bytes," OR — the cleanest — the streaming hasher should `fsync` and re-read tails of completed parts at the end before computing the final digest (which it does *not* do).

---

## Finding 4 — HTTP 206 Content-Range is not validated; server may return bytes from a different range than requested (MEDIUM)

**Path**: `server/download.go:528-565` post-patch (and pre-patch was identical in spirit).

```go
req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", part.Offset, part.Offset+part.Size-1))
resp, err := http.DefaultClient.Do(req)
...
w := io.NewOffsetWriter(file, part.Offset)
buf := make([]byte, 32*1024)
var written int64
for written < part.Size { ... }
```

There is no check on `resp.StatusCode` (must be 206 for a true range response; a 200 with a full body would dump the entire blob into one part's slot, overflowing into adjacent parts) and no check on `resp.Header.Get("Content-Range")` matching the requested range. Pre-patch, this was caught by `verifyBlob` at the end. Post-patch, the streaming hasher *will* eventually catch the wrong overall sha256, BUT:

- A 200-response (whole blob) into a `io.NewOffsetWriter(file, part.Offset)` will write up to `part.Size` bytes (the loop terminates at `written < part.Size`) and then `break` on the read loop's `if written < part.Size { ... }` condition only when the body is exhausted — actually it terminates on `written == part.Size` and then the goroutine completes successfully because the loop exits. The *rest* of the response body is discarded by `defer resp.Body.Close()`. So a 200 effectively writes the *prefix* of the whole blob into the slot of `part[N]`. For part 0 this will produce *correct* bytes; for parts N>0 this will produce wrong bytes for that range; the streaming hasher will then mismatch on `b.Digest`, returning a digest-mismatch error — but the partial file is not deleted, and the next `ollama pull` will resume from what it thinks is good prefix data (Finding 2 corollary), reading the stale corrupt prefix from sidecars marked Completed. Since the digest mismatch returned an error from `run()`, however, the blob never gets renamed to the final blob path, so subsequent processes do not consume it. The next pull WILL re-read sidecars with `Completed == Size` for whatever parts happened to "succeed" (any 200 response that fed exactly part.Size bytes into a part slot) and will skip downloading them, then the streaming hasher will again mismatch on the global digest, and the cycle repeats — *denial of service* but not silent corruption.

- A 206 response with a *different* Content-Range than requested (e.g., a malicious cache returning `bytes=0-X` for a `bytes=Y-Z` request) is also unchecked. Same outcome: digest mismatch caught, no silent compromise — but partial files persist and resume keeps re-trusting them.

**Severity**: medium. Permanent stuck-pull DoS (must `rm` the `-partial*` files manually). Not silent compromise; the streaming hasher does its job here.

---

## Finding 5 — Concurrent downloads of the same digest race on shared file descriptor and `blobDownloadManager` map (MEDIUM)

**Path**: `server/download.go:730` post-patch — `blobDownloadManager.LoadOrStore` is the dedup gate.

If two concurrent `ollama pull` calls reference the same digest, `LoadOrStore` ensures only one `blobDownload` struct is created and both callers `Wait` on it. So far so good: only one `run()` executes. But:

- The streaming hasher only knows about this `run()`. If the *first* `run()` errors out (Finding 4 case, or context cancel), the `blobDownloadManager.Delete(b.Digest)` happens at top of `run()` (line 347 `defer blobDownloadManager.Delete(b.Digest)`), the partial file remains, AND a *new* concurrent caller arriving after the deferred Delete but before the next `os.Stat` in `downloadBlob` may stat the *partial* file's path (`b.Name+"-partial"`)... no wait, `downloadBlob` stats `fp = GetBlobsPath(opts.digest)` which is the FINAL blob path, not the `-partial`. So the second caller will not cache-hit on a partial. It will create a new blobDownload, call `Prepare` which globs `b.Name + "-partial-*"` (sidecar JSONs), and trust their Completed counters again (Finding 2 issue compounded).

- Worse: the `file, err := os.OpenFile(b.Name+"-partial", os.O_CREATE|os.O_RDWR, 0o644)` (line 350 post-patch) is opened without `O_TRUNC` and without any locking. If the previous run's leaked fetcher goroutine (Finding 3) is *still* running when the next pull starts, two `*os.File` handles to the same path now exist, both writing concurrently, and the new run's `setSparse(file)` is GONE (the patch deleted `setSparse` and `_ = file.Truncate(b.Total)` — see lines 225-227 pre-patch versus 354 post-patch). So if `b.Total` shrinks across runs (different request hits a different mirror that lies about size), the file is not retruncated; if it grows, no preallocation. Mostly latent but cumulative with Finding 3.

**Severity**: medium. Not exploitable in isolation; compounds Finding 3.

---

## Finding 6 — Streaming hasher stops mid-stream on `g.Wait()` error and the partial file with a *valid prefix sha256 prefix-mismatch* persists (LOW, DoS only)

**Path**: lines 484-488 post-patch.

```go
if err := g.Wait(); err != nil {
    close(progressDone)
    sh.Stop()
    return err
}
```

`sh.Stop()` sets `h.done = true` and broadcasts the cond, causing `Run()` to exit early. No bytes are deleted. As discussed above, this leads to permanent stuck-pull until the user manually clears partials. Not a security bypass per se, but an availability issue caused by the patch's removal of the unconditional post-pull verification (which would otherwise have run a clean re-hash on a renamed file).

---

## Finding 7 — `verifyBlob` is now dead code in production but still exported in the `server` package (LOW, hygiene)

`server/images.go:1030 verifyBlob` and `errDigestMismatch` remain exported (lowercase but package-visible). After this commit, the only callers in the repo are tests. If the `errDigestMismatch` matching logic in `PullModel` is also removed (which it is — see the deleted block in the diff), there is no code path that performs mismatch-driven cleanup of the on-disk blob. The pre-patch code did:

```go
if errors.Is(err, errDigestMismatch) {
    fp, err := GetBlobsPath(layer.Digest)
    ...
    os.Remove(fp)
}
```

Post-patch, on a streaming digest mismatch, `run()` returns an error (line 499) but does NOT remove the partial file or the sidecars. The next pull will resume into the same broken state.

**Severity**: low. Compounds Findings 4 and 6.

---

## Finding 8 — gzip / Content-Encoding angle (CVE-2024-12886 lineage): NOT bypassable here

The streaming hasher reads back from disk via `ReadAt` after the writer wrote whatever bytes Go's `net/http` produced from `resp.Body.Read`. Go's default HTTP transport transparently decompresses `Content-Encoding: gzip` *only* when the client did not set `Accept-Encoding` (`http.Transport.DisableCompression` is false by default and the request here does not set Accept-Encoding). The bytes that reach `resp.Body.Read` and then get written to disk are therefore the decoded bytes. The hash is computed over those same on-disk bytes. So if the upstream server sends gzip-encoded content-with-Content-Encoding, the hasher sees the decoded bytes; for the hash to match `b.Digest`, the decoded bytes must be the original blob. A malicious server cannot trick the client into hashing the *encoded* form while writing the *decoded* form (or vice versa) because they are the same byte stream in this path.

The CVE-2024-12886 angle (gzip bomb) is *not* re-introduced by this patch because the HTTP transport's automatic decompression disclaims `Content-Length` (Go sets `resp.Uncompressed = true` and `resp.ContentLength = -1`). The download code never reads `resp.ContentLength` here; it reads up to `part.Size` bytes from the body. A gzip bomb would expand into many `part.Size`-bounded reads, but each part's loop terminates at `written == part.Size`, so write-amplification is bounded to `part.Size * num_parts == b.Total`. Disk-fill DoS is bounded to the requested blob size. Not a regression.

**Verdict for this vector**: sound.

---

## Finding 9 — Blob fetched but never registered as a layer

The `downloadBlob` function is only called from `PullModel`'s layer loop (`server/images.go:623-634` post-patch) and from the test suite. There is no path that fetches a blob without it being registered as a layer in the manifest, so blob-store pollution via "fetched but never registered" is not currently reachable. The streaming hasher's check is in `run()` which fires regardless of who caused the download. Sound.

---

## Cluster summary

| Finding | Severity | Type | New regression vs pre-patch? |
|---|---|---|---|
| 1. cacheHit bypass loses second-line check | HIGH | relocated | Yes (loses fallback) |
| 2. resume-prefix trust | MEDIUM-HIGH | sound (hasher reads prefix) | No — actually closed by streaming design |
| 3. slow-retry stray-write race | HIGH | bypassable | Yes (new code path) |
| 4. unchecked HTTP 206 / 200 / Content-Range | MEDIUM (DoS) | bypassable for DoS, sound for confidentiality | Worse (no cleanup) |
| 5. concurrent dl on shared fd + missing Truncate/setSparse | MEDIUM | relocated | Yes (Truncate removed) |
| 6. stuck partial after digest mismatch | LOW | relocated | Yes (no cleanup loop) |
| 7. dead `verifyBlob` + missing errDigestMismatch cleanup | LOW | hygiene | Yes |
| 8. gzip / Content-Encoding | n/a | sound | No |
| 9. orphan blob fetch | n/a | sound | No |

**Net verdict**: `bypassable / relocated`. The streaming-hasher design is correct for the post-completion final-byte state IF and only if (a) the hasher actually reads every byte before any post-completion modification, and (b) every code path that promotes bytes to "the blob" goes through `run()`. Finding 1 violates (b) for the cache-hit path, and Finding 3 violates (a) when slow-retry leaks a fetcher goroutine that wins the post-cancel write race.

**Recommendation for the maintainer (before merging)**:
1. In `downloadBlob`, when `os.Stat(fp)` succeeds, hash the file before returning `cacheHit=true` (or maintain a sibling `.verified` marker file written only after a successful streaming verify). Restoring the explicit `verifyBlob` call for cache hits closes Finding 1.
2. In the slow-retry branch, explicitly cancel the inner errgroup context AND `g.Wait()` for both goroutines before issuing the next attempt, OR open a per-attempt fd / use a write lease that is invalidated on abort. Closes Finding 3.
3. After `g.Wait()` succeeds, `file.Sync()` and only then run the final loop of the hasher OR re-read each part tail to ensure the page-cache view matches the disk view. Closes Finding 3 fully.
4. On any `return err` from `run()` after `Prepare`, delete the partial file and sidecars (or at least invalidate sidecars whose Completed == Size hasn't been hash-verified). Closes Finding 4 cleanup, Finding 6.
5. Validate `resp.StatusCode == 206` (or 200 only when `len(b.Parts) == 1 && part.Offset == 0`) and that `Content-Range` matches the request. Defence in depth for Finding 4.
6. Consider keeping `verifyBlob` as an end-of-pull belt-and-braces check; the cost is one O(blob-size) read from page cache (likely warm), measured at the same throughput as the streaming hasher.

