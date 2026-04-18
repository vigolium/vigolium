Phase: 10
Sequence: 001-a
Slug: download-stat-oracle-digest-traversal
Verdict: VALID
Rationale: download.go:58 calls os.Stat(filepath.Join(destDir, digestToPath(b.Digest))) before any download attempt; attacker controls both b.Digest (traversal path) and b.Size (match threshold), turning the cache-skip branch into a filesystem existence and file-size oracle with no file writes.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-001-pullwithtransfer-digest-path-traversal.md
Origin-Pattern: AP-001R

## Summary

`x/imagegen/transfer/download.go:58` runs a pre-download cache check for each blob in the manifest.
It calls `os.Stat(filepath.Join(opts.DestDir, digestToPath(b.Digest)))` and compares the returned
file size against `b.Size`. If sizes match, the blob is classified as "already downloaded" and
skipped entirely. Because `digestToPath` does no charset or traversal validation, an
attacker-controlled manifest can set:

- `b.Digest` = `sha256:../../../home/ollama/.ssh/id_rsa` (traversal path)
- `b.Size` = candidate size (e.g., 411 bytes for a typical 4096-bit RSA key)

If the file at the traversal path exists and its `os.Stat().Size()` equals `b.Size`, the cache-skip
branch fires and:
1. The blob is omitted from the `blobs []Blob` slice passed to the parallel downloader.
2. Progress is credited for the "already completed" bytes.
3. No network request is made for that blob.

An attacker observing the `/api/pull` response stream (progress callbacks) or measuring timing can
distinguish "blob skipped (file exists at size S)" from "blob downloaded" — yielding a one-bit
oracle per probe. By issuing multiple pulls with varying `b.Size` values, the attacker performs a
binary search on the file size of any path readable as a filesystem stat by the ollama user. If
the size is known (e.g., SSH key format is regular), the oracle collapses to a single probe.

This is distinct from p8-001 (which writes files); this variant reads only filesystem metadata
(stat), does not create or modify files, and executes unconditionally before the download phase.

## Location

- `x/imagegen/transfer/download.go:57-65` — cache-skip stat check
- `x/imagegen/transfer/transfer.go:164-170` — `digestToPath` (shared, unvalidated)
- `server/images.go:720-728` — `pullWithTransfer` passes raw `layer.Digest` (same entry as p8-001)

## Attacker Control

Same delivery as p8-001: attacker hosts registry; victim does:
```
POST /api/pull {"name":"evil.registry/model:latest","insecure":true}
```

Attacker controls every field of every manifest layer:
- `Digest` — set to traversal path (e.g., `sha256:../../../home/ollama/.ssh/id_rsa`)
- `Size` — set to candidate file size being probed

Attacker does not need TLS, credentials, or prior local access.

## Trust Boundary Crossed

Network (attacker-controlled registry) → local filesystem metadata (ollama user scope). The
oracle crosses the network→local boundary by reflecting filesystem state through the observable
pull-progress behavior (blob skipped vs blob downloaded).

## Impact

- Filesystem existence and size oracle for any path stat-able by the ollama user.
- Enables enumeration of: SSH key presence and size, credential file sizes, config file presence.
- Combined with p8-001 (which writes files), enables targeted file-size matching to confirm
  file presence before attempting exfiltration via the push chain (p8-004).
- The oracle requires no write capability and leaves no filesystem artifact — it is silent.

## Evidence

```go
// x/imagegen/transfer/download.go:57-65
for _, b := range opts.Blobs {
    if fi, _ := os.Stat(filepath.Join(opts.DestDir, digestToPath(b.Digest))); fi != nil && fi.Size() == b.Size {
        // ^^^ os.Stat on attacker-controlled traversal path; fi.Size() compared to attacker-controlled b.Size
        if opts.Logger != nil {
            opts.Logger.Debug("blob already exists", "digest", b.Digest, "size", b.Size)
        }
        alreadyCompleted += b.Size
        continue  // blob removed from download list — observable to attacker via progress stream
    }
    blobs = append(blobs, b)
}
```

```go
// x/imagegen/transfer/transfer.go:164-170  (digestToPath — no validation)
func digestToPath(digest string) string {
    if len(digest) > 7 && digest[6] == ':' {
        return digest[:6] + "-" + digest[7:]  // sha256:../../../etc/passwd → sha256-../../../etc/passwd
    }
    return digest
}
```

Contrast with the guarded path in `manifest/paths.go:40-47` (`BlobsPath`) which enforces
`^sha256[:-][0-9a-fA-F]{64}$` and is never called by the transfer package.

## Reproduction Steps

1. Stand up attacker HTTP registry at `http://localhost:9001` serving:
   - Manifest with one tensor layer to trigger `pullWithTransfer`:
     ```json
     {
       "layers": [
         {"mediaType":"application/vnd.ollama.image.tensor",
          "digest":"sha256:aaaa...64hex...","size":1},
         {"mediaType":"application/vnd.ollama.image.model",
          "digest":"sha256:../../../home/ollama/.ssh/id_rsa",
          "size":411}
       ]
     }
     ```
   - Serve valid blob for the tensor layer digest.
2. Issue pull from victim:
   ```
   curl -X POST http://127.0.0.1:11434/api/pull \
     -d '{"name":"localhost:9001/evil/foo:latest","insecure":true}'
   ```
3. Monitor the streaming progress JSON. If `~/.ssh/id_rsa` is exactly 411 bytes:
   - The model layer blob download is SKIPPED (no network request for it).
   - `alreadyCompleted` is credited 411 bytes in the first progress update.
   - The pull completes with only one blob downloaded (the tensor stub).
4. If pull proceeds to download the `id_rsa` blob (and fails hash verification), the file does
   NOT exist at that size. Repeat with different `size` values to binary-search the file size.
