Phase: 10
Sequence: 053
Slug: imagegen-blob-size-only-cache
Verdict: VALID
Rationale: x/imagegen/transfer/download.go skips downloading (and thus never SHA-256 verifies) blobs that already exist at the expected path with matching size, enabling local blob substitution identical to the p8-044 size-only DiskCache check.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-044-blob-cache-poisoning.md
Origin-Pattern: AP-004

## Summary

`x/imagegen/transfer/download.go:58` checks if a blob already exists by comparing file size only (`fi.Size() == b.Size`). If the check passes, the blob is skipped entirely -- no SHA-256 verification is performed, and no download occurs. A local attacker (or anyone who can write to the blob directory) can substitute a same-size malicious safetensors file and the imagegen downloader will silently accept it, never verifying its digest.

This is the imagegen parallel of the `server/internal/cache/blob/cache.go:459` size-only check identified in p8-044, but in the transfer subsystem that handles imagegen model downloads.

Note: when a blob *is* downloaded, the `save()` function at line 196 does verify SHA-256 (`if got := fmt.Sprintf("sha256:%x", h.Sum(nil)); got != blob.Digest`). The vulnerability is exclusively on the cache-hit skip path.

## Location

- `x/imagegen/transfer/download.go:58` -- `if fi, _ := os.Stat(...); fi != nil && fi.Size() == b.Size { ... continue }` -- size-only check, SHA-256 skipped
- `x/imagegen/transfer/download.go:196-198` -- `save()`: SHA-256 verification present only for fresh downloads, never for cache hits

## Attacker Control

Local attacker with write access to `opts.DestDir` (the blob directory, typically `~/.ollama/models/blobs/`) can:
1. Identify target blob by digest name and size from the model manifest
2. Create a malicious safetensors file of exactly the same byte count
3. Place it at the expected path (`sha256-<digest>`)
4. Next time imagegen downloads or loads the model, the malicious blob is accepted without verification

## Trust Boundary Crossed

Local filesystem (attacker-writable blob directory) -> imagegen model loading pipeline -> safetensors parser -> MLX inference runtime.

## Impact

- Integrity bypass: malicious safetensors loaded without digest verification
- Can chain with p10-031 (safetensors OOM) for denial of service
- Can deliver adversarially crafted tensors affecting inference output (model poisoning)
- In container environments with 0o777 blob directory permissions (p8-044 mechanism), any local process can exploit this

## Evidence

1. `x/imagegen/transfer/download.go:58`: size-only skip: `if fi, _ := os.Stat(filepath.Join(opts.DestDir, digestToPath(b.Digest))); fi != nil && fi.Size() == b.Size { ... continue }`
2. `x/imagegen/transfer/download.go:196`: digest check only fires in `save()`, which is only called when a blob is actually downloaded (not when skipped)
3. Structural parallel: `server/internal/cache/blob/cache.go:459`: `if err == nil && info.Size() == size { return nil }` with `// TODO: Do the hash check`
4. `x/imagegen/safetensors/safetensors.go:83-116`: `LoadModelWeights` loads safetensors directly from blob paths without any post-load integrity check
