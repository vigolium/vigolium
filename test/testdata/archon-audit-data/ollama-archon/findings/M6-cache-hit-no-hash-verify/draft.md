Phase: 8
Sequence: 006
Slug: cache-hit-no-hash-verify
Verdict: VALID
Rationale: server/download.go:478 returns cacheHit=true on bare os.Stat; server/images.go:658 uses skipVerify to bypass verifyBlob for cache-hits; local co-tenant with blob-dir write access substitutes malicious bytes — Advocate confirmed no alternate hash check on the cache-hit path.
Severity-Original: MEDIUM
Severity-Final: MEDIUM
PoC-Status: pending
Pre-FP-Flag: check-4-ambiguous (requires shared-cache deployment for realistic attacker position)
Debate: archon/chamber-workspace/chamber-01/debate.md

## Summary

`server/download.go:478 downloadBlob` returns `cacheHit=true` purely on `os.Stat(fp)` succeeding — no size check, no hash check, no owner check. `server/images.go:641-660 PullModel` stores `skipVerify[layer.Digest] = cacheHit` and at line 657-660 skips `verifyBlob` whenever the flag is set. Consequence: any process that can write to `<OLLAMA_MODELS>/blobs/sha256-<digest>` can substitute model weights for any future pull of that digest, bypassing integrity verification entirely.

This is dangerous in configurations with shared blob directories:
- Docker images with `~/.ollama/` bind-mounted from host as shared volume (common for model persistence across containers).
- Multi-user Linux boxes where `/usr/share/ollama/.ollama/models/blobs/` is group-writable (operator group).
- CI runners that restore blob caches from artifact stores.
- NFS-mounted home directories in development environments.

In single-user default install (`~/.ollama/` owned by user, mode 0755 on directories), the attacker position is not easily achievable and severity drops.

## Location

- `server/download.go:467-492` — `downloadBlob`
- `server/download.go:478-491` — cache-hit branch (existence-only)
- `server/images.go:641-660` — `skipVerify` logic in `PullModel`
- `server/images.go:1030-1066` (approx) — `verifyBlob` (skipped on cache-hit)

Parallel path in `x/imagegen/transfer`:
- `x/imagegen/transfer/download.go:58` — also skips download when file size matches; stronger than the legacy existence-only check but still no hash verification on the cached content.

## Attacker Control

Local attacker with write access to `<OLLAMA_MODELS>/blobs/`. Realistic in:
- Multi-tenant Docker hosts with shared volume mounts.
- CI systems with shared cache dirs.
- Shared workstation / dev-server configs.

## Trust Boundary Crossed

Local co-tenant (filesystem) → inference runtime (model weights).

## Impact

- Substitute model weights for any cached digest; victim believes they are running the expected model (`ollama show` reports the legitimate digest) but the bytes loaded by llama.cpp / imagegen come from the attacker.
- Chain to: adversarial-prompt-injection baked into weights; GGUF tensor OOB if the pre-seeded Finding 9d902d63 area regresses; data exfiltration via influenced generation.

## Evidence

```go
// server/download.go:467-492
func downloadBlob(ctx context.Context, opts downloadOpts) (cacheHit bool, _ error) {
    if opts.digest == "" {
        return false, fmt.Errorf(("%s: %s"), opts.n.DisplayNamespaceModel(), "digest is empty")
    }
    fp, err := manifest.BlobsPath(opts.digest)
    ...
    fi, err := os.Stat(fp)
    switch {
    case errors.Is(err, os.ErrNotExist):
    case err != nil:
        return false, err
    default:
        opts.fn(...)
        return true, nil   // <-- cacheHit on bare existence, no size/hash
    }
    ...
}

// server/images.go:641-660
skipVerify := make(map[string]bool)
for _, layer := range layers {
    cacheHit, err := downloadBlob(ctx, downloadOpts{...})
    ...
    skipVerify[layer.Digest] = cacheHit   // <-- network-vouched cache-hit skips verify
    delete(deleteMap, layer.Digest)
}

fn(api.ProgressResponse{Status: "verifying sha256 digest"})
for _, layer := range layers {
    if skipVerify[layer.Digest] {
        continue                          // <-- skip verifyBlob
    }
    if err := verifyBlob(layer.Digest); err != nil { ... }
}
```

## Reproduction Steps

Shared-volume Docker example:
1. Container A (attacker) and Container B (victim) share volume `/root/.ollama`.
2. In container A: write a malicious GGUF file to `/root/.ollama/models/blobs/sha256-<known-llama3-digest>` of any size and any content.
3. In container B: `ollama pull llama3:latest` → `downloadBlob` stats the file, returns `cacheHit=true` → no hash check → `ollama run llama3` loads attacker bytes.

Debate context: The network-only variant of this attack is BLOCKED by `save()` hash verification in both the transfer and legacy download paths, so this finding is realistic only in deployments where a local attacker can write directly to the blob dir. Advocate marked this MEDIUM rather than HIGH because the attacker position is conditional. Fix: hash the cached file on `downloadBlob` cache-hit, or at minimum size-check against the expected `layer.Size`.
