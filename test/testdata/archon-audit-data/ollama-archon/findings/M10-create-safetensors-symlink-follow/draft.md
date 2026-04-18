Phase: 8
Sequence: 010
Slug: create-safetensors-symlink-follow
Verdict: VALID
Rationale: CreateSafetensorsModel enumerates a user-supplied directory with os.ReadDir and opens each entry with os.Open (via safetensors.OpenForExtraction and direct JSON readers) without filepath.EvalSymlinks, filepath.IsLocal, or os.OpenRoot; symlinks are followed transparently, so model.safetensors -> /etc/shadow reads arbitrary files into the blob store.
Severity-Original: HIGH
Severity-Final: MEDIUM
PoC-Status: executed
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-02/debate.md

## Summary

`x/create/create.go:CreateSafetensorsModel` reads a directory with `os.ReadDir` and opens every `.safetensors` and `.json` entry with `os.Open`. No symlink resolution is performed. An attacker who can place files in the target directory (or who controls what `modelDir` points to) can create symlinks that, when followed, read arbitrary files owned by the Ollama process user.

This is the same class of bug fixed in commit `d931ee8f` for a different enumeration path (`filesForModel`); the fix was never applied to `CreateSafetensorsModel`. `archon/bypass-analysis/d931ee8f-symlink.md` documents this as a known gap.

## Location

- `x/create/create.go:695` -- `os.ReadDir(modelDir)`
- `x/create/create.go:706` -- `stPath := filepath.Join(modelDir, entry.Name())`
- `x/create/create.go:709` -- `safetensors.OpenForExtraction(stPath)` follows symlink
- `x/create/create.go:874` -- `os.Open(fullPath)` follows symlink for JSON config files

## Attacker Control

Any caller with write access to the directory passed to `CreateSafetensorsModel`:
- Direct: `x/create/client.CreateSafetensorsModel` invocation (requires `--experimental` + localhost).
- Indirect: `POST /api/create` with a Modelfile importing a directory the attacker wrote (mounted-in volume on shared-host deployments, or an NFS-backed home directory on multi-user servers).

## Trust Boundary Crossed

Filesystem permissions (Ollama process user's read access) -> model blob store -> exposed via `/api/show` and pullable by any user of the Ollama server.

## Impact

Arbitrary file read. Because Ollama frequently runs as root via systemd on Linux, this typically means read access to `/etc/shadow`, `/root/.ssh/id_ed25519`, `/proc/1/environ`, TLS private keys, and cloud credentials. The contents are hashed and stored as a blob, then returned by `/api/show` and any subsequent `/api/pull` from the same registry.

## Evidence

```
// x/create/create.go:695-716
entries, err := os.ReadDir(modelDir)
...
for _, entry := range entries {
    if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".safetensors") {
        continue
    }
    stPath := filepath.Join(modelDir, entry.Name())
    extractor, err := safetensors.OpenForExtraction(stPath)  // follows symlinks
    ...
}

// x/create/create.go:859-890 -- same pattern for .json files
for _, entry := range entries {
    ...
    fullPath := filepath.Join(modelDir, cfgPath)
    f, err := os.Open(fullPath)   // follows symlinks
    ...
}
```

Advocate (Round 3): confirmed via `bypass-analysis/d931ee8f-symlink.md` as a known unfixed gap; the `--experimental` + `isLocalhost` gate is opt-in but does not cover the server-side `convert.Convert` -> `parseSafetensors` chain reached via unauthenticated `/api/create`.

## Reproduction Steps

1. As an attacker with write access to a directory the victim will import:
   ```
   mkdir /tmp/poisoned
   echo '{"architectures":["foo"]}' > /tmp/poisoned/config.json
   ln -s /etc/shadow /tmp/poisoned/model.safetensors
   ```
2. Victim runs `ollama create mymodel -f /tmp/poisoned/Modelfile` or `POST /api/create` referencing the directory.
3. The contents of `/etc/shadow` are hashed and stored as a blob in `$OLLAMA_MODELS/blobs/`.
4. `GET /api/show` or `ollama cat <blob-digest>` exposes the contents.

Fix direction:
- Use `filepath.EvalSymlinks(stPath)` and verify the resolved path is `filepath.IsLocal` relative to `modelDir`.
- Or use `os.OpenRoot(modelDir)` / the Go 1.23+ `*Root` API which confines opens to within the directory.
- Reject any directory entry whose `Lstat().Mode() & os.ModeSymlink != 0` before calling `os.Open`.

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Built HEAD binary and observed /etc/passwd stored as a 9344-byte blob after `ollama create --experimental` imported a directory containing `malicious.json` symlinked to /etc/passwd; no EvalSymlinks/IsLocal/OpenRoot guard exists at x/create/create.go:859-890.
Severity-Final: MEDIUM
PoC-Status: executed
