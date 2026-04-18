# d931ee8f — Symlink Escape Bypass Analysis

- **Commit**: `d931ee8f22d38a87d4ff1886ccf56c38697f3fa0`
- **Type**: undisclosed-fix (silent security fix; PR title was "create blobs in parallel")
- **Files patched**: `parser/parser.go` (`fileDigestMap`)
- **Cluster ID**: `cluster-symlink-escape`

## Patch Summary

The fix added a 3-step path validation to `fileDigestMap()` for every file
returned by `filesForModel()`:

```go
f, err := filepath.EvalSymlinks(f)              // resolve symlinks
rel, err := filepath.Rel(path, f)               // make relative to model dir
if !filepath.IsLocal(rel) {                     // reject paths that escape
    return nil, fmt.Errorf("insecure path: ...")
}
```

Pre-fix: a model directory containing `model.safetensors -> /etc/shadow`
would have the symlink target read, hashed, and uploaded to the local
blob store as a layer (and pushable to a registry).

The validation is gating only on the `parser.fileDigestMap` enumeration
that backs the standard `client.Create` API path used by the unprivileged
`ollama create` HTTP client flow.

## Bypass Hypotheses Tested

### 1. Alternate entry points (BYPASSED)

**Result: BYPASSED** — `x/create/create.go::CreateSafetensorsModel` and
`x/create/imagegen.go::CreateImageGenModel` enumerate the SAME model
directory via `os.ReadDir` and open files (`*.safetensors`, every `*.json`,
specific config files such as `tokenizer/vocab.json`, `text_encoder/config.json`,
`model_index.json`) via `os.Open` / `os.ReadFile` with **no symlink
resolution, no `filepath.IsLocal`, no `os.OpenRoot` containment**.

Concrete bypass path:

```
cmd/cmd.go:148 CreateHandler
  if --experimental:
    cmd/cmd.go:201  xcreateclient.CreateModel(opts)
      x/create/client/create.go:119  CreateModel
        x/create/create.go:653  CreateSafetensorsModel
          x/create/create.go:695  os.ReadDir(modelDir)        # plain readdir
          x/create/create.go:706  filepath.Join(modelDir, entry.Name())
          x/create/create.go:709  safetensors.OpenForExtraction(stPath)  # follows symlink
          x/create/create.go:874  os.Open(filepath.Join(modelDir, entry.Name()))   # any *.json
          x/create/create.go:879  createLayer(f, "...image.json", cfgPath)         # blob written
```

For image-gen models the same applies in `x/create/imagegen.go:135-198` —
the 9 hard-coded config files (`model_index.json`, `tokenizer/vocab.json`,
etc.) are opened via `os.ReadFile` / `os.Open` and persisted as blob
layers. A symlink at `<modelDir>/tokenizer/vocab.json -> /etc/shadow` is
read in full and stored as an Ollama image layer, mirroring the exact
pre-d931ee8f outcome.

**Gating caveat**: this entry point is gated behind the `--experimental`
CLI flag and an `isLocalhost()` check (cmd.go:161-165). It is therefore a
**default-state gap** rather than a fully exposed bypass — but once the
operator opts in (an explicitly documented user feature for safetensors
import), the protection that d931ee8f added is silently absent.

### 2. TOCTOU between EvalSymlinks and Open (PARTIALLY BYPASSABLE)

`fileDigestMap` resolves the symlink at parser/parser.go:173 and stores
the **resolved real path** in `files`. Later, `digestForFile`
(parser/parser.go:220) calls `filepath.EvalSymlinks(filename)` AGAIN on
the already-resolved path before `os.Open`.

If the real-path location is itself replaced with a new symlink between
the two `EvalSymlinks` calls, the second resolve walks the new symlink
and `os.Open` reads the swapped target. The `os.Open` at line 226 is not
performed on the file descriptor that was validated.

This is a real TOCTOU window. Exploitation requires write access to the
resolved real path location, so it is mainly relevant when the model
directory is on a path writable by another local user (e.g.
`/tmp/shared-models/`). It does NOT defend the `--upload-this-as-a-blob`
behavior under concurrent local-user attack.

`createBlob` in `cmd/cmd.go:332` ALSO repeats `EvalSymlinks` then `os.Open`
— same TOCTOU.

### 3. detectContentType opens files BEFORE the symlink check
(BENIGN INFO LEAK)

`filesForModel` calls `detectContentType` on every glob match
(parser/parser.go:264-265) which `os.Open`s the file. This happens BEFORE
the symlink check in `fileDigestMap`. For safetensors globs, the
`contentType` argument is `""`, so the type comparison at line 267 is
skipped — meaning ANY symlink target is opened and 512 bytes are read
for the type check.

Effect:
- Bounded read of 512 bytes (returned only via `http.DetectContentType`
  string, not stored).
- Side effect: opening device files (`/dev/zero`, FIFOs) can hang the
  goroutine before the validation ever runs.
- Side effect: `os.Open` on `/etc/shadow` as root succeeds before the
  IsLocal check rejects the path.

Not a confidentiality bypass for blob upload, but the symlink-induced
side effects (hang, audit log noise, FD pressure) are reachable.

### 4. Symlink to directory whose contents are walked (BLOCKED but caveat)

`filesForModel` uses `filepath.Glob`, which uses `os.Lstat` for matching
the final path component but `os.Stat` for intermediate ones (resolves
intermediate symlinks). A subdirectory that is itself a symlink to `/etc`
is followed when matching `**/*.json` or `**/tokenizer.model`.

However, Go stdlib `filepath.Glob` does not implement `**` recursive
matching — `**` is treated as a single-segment glob, so `<modelDir>/**/*.json`
only matches one level of subdirectories. The post-glob symlink check
still catches the resolved path, so this is blocked in `fileDigestMap`.

But in the `x/create` path (hypothesis #1), `os.ReadDir` enumerates direct
entries and `safetensors.OpenForExtraction` follows symlinks to opened
files. Combined with hypothesis #1 this remains a bypass.

### 5. Windows path semantics (POTENTIALLY BYPASSABLE)

`filepath.IsLocal` on Windows treats drive-rooted paths (`C:\...`) and
UNC paths (`\\server\share\...`) as non-local, so the standard cases are
covered. However:

- **Junctions and reparse points**: `filepath.EvalSymlinks` follows NTFS
  junctions, so a junction pointing outside the model dir is resolved and
  then rejected by `IsLocal`. Safe.
- **Long path prefix (`\\?\`)**: `EvalSymlinks` may return a `\\?\C:\...`
  prefixed path on Windows. `filepath.Rel(modelDir, "\\?\C:\foo\bar")`
  may produce non-canonical results that defeat `IsLocal` lexical
  comparison. Worth runtime testing on Windows; current macOS/Linux tests
  in repo cover none of this.
- **Alternate Data Streams (ADS)**: `model.safetensors:hidden` is one
  filename on NTFS — `filepath.Glob` does NOT match ADS suffixes, so not
  reachable via the glob, but a Modelfile path that explicitly references
  `<modelDir>/foo:bar` would bypass the directory enumeration.

### 6. Race during parallel blob creation (BYPASSED via TOCTOU)

The post-d931ee8f code creates blobs in parallel (`errgroup` in
cmd/cmd.go:257). The parallelism amplifies the TOCTOU race in
hypothesis #2 — many goroutines call `createBlob` -> `EvalSymlinks` ->
`os.Open` concurrently after `fileDigestMap` already validated the
paths once. An attacker swapping symlinks between validation and any
goroutine's open succeeds with high probability.

### 7. Default-state gaps (BYPASSED)

`--experimental` (hypothesis #1) is the primary default-state gap. There
is no other env-var gate that disables the symlink check itself.

### 8. Parser differentials (NOT FOUND)

`expandPath` (parser/parser.go:632) does NOT call `EvalSymlinks` on the
model directory path itself before passing it to `fileDigestMap`. That
means if the user's model dir is itself a symlink (e.g.
`./models/foo -> /home/user/realmodels/foo`), then `filepath.Rel(symlinkDir,
realPath)` produces a relative path full of `..` and `IsLocal` returns
`false`. This causes legitimate symlinked model dirs to FAIL with
"insecure path" — a usability bug, not a security bypass. (No CVE
material here, but it is the kind of thing that drives users to disable
the check or shell-out to copy the dir, which expands the bypass surface.)

### 9. Sibling ADAPTERS path (PROTECTED — same code path)

`fileDigestMap` is invoked for both `model` and `adapter` Modelfile
commands (parser/parser.go:71 and 92), so the symlink check covers both.

## Conclusion

**PARTIALLY_BYPASSED**

- The parser/parser.go fix is correct **for the legacy `client.Create`
  HTTP API path** that the d931ee8f commit was scoped to.
- The same vulnerability class exists, unfixed, in `x/create/create.go`
  and `x/create/imagegen.go` (`CreateSafetensorsModel`,
  `CreateImageGenModel`) reached via `cmd/cmd.go --experimental`. This is
  the **relocated/incomplete** form of the same bug: a symlinked
  `tokenizer/vocab.json` or `model_index.json` is read in full and
  written to the local blob store as a model layer, with no
  `EvalSymlinks` / `IsLocal` / `OpenRoot` defense.
- A real TOCTOU race exists in both `fileDigestMap`+`digestForFile` and
  `createBlob` due to repeated `EvalSymlinks`-then-`Open` patterns. Risk
  is bounded to threat models where another local principal can write to
  the resolved real-path location.
- The fix has no Windows-specific test coverage; `\\?\` long-path prefix
  behavior under `filepath.Rel`/`IsLocal` should be confirmed on Windows.

## Notes for Phase 5/8

- **Phase 5 (chamber: x/create symlink escape)**: Strong candidate for a
  patch-bypass finding. The same vulnerability class that d931ee8f fixed
  in `parser` exists unfixed in `x/create`. Recommended chamber prompt:
  "Show that `x/create.CreateSafetensorsModel` and
  `x/create.CreateImageGenModel` will read and persist as blobs the
  contents of `<modelDir>/tokenizer/vocab.json` (and any other listed
  config) when that path is a symlink to an arbitrary file the ollama
  process can read."
- **Phase 5 (chamber: TOCTOU on EvalSymlinks pair)**: Lower priority,
  needs a multi-user threat model. Useful for completeness.
- **Phase 8 (regression hardening)**: Suggest an `os.OpenRoot(modelDir)`
  wrapper used by both `parser.fileDigestMap` and the `x/create` family,
  combined with `root.Open` for all subsequent reads. This eliminates
  both the alternate entry point AND the TOCTOU race.
- **Cluster note**: This commit is a single-commit cluster from
  Phase-2 commit-archaeologist. No adjacent commits touch the same
  `filesForModel` / `fileDigestMap` functions in the same window.
