Adversarial Review: create-safetensors-symlink-follow
=====================================================

## Step 1 - Restated claim and decomposition

The finding alleges that `x/create/create.go:CreateSafetensorsModel` enumerates a
user-supplied directory with `os.ReadDir` and opens each `.safetensors` and
`.json` entry with `os.Open` / `safetensors.OpenForExtraction`. Neither the
Lstat/EvalSymlinks nor the `os.OpenRoot`/`IsLocal` guard is applied, so a
symlink entry (e.g. `malicious.json -> /etc/passwd`) is transparently followed
and its target contents are hashed into the Ollama blob store, then referenced
by the generated manifest.

Sub-claims:
- A. Attacker can plant a symlink in a directory the victim will import.
- B. The enumeration/open at `x/create/create.go:695-709` and `:859-874` does
  not reject symlinks or resolve paths against the enumerated root.
- C. The opened data is fed into `createLayer` / `createTensorLayer`, which
  write a content-addressed blob under `$OLLAMA_MODELS/blobs/`, producing a
  manifest layer that later exposes the data via pushing / `/api/show`.

## Step 2 - Independent code-path trace

Entry surface (cold):

- CLI entry `cmd.CreateHandler` in `cmd/cmd.go:148` checks the
  `--experimental` flag. When set, it requires `isLocalhost()` (cmd/cmd.go:137)
  and otherwise returns `errors.New("remote safetensor model creation not yet
  supported")`. With the gate satisfied, it calls
  `xcreateclient.CreateModel(...)` at `cmd/cmd.go:201`.
- `x/create/client/create.go:119 CreateModel` detects the safetensors layout
  via `IsSafetensorsModelDir` and calls
  `create.CreateSafetensorsModel(opts.ModelName, opts.ModelDir, ...)` at line
  161.
- `x/create/create.go:653 CreateSafetensorsModel`
  - line 695: `entries, err := os.ReadDir(modelDir)`
  - lines 701-706: iterate `.safetensors` entries, build `stPath` via
    `filepath.Join(modelDir, entry.Name())`. No `Lstat` check on
    `entry.Type()` / `os.ModeSymlink`.
  - line 709: `safetensors.OpenForExtraction(stPath)`; that function at
    `x/safetensors/extractor.go:183` uses `os.Open(path)` which follows
    symlinks by default.
  - lines 858-874: second loop iterates `.json` entries and calls
    `os.Open(fullPath)` on each, again with no symlink resolution.
  - line 879: the opened `*os.File` is passed to `createLayer`, which (via
    `manifest.NewLayer`) copies the entire file into the content-addressed
    blob store.

Nothing on the path performs `filepath.EvalSymlinks`, `filepath.IsLocal`,
`os.Lstat`, or `os.OpenRoot`.

Contrast with the unrelated server path (noted to dispute the draft's
attacker model): `/api/create` runs in `server/create.go:46
(*Server).CreateHandler`. For safetensors it calls
`convertFromSafetensors` (server/create.go:400) which
1. `os.MkdirTemp` creates a fresh tmpDir under `envconfig.Models()`.
2. `os.OpenRoot(tmpDir)` + `fs.ValidPath(fp)` + `root.Stat(fp)` reject paths
   outside the root.
3. `createLink(blobPath, filepath.Join(tmpDir, fp))` places digest-addressed
   blobs only.
4. `convert.ConvertModel(os.DirFS(tmpDir), t)` parses from the sandbox.

The HTTP entry never invokes `x/create.CreateSafetensorsModel`; the only
importer of `x/create(/client)` is `cmd/cmd.go`. The finding's verbiage in the
draft ("server-side convert.Convert -> parseSafetensors chain reached via
unauthenticated /api/create") therefore refers to a different sink and is not
reached by this specific code path.

## Step 3 - Protection surface search

| Layer | Observation |
|-------|-------------|
| Language | `os.Open` follows symlinks. `os.ReadDir` returns symlink entries without special treatment. |
| Framework | No ORM/template auto-escape relevance. |
| Application | `parser.fileDigestMap` (parser/parser.go:157) applies `filepath.EvalSymlinks` + `filepath.IsLocal` post-`filesForModel`, introduced in commit d931ee8f (verified via `git show d931ee8f -- parser/parser.go`). This guard is on the STANDARD `/api/create` CLI path (via `parser`), not on `x/create/CreateSafetensorsModel`. |
| CLI gate | `cmd/cmd.go:161-165` requires `--experimental` and `isLocalhost()`. This is an opt-in local-only gate; it does not block the symlink attack once the victim has opted in. |
| Server gate | `server/create.go:413-428` sandbox (`os.OpenRoot(tmpDir)`, `fs.ValidPath`, digest-addressed `createLink`) makes the HTTP path unreachable by attacker-planted symlinks. This also means the finding's "unauthenticated /api/create" narrative does not apply. |

No protection blocks the attack on the claimed CLI path.

## Step 4 - Real-environment reproduction

Environment:
- Repo `/Users/bytedance/Desktop/demo/ollama`, commit `57653b8e` (HEAD).
- Built binary via `go build -o /tmp/ollama_test .` (succeeded with only a
  duplicate-libs linker warning).
- `OLLAMA_MODELS=/tmp/ollama_test_models` to avoid clobbering user state.

Healthcheck: `/tmp/ollama_test --version` prints `ollama version is 0.18.3`.

Attack directory `/tmp/poisoned_p8_026/`:
- `model.safetensors`: minimal valid safetensors (single F32 tensor, 1
  element) generated by a short Go helper (`/tmp/make_st.go`).
- `config.json`: `{"architectures":["Llama"]}`.
- `malicious.json` -> symlink to `/etc/passwd` (9344 bytes).
- `Modelfile`: `FROM .`.

Invocation:
```
/tmp/ollama_test create test-malicious --experimental -f /tmp/poisoned_p8_026/Modelfile
```

Output: progress log reports
```
importing model.safetensors (1 tensors)
importing config config.json
importing config malicious.json
writing manifest for test-malicious
successfully imported test-malicious with 3 layers
Created safetensors model 'test-malicious'
```

Post-state in blob store (`/tmp/ollama_test_models/blobs/`):
- `sha256-5676bbb620dfd6c54c49e86831ea2577aa8d9cbc7e6ad5ea1f6848e9bc4f69fa`
  is exactly 9344 bytes (equal to `/etc/passwd`).
- `head -5` of that blob matches the first five lines of `/etc/passwd`
  (`## # User Database ...`).

Manifest
`/tmp/ollama_test_models/manifests/registry.ollama.ai/library/test-malicious/latest`
lists the blob as a layer named `malicious.json` with
`application/vnd.ollama.image.json` media type. The data is now part of the
model and would ship with any `ollama push` / `/api/show`.

Evidence stored in
`archon/real-env-evidence/p8-026-create-safetensors-symlink-follow/`:
- `blob-with-etc-passwd.bin`  (exfiltrated blob)
- `blob-first-5-lines.txt`    (leading content)
- `poisoned-dir-listing.txt`  (attack layout)
- `commit.txt`                (HEAD hash)

PoC-Status: executed.

## Step 5 - Briefs

### Prosecution

At HEAD `57653b8e`, running
`ollama create test-malicious --experimental -f <attacker-writable-dir>/Modelfile`
stores the full contents of `/etc/passwd` into the Ollama blob store as a
9344-byte blob and records it in the manifest as a named JSON layer. The
code path at `x/create/create.go:859-890` reads every `.json` entry with
`os.Open`, which follows symlinks. No `Lstat`, `EvalSymlinks`, `IsLocal`, or
`OpenRoot` guard is present. The prior fix in commit d931ee8f added exactly
these guards to `parser/parser.go:fileDigestMap` for the standard path,
demonstrating the maintainers' awareness of the class; the fix was not
propagated to `x/create/CreateSafetensorsModel`. On multi-user systems or
NFS-mounted home directories, any local-write-capable attacker can leak
victim-readable files via a symlinked `.json` sibling to a (legitimate-looking)
`.safetensors`. Once blob-ified, the data travels with `ollama push` and is
surfaced via `/api/show`.

### Defense

The vulnerability is real at the code level but the draft's framing
overstates reach. Three items constrain severity:

1. Only the CLI `--experimental` flag reaches this code path. `cmd/cmd.go:161`
   enforces `isLocalhost()`. The HTTP `/api/create` path goes through
   `server.convertFromSafetensors` which `os.OpenRoot`-sandboxes a tmpDir and
   only plants digest-addressed links from the existing blob store - it
   cannot be coerced into following an attacker symlink.
2. The CLI client `x/create/client.CreateModel` runs in-process as the
   invoking user (doc: "bypassing the HTTP API"). It does not execute with
   the Ollama daemon's privileges, so the "runs as root via systemd" clause
   in Impact is not satisfied by this code path; the read is limited to files
   the invoking user can already read.
3. The attack is user-initiated: the victim must voluntarily point
   `ollama create --experimental` at an attacker-controlled directory. This
   is a local, opt-in, shared-filesystem trust scenario, not an
   unauthenticated-network primitive.

Those three points, taken together, justify downgrading from HIGH.

## Step 6 - Severity challenge

Starting at MEDIUM.
- Not remotely triggerable (CLI flag + localhost gate + user-initiated):
  no HIGH upgrade.
- Reads occur with the invoking user's filesystem privileges, not a
  privileged daemon's: no auto-escalation to sensitive files like
  `/etc/shadow` on a typical developer workstation.
- Preconditions: opt-in `--experimental`, shared/attacker-writable directory,
  victim chooses to import it.
- Meaningful effect still present: the data is persisted to disk (blob store)
  and travels with the manifest on `ollama push` / `/api/show`, so the blast
  radius is larger than a single read.

Net: MEDIUM. Downgrade from original HIGH.

## Step 7 - Verdict

CONFIRMED with severity downgrade.

- Code gap: real and reproduced on the live binary at HEAD.
- Defense identifies no protection that blocks the CLI path.
- Defense does rebut the "unauthenticated /api/create" reach and the "runs as
  root" impact framing, which correctly lowers severity but does not
  invalidate the bug.
- PoC executed: /etc/passwd contents observed inside the blob store with
  matching size and first-five-line content.

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Built HEAD binary and observed /etc/passwd stored as a
9344-byte blob after `ollama create --experimental` imported a directory
containing `malicious.json` -> /etc/passwd; no EvalSymlinks/IsLocal/OpenRoot
guard exists at x/create/create.go:859-890.
Severity-Final: MEDIUM
PoC-Status: executed
