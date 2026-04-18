# Round 1 Hypotheses — Backward Reasoner (Pre-Mortem / Abductive)

## PH-01: digestToPath arbitrary file write via tensor model pull (path traversal)

**Method**: Abductive (backward from known harm)
**Target**: `x/imagegen/transfer/transfer.go:165` — `digestToPath()`, `x/imagegen/transfer/download.go:213` — `downloader.save()`
**Attack input**: Manifest JSON with `"digest": "sha256:../../../etc/cron.d/evil"` served by attacker-controlled registry
**Code path**:
  `x/imagegen/transfer/download.go:58` (stat check uses digestToPath) →
  `download.go:168` (dest path construction) →
  `download.go:213-215` (os.MkdirAll + os.Create of dest+".tmp")
  No call to `manifest.BlobsPath` regex at any point.
**Sanitizers on path**: None. `digestToPath` performs `strings.Replace(":", "-", 1)` only. `filepath.Join` cleans `..` lexically but does NOT prevent escape from base directory.
**Security consequence**: Arbitrary file write (as `.tmp` suffix) under the ollama service user anywhere on the filesystem reachable from `DestDir`. Creates intermediate directories with 0o755. Hash check fails so `os.Rename` to final path does NOT run — but the `.tmp` file persists for large blobs (>=64 MB), enabling persistent writes to `/etc/cron.d/`, `/etc/profile.d/`, etc. For the exact path `sha256:../../../etc/cron.d/0pwn` the path becomes `sha256-../../../etc/cron.d/0pwn.tmp` which resolves to `/etc/cron.d/0pwn.tmp`.
**Severity estimate**: CRITICAL
**Status**: VALIDATED — confirmed by KB bypass analysis, confirmed by direct code reading (no `filepath.IsLocal`, no regex validation in digestToPath or callers)

---

## PH-02: resolveManifestPath directory traversal read via model name with `..`

**Method**: Pre-Mortem
**Target**: `x/imagegen/manifest/manifest.go:71` — `resolveManifestPath()`, `x/create/create.go:52` — `resolveManifestPath()`
**Attack input**: Model name `../../etc/passwd:latest` or `evil.com/../../etc/shadow/model:tag`
**Code path**:
  User calls `LoadManifest("../../etc/passwd:latest")` →
  `resolveManifestPath` splits on `/` and `:` →
  `filepath.Join(manifestDir, "registry.ollama.ai", "library", "../../etc/passwd", "latest")` →
  Resolves to `manifestDir/etc/passwd/latest` (one `..` absorbed) or deeper escapes with more segments
  Then `os.ReadFile(manifestPath)` is called.
**Sanitizers on path**: None. The function calls `strings.Split(name, "/")` and feeds results directly into `filepath.Join`. `model.ParseName` / `isValidPart` guard the main server-side manifest path resolution but these are independent copies without that guard.
**Security consequence**: Arbitrary file read from any path accessible to the ollama user. Content returned as error message or silently discarded on unmarshal failure. If the file is valid JSON the content is parsed; if it matches the Manifest struct, it can load a crafted manifest pointing to attacker-chosen blobs.
**Severity estimate**: HIGH
**Status**: VALIDATED — confirmed by direct code reading: no sanitization in either copy of resolveManifestPath

---

## PH-03: loadModelConfig / GetModelArchitecture blob path escape via digest in manifest

**Method**: Abductive
**Target**: `x/create/create.go:102` — `loadModelConfig()`, `x/create/create.go:159` — `GetModelArchitecture()`
**Attack input**: A manifest file on disk whose `Config.Digest` field is `sha256:../../../etc/shadow`
**Code path**:
  `loadModelConfig(modelName)` →
  `loadManifest(modelName)` reads manifest →
  `blobName := strings.Replace(manifest.Config.Digest, ":", "-", 1)` →
  `blobPath := filepath.Join(defaultBlobDir(), blobName)` where blobName = `sha256-../../../etc/shadow` →
  `os.ReadFile(blobPath)` reads arbitrary file
**Sanitizers on path**: None. `strings.Replace` is the only transformation applied to the digest before it becomes a file path.
**Security consequence**: Arbitrary file read as the ollama user. If the target file is valid JSON (e.g., `/etc/group`), its content is unmarshaled. More critically, any call path invoking `IsSafetensorsModel`, `IsImageGenModel`, `GetModelArchitecture` with an attacker-controlled model name and a crafted on-disk manifest yields arbitrary file read.
**Severity estimate**: HIGH
**Status**: VALIDATED — confirmed by direct code reading

---

## PH-04: BlobPath read-side arbitrary file read in x/imagegen/manifest

**Method**: Pre-Mortem
**Target**: `x/imagegen/manifest/manifest.go:101` — `BlobPath()`, callers `ReadConfig()`, `OpenBlob()`, `detectQuantizationFromBlobs()`
**Attack input**: A manifest where any `layer.Digest` = `sha256:../../../home/user/.ssh/id_rsa`
**Code path**:
  `LoadManifest(modelName)` (traversal from PH-02, or legitimate manifest with crafted digest planted via PH-01) →
  Any call to `manifest.ReadConfig(path)` → `m.BlobPath(layer.Digest)` → `os.ReadFile(blobPath)`
  Also: `detectQuantizationFromBlobs` in `GetModelInfo` reads first tensor blob header via `readBlobHeader(manifest.BlobPath(layer.Digest))`
**Sanitizers on path**: None.
**Security consequence**: Arbitrary file read. Especially severe if chained: PH-01 writes a crafted manifest JSON as a `.tmp` file; PH-02 reads it as a legitimate manifest; PH-04 reads arbitrary target files via `BlobPath`.
**Severity estimate**: HIGH
**Status**: VALIDATED

---

## PH-05: ed25519 key perm check missing — symlink / world-readable key leads to identity theft

**Method**: Pre-Mortem
**Target**: `auth/auth.go:21` — `GetPublicKey()`, `auth/auth.go:53` — `Sign()`
**Attack input**: Attacker replaces `~/.ollama/id_ed25519` with a symlink to an attacker-controlled key file, or creates the file world-readable in a shared environment
**Code path**:
  `Sign(ctx, bts)` →
  `os.ReadFile(filepath.Join(home, ".ollama", "id_ed25519"))` —
  No `os.Lstat` to detect symlink, no `fi.Mode() & 0o077 != 0` check, no owner check →
  `ssh.ParsePrivateKey(privateKeyFile)` →
  Returns attacker's key material as if it were the user's key
**Sanitizers on path**: None. The KB explicitly confirms this: "no Lstat, no ModeType check" (H2, H3 in bypass analysis for 64883e3c).
**Security consequence**: The signing identity used for ollama.com registry authentication is the attacker's key. All push/pull operations are authenticated as the attacker. In a shared CI environment (shared `OLLAMA_HOME` or Docker volume), a low-privilege process can substitute the key and impersonate the ollama user identity.
**Severity estimate**: HIGH
**Status**: VALIDATED

---

## PH-06: api/client.go::getAuthorizationToken challenge parity gap vs server/auth.go

**Method**: Abductive (Phase 2 seed)
**Target**: `api/client.go:88` — `getAuthorizationToken()`, vs `server/auth.go:53` — `getAuthorizationToken()`
**Attack input**: Timing or replay attack; or malicious server sending a crafted challenge
**Analysis**:
  - `api/client.go` challenge: `method + "," + path + "?ts=" + timestamp` — client-constructed, no server-supplied nonce
  - `server/auth.go` challenge: Uses `registryChallenge.URL()` which adds `ts` + a server-generated `nonce` (16-byte random) to the Realm URL, then signs `GET,<full-redirect-URL>,<sha256-of-empty-body>`
  These two code paths sign COMPLETELY DIFFERENT data formats. `api/client.go` is used for OLLAMA_AUTH local auth and direct ollama.com connections; `server/auth.go` is used for registry push/pull auth.
  The `api/client.go` challenge string contains no nonce — the timestamp `ts` is both constructed AND included by the client. If the server's verification window is large (e.g., ±300 seconds), a captured Authorization header can be replayed against the API server within that window.
  Furthermore, the server-side local auth verification (when `OLLAMA_AUTH=1`) must parse the client-format challenge; if any server-side code path calls `auth.Sign` for verification rather than constructing a nonce-based challenge, the absence of nonce makes replay trivially possible.
**Security consequence**: Replay attack on local OLLAMA_AUTH API; or signature accepted for wrong resource if the challenge format diverges.
**Severity estimate**: MEDIUM
**Status**: NEEDS-DEEPER — requires reading the server-side OLLAMA_AUTH verification path (not in this group's files)

---

## PH-07: CreateImageGenModel / CreateSafetensorsModel modelDir traversal

**Method**: Pre-Mortem
**Target**: `x/create/imagegen.go:20` — `CreateImageGenModel()`, `x/create/create.go:653` — `CreateSafetensorsModel()`
**Attack input**: Modelfile with `model: ../../sensitive_dir` or absolute path `/etc`
**Code path**:
  `ConfigFromModelfile` extracts `modelDir = cmd.Args` when `cmd.Name == "model"` →
  `CreateModel(opts)` where `opts.ModelDir` is the raw string →
  `os.ReadDir(componentDir)` / `os.ReadDir(modelDir)` reads from attacker-chosen location →
  `safetensors.OpenForExtraction(stPath)` opens any `.safetensors` file found →
  Tensor data from that file is hashed and written as a blob layer
**Sanitizers on path**: None for modelDir. `IsSafetensorsModelDir` checks for `config.json` existence but does not restrict where that directory can be.
**Security consequence**: An attacker with the ability to create a Modelfile (local user or via API if `POST /api/create` supports Modelfiles with the `model:` directive) can cause ollama to read and store as blobs arbitrary `.safetensors` and `.json` files from anywhere on the filesystem. This includes sensitive config files and, if the format happens to parse, potentially exfiltrates key material into the blob store.
**Severity estimate**: HIGH
**Status**: VALIDATED — confirmed by code reading

---

## PH-08: tools/template.go findToolCallNode nil-Pipe dereference — DoS via chat with tools

**Method**: Pre-Mortem
**Target**: `tools/template.go:51` — `findToolCallNode()` line `for _, cmd := range n.Pipe.Cmds`
**Attack input**: Template AST with an IfNode whose Pipe field is nil; reachable via `thinking.InferTags` or `template.Subtree` producing a non-parser-generated AST
**Code path**:
  Chat request with `tools: [...]` and non-nil `builtinParser` set to nil →
  `tools.NewParser(m.Template.Template, req.Tools)` →
  `parseTag(tmpl)` →
  `findToolCallNode(tmpl.Tree.Root.Nodes)` →
  `n.Pipe.Cmds` dereference on nil Pipe → nil-pointer panic
**Sanitizers on path**: `parseTag` checks `tmpl == nil || tmpl.Tree == nil` but does NOT check individual node Pipe fields. The stdlib parser always populates Pipe on IfNode for parser-generated trees, but `template.Subtree` / `deleteNode` / `thinking.InferTags` operate on the tree directly and can produce nodes with nil Pipe.
**Security consequence**: Process crash (nil-pointer panic recovered by gin's recovery middleware → 500 error, not process death); or if triggered in a goroutine without recovery: process termination. DoS for any chat request involving tools.
**Severity estimate**: MEDIUM
**Status**: NEEDS-DEEPER — depends on whether a reachable path produces a nil Pipe IfNode in production
