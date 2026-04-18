# Attack Surface Map: Group F+G (x/create, x/imagegen, harmony, thinking, sample, tools, discover, api/client.go, auth/auth.go, envconfig)

## Entry Points

- `x/imagegen/transfer/transfer.go:165` — `digestToPath(digest string)` — accepts raw digest strings from manifest JSON without validation
- `x/imagegen/transfer/download.go:58` — `download()` cache-hit stat check — accepts blob.Digest from caller without invoking BlobsPath regex
- `x/imagegen/transfer/download.go:212` — `downloader.save()` — accepts attacker-controlled blob.Digest to construct dest/tmp file paths
- `x/imagegen/manifest/manifest.go:101` — `ModelManifest.BlobPath(digest)` — strings.Replace only, no allowlist/regex on digest
- `x/imagegen/manifest/manifest.go:71` — `resolveManifestPath(modelName)` — splits on "/" only, `..` is a valid segment
- `x/create/create.go:52` — `resolveManifestPath(modelName)` — identical vulnerability: `..` allowed in any path component
- `x/create/create.go:102` — `loadModelConfig()` — derives blob path from `manifest.Config.Digest` with only strings.Replace
- `x/create/create.go:159` — `GetModelArchitecture()` — reads layer.Digest from manifest with only strings.Replace
- `x/create/imagegen.go:20` — `CreateImageGenModel()` — accepts modelDir from caller, no containment check before ReadDir
- `x/create/create.go:653` — `CreateSafetensorsModel()` — accepts modelDir from caller, iterates all .safetensors and .json
- `x/create/client/create.go:119` — `CreateModel()` — top-level entry; accepts ModelDir string directly from Modelfile parser
- `auth/auth.go:21` — `GetPublicKey()` — reads `~/.ollama/id_ed25519`; no Lstat, no owner/perm check
- `auth/auth.go:53` — `Sign()` — reads same key path; no Lstat, no mode check
- `api/client.go:88` — `getAuthorizationToken()` — builds challenge string from method+path+timestamp; calls Sign()
- `api/client.go:43` — `checkError()` — json.Unmarshal of 401 body into AuthorizationError; swallows unmarshal error
- `api/client.go:222` — `stream()` — reads `signin_url` from server JSON response; passes verbatim to caller
- `envconfig/config.go:113` — `Models()` — reads OLLAMA_MODELS env var; no path validation before use as base for all blob/manifest paths
- `tools/template.go:50` — `findToolCallNode()` — walks parse.IfNode.Pipe.Cmds without nil-Pipe guard
- `tools/template.go:108` — `findTextNode()` — same walker pattern, no nil-List guard on IfNode/RangeNode/WithNode
- `x/imagegen/server.go:116` — `Server.Load()` — spawns subprocess with s.modelName directly as --model argument
- `x/imagegen/safetensors/loader.go:75` — `LoadModule()` — reflection-based weight loader; accepts weight names from manifests

## Trust Boundary Crossings

- **Registry manifest -> blob path construction**: Attacker-controlled manifest JSON (from a malicious registry or `POST /api/pull` with attacker host) flows into `digestToPath()` and `BlobPath()` without the `manifest.BlobsPath` regex guard that protects the legacy pull path. This crosses from untrusted network data into filesystem write operations.
- **Modelfile model: directive -> modelDir**: A user-supplied Modelfile `model:` path (processed by `ConfigFromModelfile`) becomes `opts.ModelDir` with no containment check. This crosses from user text input into `os.ReadDir(modelDir)` and all subsequent file operations.
- **Server JSON response -> SigninURL in CLI output**: A server-supplied `signin_url` field flows through `api/client.go:stream()` into `AuthorizationError.SigninURL` with no host pinning, then the CLI prints it to the user verbatim.
- **OLLAMA_MODELS env var -> all blob/manifest base paths**: The `Models()` function reads an env var with no sanitization. Every blob and manifest path is rooted here. A malicious OLLAMA_MODELS (e.g. `../../etc`) would affect all model storage paths.
- **ed25519 private key file -> signing oracle**: `auth/auth.go:Sign()` reads `~/.ollama/id_ed25519` with no permission or ownership check. If that file is a symlink or world-readable, the key material is usable by a different UID.
- **MLX subprocess model name -> exec.Command args**: `s.modelName` flows directly into `exec.Command(exe, "runner", "--imagegen-engine", "--model", s.modelName, ...)` without shell quoting (safe because individual args, but path traversal within modelName is not checked).

## Auth / AuthZ Decision Points

- `api/client.go:119` — `do()` — decides whether to call `getAuthorizationToken` based on `envconfig.UseAuth() || c.base.Hostname() == "ollama.com"`. If neither condition holds (default local server), the Authorization header is omitted entirely.
- `api/client.go:184` — `stream()` — same logic; auth token only added for `OLLAMA_AUTH=1` or direct ollama.com connections.
- `auth/auth.go:53` — `Sign()` — produces ed25519 signature from private key; the challenge is caller-constructed: `method + "," + path + "?ts=" + timestamp`. No server-side nonce; the client constructs its own challenge. If the server does not validate the timestamp, replay within the window is possible.
- `server/auth.go` (not in this group but relevant): The server-side counterpart validates the Authorization header; parity with client construction must hold.
- `envconfig/config.go:234` — `UseAuth` — boolean env var; default false means auth is OFF for all local API calls.

## Validation / Sanitization Functions

- `manifest.BlobsPath(digest)` — regex `^sha256[:-][0-9a-fA-F]{64}$` — GUARDS legacy pull/push; NOT called by `pullWithTransfer` or `x/imagegen/transfer`
- `x/imagegen/transfer/transfer.go:165` — `digestToPath()` — NO validation; raw strings.Replace of `:` with `-` only
- `x/imagegen/manifest/manifest.go:101` — `BlobPath()` — NO validation; same strings.Replace
- `x/create/create.go:52` — `resolveManifestPath()` — NO validation; `..` segments pass through filepath.Join
- `model.ParseName()` + `isValidPart()` — validates host/namespace/model/tag for manifest *filenames*; does NOT cover blob digests inside manifests
- `auth/auth.go` — no `Lstat`, no `os.FileMode` check at key-load time
- `envconfig.Models()` — no path validation on `OLLAMA_MODELS` value

## Layer Trust Chain

| From Layer | To Layer | Trust Assumption | Holds for ALL paths? | Alternate Paths that Skip This Layer? |
|-----------|---------|-----------------|:---:|---|
| Network (registry manifest JSON) | Blob filesystem write | Digest is validated by `manifest.BlobsPath` regex | NO | `pullWithTransfer` / `x/imagegen/transfer` use `digestToPath()` which has no regex |
| User Modelfile text | modelDir filesystem read | modelDir is a local directory under user control | NO | Modelfile `model:` accepts any path; no containment check relative to CWD or home |
| OLLAMA_MODELS env var | All blob/manifest base paths | Env var is a safe absolute path | NO | No sanitization; adversary-controlled env (CI, container) can redirect to /etc or /tmp |
| Registry manifest | `resolveManifestPath()` path | modelName has been validated by `model.ParseName` | NO | `x/imagegen/manifest/resolveManifestPath` and `x/create/create.go:resolveManifestPath` do their own naive split, `..` passes through |
| ed25519 key file | Signing oracle | File at `~/.ollama/id_ed25519` is owned and protected | NO | No perm/owner check; symlink followed silently; world-readable file accepted |
| Server 401 JSON | CLI output / `SigninURL` field | Server is trusted ollama.com | NO | Any server (local attacker, MITM) can plant arbitrary `signin_url`; client prints verbatim |
| Middleware (allowedHostsMiddleware) | imagegen server handlers | All requests pass host validation | NO | `OLLAMA_HOST=0.0.0.0` disables middleware; `OLLAMA_EXPERIMENT=client2` skips it for /api/pull and /api/delete |
| `template.Parse()` validation | `tools/findToolCallNode` walker | Template AST has well-formed Pipe/List nodes | NO | `tools/template.go` walker has no nil-Pipe or nil-List guards; depends on stdlib invariant |

## Trust Chain Gaps (rows where "Alternate Paths" column is NOT empty)

1. **digest-path-bypass**: `pullWithTransfer` (server/images.go) and `x/imagegen/transfer/download.go:digestToPath()` construct filesystem paths from manifest-supplied digest strings without invoking `manifest.BlobsPath` regex. An attacker-controlled manifest can supply `sha256:../../../etc/cron.d/evil` to achieve arbitrary file write (`.tmp` suffix) under the ollama service user. Confirmed by KB bypass analysis section for CVE-2024-37032.

2. **modeldir-traversal**: `CreateImageGenModel` and `CreateSafetensorsModel` accept a `modelDir` argument derived from Modelfile `model:` directive without any containment check. An adversary supplying `model: /etc` or `model: ../../../sensitive` could cause the importer to read arbitrary `.safetensors` or `.json` files outside the intended model directory.

3. **manifest-resolveManifestPath-traversal**: Both `x/imagegen/manifest/resolveManifestPath()` and `x/create/create.go:resolveManifestPath()` accept model names with `..` segments (e.g., `../../etc/passwd:latest`) and build `filepath.Join(manifestDir, host, namespace, name, tag)` paths that escape the manifest directory. This enables arbitrary manifest file reads from anywhere the ollama user can read.

4. **key-no-perm-check**: `auth/auth.go:GetPublicKey()` and `Sign()` call `os.ReadFile(keyPath)` without `Lstat` owner/mode checks. A symlinked or world-readable key file is accepted silently. Combined with `~/.ollama/` being mode 0755 by default, any local user can read the public key; a symlink attack targeting the private key is possible in misconfigured environments.

5. **signinURL-injection**: `api/client.go:stream()` extracts `signin_url` from server JSON responses without host pinning. A malicious server (or MITM) can inject an arbitrary URL that the CLI prints to the user, enabling phishing.

6. **tools-walker-nil-pipe**: `tools/template.go:findToolCallNode` dereferences `n.Pipe.Cmds` (line 52) without a nil check, coupling safety to an undocumented stdlib invariant that `IfNode.Pipe` is never nil when produced by the parser. A hand-constructed AST (e.g., from `Subtree`, `deleteNode`, or `thinking.InferTags`) can produce a nil Pipe, causing a nil-deref panic in the chat handler.

7. **cache-hit-no-rehash**: `x/imagegen/transfer/download.go:58` checks blob existence via `os.Stat` and skips download if size matches, without hashing the file. An attacker with write access to the blob store can pre-stage corrupted model weights that are accepted silently on the next pull.
