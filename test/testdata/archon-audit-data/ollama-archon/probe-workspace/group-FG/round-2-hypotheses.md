# Round 2 Hypotheses — Contradiction Reasoner (TRIZ / Game-Theory / Invariant-Breaking)

## PH-09: cache-hit size-match bypass — pre-staged model weight substitution

**Method**: TRIZ (contradiction: the system "checks" presence but does not "verify" content)
**Target**: `x/imagegen/transfer/download.go:58` — blob cache hit check
**Attack input**: Attacker pre-stages a file at `<DestDir>/sha256-<legitimatedigest>` with the correct size but corrupted/attacker-chosen weight data, before an `ollama pull` runs
**Code path**:
  `download()` →
  `os.Stat(filepath.Join(opts.DestDir, digestToPath(b.Digest)))` →
  `fi.Size() == b.Size` — TRUE (attacker matched the size) →
  blob is accepted as "already downloaded", skipped entirely, never hashed →
  Model loads the attacker-controlled weights via the imagegen runner subprocess
**Sanitizers on path**: None. The stat-and-size check is the only gate. There is no `sha256` re-verification of pre-existing blobs in this code path.
**Security consequence**: An attacker with write access to `OLLAMA_MODELS/blobs/` (shared host, misconfigured mount, co-tenant container, backup restore) can substitute arbitrary model weights that are loaded into the MLX runtime. For image generation models this affects generated output; for LLM-class safetensors models this could influence inference behavior. The attack is persistent across pulls.
**Severity estimate**: HIGH
**Status**: VALIDATED — directly confirmed by code: no hash check in cache-hit branch

---

## PH-10: OLLAMA_MODELS env injection — redirect all model storage to attacker-controlled path

**Method**: Game-Theory (attacker controls environment)
**Target**: `envconfig/config.go:113` — `Models()`
**Attack input**: `OLLAMA_MODELS=/tmp/attacker` or `OLLAMA_MODELS=../../etc` set in the process environment before `ollama serve` starts
**Code path**:
  `envconfig.Models()` returns `/tmp/attacker` →
  All calls to `defaultBlobDir()`, `defaultManifestDir()`, `manifest.DefaultBlobDir()`, `manifest.DefaultManifestDir()` use this base →
  All blob reads, manifest reads, and blob writes target attacker-chosen location →
  An attacker who can control `OLLAMA_MODELS` AND has write access to that path can pre-stage manifests and blobs for PH-09 and PH-03
**Sanitizers on path**: None. `Var("OLLAMA_MODELS")` strips quotes and whitespace but does not validate the path.
**Security consequence**: In containerized deployments where `OLLAMA_MODELS` is set from user-supplied environment (e.g., a multi-tenant orchestrator, Kubernetes ConfigMap from user input), an attacker can redirect model storage to a shared or attacker-writable location. Combined with PH-09, this enables arbitrary weight substitution without filesystem write access to the default location.
**Severity estimate**: MEDIUM (requires environment control, which is elevated access but common in container environments)
**Status**: VALIDATED

---

## PH-11: SigninURL injection via malicious server — phishing / open redirect in CLI

**Method**: Contradiction (system trusts server response without host pinning)
**Target**: `api/client.go:222-243` — `stream()` SigninURL extraction
**Attack input**: A server (attacker-controlled, or MITM on an insecure local connection) returns a streaming response with `{"signin_url": "https://evil.com/steal?token=..."}` in a 401 response
**Code path**:
  `client.stream()` reads each line →
  `json.Unmarshal(bts, &errorResponse)` populates `errorResponse.SigninURL` →
  `return AuthorizationError{..., SigninURL: errorResponse.SigninURL}` →
  CLI's `RunHandler` / `SigninHandler` prints `sErr.SigninURL` verbatim via `fmt.Printf(ConnectInstructions, sErr.SigninURL)` →
  User clicks or pastes the URL, navigating to the attacker's site
**Sanitizers on path**: None. `api/client.go:checkError` swallows the json.Unmarshal error when parsing 401 non-streaming responses, accepting any JSON body. No scheme or host validation on `SigninURL` before display.
**Security consequence**: Phishing attack: ollama CLI displays an attacker-controlled URL as if it were the official ollama.com signin URL. In a compromised local server or MITM scenario, this can harvest ollama credentials or browser sessions.
**Severity estimate**: MEDIUM
**Status**: VALIDATED — confirmed by code and KB bypass analysis H6/M14 for 64883e3c

---

## PH-12: mlx runner subprocess — model name passed to exec.Command unvalidated

**Method**: TRIZ (contradiction: process isolation assumed, but model name can be a path)
**Target**: `x/imagegen/server.go:116` — `exec.Command(exe, "runner", "--imagegen-engine", "--model", s.modelName, ...)`
**Attack input**: `s.modelName` = `../../../malicious_model` or a model name resolving to a path outside the blobs directory
**Code path**:
  `Server.Load()` constructs `exec.Command` with `s.modelName` directly as the `--model` flag value →
  The mlx runner subprocess receives this path →
  If the runner loads model files from this path directly (not via manifest+blob abstraction), arbitrary file read by the subprocess is possible
**Sanitizers on path**: `filepath.EvalSymlinks(exe)` is applied to the EXECUTABLE path but NOT to `s.modelName`. The individual args are safe from shell injection (no shell involved), but path traversal within the model name argument is not checked.
**Security consequence**: Subprocess reads model weights from an attacker-chosen path. Lower severity than PH-01/PH-02 because this requires the model name to already have been accepted by the scheduler (which may do its own validation). However, the exec boundary does not add a validation layer.
**Severity estimate**: MEDIUM
**Status**: NEEDS-DEEPER — requires tracing how the mlx runner subprocess handles the --model argument and whether model.ParseName validation precedes this call

---

## PH-13: x/imagegen/transfer upload path traversal — digest in upload source path

**Method**: Contradiction (upload mirrors download; if download is vulnerable, upload is likely too)
**Target**: `x/imagegen/transfer/upload.go:181` — `os.Open(filepath.Join(u.srcDir, digestToPath(blob.Digest)))`
**Attack input**: An upload initiated with blobs whose `Digest` field contains `../../../etc/shadow`
**Code path**:
  `Upload(ctx, UploadOptions{Blobs: []Blob{{Digest: "sha256:../../../etc/shadow", Size: ...}}, SrcDir: blobDir})` →
  `digestToPath("sha256:../../../etc/shadow")` = `"sha256-../../../etc/shadow"` →
  `filepath.Join(srcDir, "sha256-../../../etc/shadow")` escapes srcDir →
  `os.Open(path)` reads the arbitrary file →
  File contents are uploaded to the registry
**Sanitizers on path**: None in the upload path. Same `digestToPath` function, same absence of validation.
**Security consequence**: Arbitrary file read and exfiltration: the ollama push operation uploads the contents of any file readable by the ollama user to an attacker-controlled (or legitimate) registry. This includes private keys, shadow files, config files, etc.
**Severity estimate**: HIGH
**Status**: VALIDATED — direct code confirmation; upload.go:181 uses digestToPath identically to download.go

---

## PH-14: harmony parser — large input DoS via unbounded parse state

**Method**: TRIZ (resource exhaustion)
**Target**: `harmony/harmonyparser.go` — parser entry point
**Attack input**: Extremely long or deeply nested harmony syntax input provided as model response
**Code path**: (Requires reading harmonyparser.go — not yet done)
**Status**: NEEDS-DEEPER — harmony parser not yet read; deferring to round 3

---

## PH-15: sample/samplers.go — integer underflow in temperature/top-p sampling

**Method**: Contradiction (numeric boundary)
**Target**: `sample/samplers.go` — temperature or top-p sampler
**Attack input**: `temperature=0.0` or `top_p=0.0` or negative values passed from API
**Code path**: (Requires reading samplers.go)
**Status**: NEEDS-DEEPER — deferring to round 3

---

## PH-16: x/create/create.go ShouldQuantize — tensor name substring injection affecting quantization decision

**Method**: Game-Theory (attacker controls tensor names in safetensors file)
**Target**: `x/create/create.go:243` — `ShouldQuantize(name, component)`
**Attack input**: A safetensors file where tensor names are crafted to contain or not contain target substrings (e.g., a weight tensor named `model.layers.0.norm.weight.weight` to look like a norm and bypass quantization)
**Code path**:
  `CreateSafetensorsModel` / `CreateImageGenModel` iterates tensors →
  `ShouldQuantize(tensorName, component)` applies substring checks →
  A tensor containing "norm" or "embed" in its name is skipped for quantization regardless of its actual role →
  Attacker-supplied safetensors can arrange that sensitive tensors are quantized or not quantized contrary to policy
**Security consequence**: Quantization policy bypass — model weights that should be quantized are stored at full precision (wasting space) or vice versa (degrading accuracy). Not a direct security vulnerability but represents a trust boundary: the model creator can manipulate the quantization behavior of the importer.
**Severity estimate**: LOW (policy bypass, no direct security impact)
**Status**: NEEDS-DEEPER — low priority

---

## PH-17: x/create resolveManifestPath + loadManifest — arbitrary JSON read from the manifest dir (second copy of PH-02 in create package)

**Method**: Contradiction (two independent copies of vulnerable code)
**Target**: `x/create/create.go:52-75` — local `resolveManifestPath()` + `loadManifest()`
**Attack input**: Calls to `IsSafetensorsModel("../../etc/hosts")`, `IsImageGenModel("../../etc/hosts")`, `IsSafetensorsLLMModel("../../etc/hosts")`
**Code path**:
  `loadModelConfig("../../etc/hosts")` →
  `loadManifest("../../etc/hosts")` →
  `resolveManifestPath("../../etc/hosts")` = `filepath.Join(manifestDir, "registry.ollama.ai", "library", "../../etc", "hosts")` = `manifestDir/../etc/hosts` →
  `os.ReadFile(manifestPath)` →
  Result: `json.Unmarshal` fails silently or succeeds if the file is valid JSON
**Sanitizers on path**: None in the x/create copy.
**Security consequence**: The three public `IsSafetensorsModel`, `IsImageGenModel`, `IsSafetensorsLLMModel` functions can be called with arbitrary strings (e.g., from an HTTP request that includes a model name in the experimental create path). This enables arbitrary file reads from the manifest directory's parent hierarchy.
**Severity estimate**: HIGH (same class as PH-02, different call site)
**Status**: VALIDATED
