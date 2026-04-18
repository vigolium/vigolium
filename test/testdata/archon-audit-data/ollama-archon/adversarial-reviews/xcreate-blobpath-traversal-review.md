Review-Target: archon/findings-draft/p8-007-xcreate-blobpath-traversal.md
Reviewer-Role: Cold adversarial verification (no chamber context)

# Step 1 — Restated Claim and Sub-Claims

Restated: The finding alleges that in `x/create/create.go`, two helper
functions, `loadModelConfig` and `GetModelArchitecture`, build a blob
filesystem path by taking a digest string from a locally-stored manifest
(`manifest.Config.Digest` and `layer.Digest` respectively), applying only
`strings.Replace(digest, ":", "-", 1)`, and passing that result straight into
`filepath.Join(defaultBlobDir(), blobName)` and `os.ReadFile`, thus allowing an
attacker-controlled manifest containing a traversal digest (e.g.
`sha256:../../../etc/passwd`) to cause an arbitrary-file read as the ollama
user when downstream dispatch code calls `IsSafetensorsModel`,
`IsSafetensorsLLMModel`, `IsImageGenModel`, or `GetModelArchitecture`.

Sub-claims:
- Sub-claim A: An attacker can persuade the victim to obtain a manifest that
  carries a traversal `Digest` string in either the config layer or a
  layer named `config.json`.
- Sub-claim B: The path reaches `loadModelConfig` or `GetModelArchitecture`
  through production code automatically triggered by a typical operation
  such as `ollama run` or `ollama show`.
- Sub-claim C: The raw `strings.Replace(digest, ":", "-", 1)` + `filepath.Join`
  + `os.ReadFile` pattern produces a read of the attacker-pointed file and
  that read is observable (content returned to attacker or executed).

Sub-claim A is, in principle, plausible; the `loadManifest` function reads
from disk with only JSON unmarshal. Sub-claim C is mechanically true in the
code shown — `filepath.Join` does not clean a leading `../` that precedes
`defaultBlobDir()` completely but `strings.Replace(..., ":", "-", 1)` does
not sanitize `..` or `/`, and there is no `filepath.IsLocal`. The entire
exploit hinges on Sub-claim B — is there any production caller?

# Step 2 — Independent Code Path Trace

File: `x/create/create.go` (read end-to-end, not just the cited lines).

Sinks, as claimed, exist exactly as described:
- `loadModelConfig` (lines 95-116): reads `manifest.Config.Digest`, applies
  `strings.Replace(..., ":", "-", 1)`, joins with `defaultBlobDir()`, passes
  to `os.ReadFile`, then `json.Unmarshal` into `ModelConfig`.
- `GetModelArchitecture` (lines 148-185): iterates `manifest.Layers`, for
  entries with `layer.Name == "config.json"` and `layer.MediaType ==
  "application/vnd.ollama.image.json"`, same pattern.

`loadModelConfig` is a package-private helper. It is invoked by three
exported helpers:
- `IsSafetensorsModel` (line 120)
- `IsSafetensorsLLMModel` (line 130)
- `IsImageGenModel` (line 140)

`GetModelArchitecture` is directly exported (line 149).

Now — who calls these four exported helpers? Independent search (excluding
the finding-draft directory and archon workspace) returns:

```
./x/create/create.go:120:func IsSafetensorsModel(...)          # definition only
./x/create/create.go:130:func IsSafetensorsLLMModel(...)       # definition only
./x/create/create.go:140:func IsImageGenModel(...)             # definition only
./x/create/create.go:149:func GetModelArchitecture(...)        # definition only
```

Zero call sites elsewhere in the repo. I searched:
- `cmd/` (includes `ollama run`, `ollama show` handlers) — no matches.
- `server/` (HTTP handler routing, create.go, routes.go) — no matches.
- `x/create/client/` — only uses `IsSafetensorsModelDir` (a totally different
  function that takes a directory path argument, not a model name, and does
  not invoke `loadModelConfig` at all).
- All other packages under the repo, including `x/mlxrunner`, `llm`,
  `runner`, `ml`, `discover`, `template`, `tools`, etc.

No `go:linkname` directives exist in the repo, and these exported Go
functions are not referenced via any string-based dispatch, reflection, or
build-tag-gated file.

The exported helpers are essentially dead code.

# Step 3 — Protection Surface Search

Because the relevant code path is never entered, formal protections
(allowlist regex, `filepath.IsLocal`, `manifest.BlobsPath`) are not applied
to the `loadModelConfig` / `GetModelArchitecture` sinks.

Counter-protection identified: the defense does not rely on input validation
at the sink, it relies on **unreachability of the sink**. The vulnerable
code is not invoked by any caller in `cmd`, `server`, or anywhere else.

For completeness, `manifest.BlobsPath` (manifest/paths.go:40) does enforce
`^sha256[:-][0-9a-fA-F]{64}$` and is the correct API the code should have
used; but `loadModelConfig`/`GetModelArchitecture` re-implement the path
construction without calling it. That misimplementation would be a real bug
if the functions were wired into the request pipeline — but they are not.

# Step 4 — Real-Environment Reproduction Attempt

The draft's reproduction step 2 is:

> Invoke any dispatch path that calls `IsSafetensorsModel(modelName)` or
> `GetModelArchitecture(modelName)` — common during `ollama run`,
> `ollama show`, or template-aware endpoints.

Attempt 1 — Static resolution: Search for any code path in `cmd/cmd.go`
that invokes these helpers during `ollama run` / `ollama show`. Result:
no reference to `IsSafetensors*`, `IsImageGen*`, or `GetModelArchitecture`
in the entire `cmd/` subtree. Reproduction is impossible because the
entry points identified in the draft do not call the helpers.

Attempt 2 — Check HTTP server routes: Searched `server/routes.go` and
`server/create.go` for the same identifiers. No hits. The server never
invokes these helpers.

Attempt 3 — Check plugin/template/renderer paths: Searched the entire
repository for `\.IsSafetensorsModel\b`, `\.IsImageGenModel\b`,
`\.GetModelArchitecture\b`, `\.IsSafetensorsLLMModel\b`. No matches
anywhere outside the definition file and a handful of archon meta-analysis
notes.

All three reproduction attempts fail because there is no reachable path
from any external input (HTTP request, CLI command, subprocess) to the
vulnerable sink. The reproduction is blocked at the first step: the
helpers that would use a traversal digest are never executed.

Evidence stored in this review; no runtime environment needed because
static reachability refutation is decisive for this finding.

PoC-Status: blocked (unreachable dead code — cannot instantiate exploit).

# Step 5 — Prosecution Brief

The sinks are mechanically unsafe. The raw digest from a locally-stored
manifest is not validated: `strings.Replace(digest, ":", "-", 1)` only
replaces one `:` with `-` and will leave `../` sequences intact. For
instance, `sha256:../../../etc/passwd` becomes `sha256-../../../etc/passwd`,
and `filepath.Join(defaultBlobDir(), "sha256-../../../etc/passwd")` does
not strip path traversal beyond what `filepath.Clean` performs inside
`Join` — which would collapse `blobs/sha256-../../../etc/passwd` into
`../etc/passwd` relative to the models directory. `os.ReadFile` then
reads the attacker-pointed file, and the contents flow into
`json.Unmarshal`; on parse failure, the bytes are returned as part of
the error via `fmt.Errorf`'s `%w` wrapper chain in typical Go usage.

The correct API — `manifest.BlobsPath` — validates the digest with a
strict regex; the sink code does not call it. The finding is, in
isolation, a clear exemplar of path traversal via digest reuse.

# Step 6 — Defense Brief

The code in question is exported Go symbols with **no callers in the
repository**. No file under `cmd/`, `server/`, `x/create/client/`,
`x/mlxrunner/`, `llm/`, `runner/`, `template/`, or anywhere else
invokes `IsSafetensorsModel`, `IsSafetensorsLLMModel`, `IsImageGenModel`,
or `GetModelArchitecture`. The `client` package that does import
`x/create` uses only `IsSafetensorsModelDir` / `IsTensorModelDir` /
`CreateSafetensorsModel` / `CreateImageGenModel` — none of which exercise
the unsafe digest-to-path helpers.

The draft's own reproduction narrative assumes that "dispatch" triggered
by `ollama run`, `ollama show`, or "template-aware endpoints" reaches
these helpers. Cold verification shows this chain does not exist.
There is no routing layer, no model-type dispatch, no
capability-detection code path in production that calls these
helpers. They are exported, but effectively dead code.

Without a reachable path, sub-claim B fails. An unreachable unsafe
function is an internal hygiene issue, not an exploitable vulnerability.
A competent fix (switch to `manifest.BlobsPath`) is still warranted for
code quality, but it is not a security finding under a normal threat
model.

The draft's severity (HIGH) presupposes "common" triggering during
routine operations; the defense disproves that premise.

# Step 7 — Severity Challenge

Starting at MEDIUM per the process rules.
- Remotely triggerable: No — no production caller.
- Trust boundary crossing: Theoretical only — the trust boundary is
  never crossed in any real dispatch path.
- Significant preconditions: Attacker must (a) get the victim to store
  a malicious manifest on disk, and (b) get the victim to invoke a
  caller of `IsSafetensorsModel`/`GetModelArchitecture`. The latter
  does not exist in production code.

Downgrade signals present:
- Theoretical only (no reproduction possible).
- Requires dead-code to be revived, i.e. non-default (non-existent)
  configuration.

Challenged severity: LOW at most; effectively INFORMATIONAL as a code
hygiene recommendation.

# Step 8 — Verdict

DISPROVED.

The defense identifies a decisive blocker: the exported helpers that
would pass unsanitized digest strings into `os.ReadFile` have no callers
anywhere in the codebase. Sub-claim B of the finding (reachability from
a production dispatch path) fails on cold inspection. All three
reproduction attempts were blocked by this unreachability, with no
environment-level workaround available — the code path simply does not
exist.

The unsafe pattern at `x/create/create.go:102` and `:158` remains a
legitimate code-quality issue (the helpers should use
`manifest.BlobsPath`), but it is not an exploitable vulnerability in
the current tree.

Adversarial-Verdict: DISPROVED
Adversarial-Rationale: The four helpers that would reach the unsafe
`strings.Replace` + `filepath.Join` + `os.ReadFile` sinks
(`IsSafetensorsModel`, `IsSafetensorsLLMModel`, `IsImageGenModel`,
`GetModelArchitecture`) have zero call sites in the entire
repository outside of `create.go` itself — cmd/, server/, and
x/create/client/ all do not invoke them, so the "dispatch path"
described in the finding does not exist and the traversal cannot be
reached by any attacker input.
Severity-Final: LOW (informational code-hygiene)
PoC-Status: blocked
