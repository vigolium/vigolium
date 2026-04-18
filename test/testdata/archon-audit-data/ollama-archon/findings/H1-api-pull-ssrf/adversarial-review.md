# Adversarial cold review: p8-002-api-pull-ssrf

## Step 1 — Restated claim

The legacy `POST /api/pull` handler accepts a JSON body containing a `name`
and an `insecure` boolean. The `name` is parsed into a `model.Name` where
the `Host` component may be any string of alphanumerics plus `.`, `-`, `_`,
`:` (including IP literals and link-local addresses). The server then issues
an outbound `GET http://<Host>/v2/<namespace>/<model>/manifests/<tag>` to
that attacker-chosen host. With `insecure=true`, the HTTPS-only guard is
bypassed and the scheme is forced to HTTP. Error responses from the target
(status >= 400) include the response body verbatim in the error string,
which is wrapped again by `PullModel` and ultimately serialized to the
HTTP caller via `ch <- gin.H{"error": err.Error()}`.

### Sub-claims

- A: Unauthenticated remote caller controls `name` (host component) and
  `insecure` flag on `/api/pull`.
- B: The host component traverses name parsing and reaches the HTTP client
  without any outbound allowlist, private-IP rejection, or IMDS blocker.
- C: The response body of the SSRF target is reflected back to the caller
  through the error propagation chain.

All three sub-claims are coherent.

## Step 2 — Independent code-path trace

Starting point: `server/routes.go:1689` registers `r.POST("/api/pull", s.PullHandler)`.

- `PullHandler` (`server/routes.go:914-970`) binds JSON into
  `api.PullRequest`, calls `parseNormalizePullModelRef` on the `Model`/`Name`
  field, then `getExistingName`, then spawns a goroutine that calls
  `PullModel(ctx, name.DisplayShortest(), regOpts, fn)` with
  `regOpts.Insecure = req.Insecure`. No authentication gate.
- `parseNormalizePullModelRef` (`server/model_resolver.go:57`) passes through
  to `modelref.NormalizePullName` (`internal/modelref/modelref.go:69`) and
  `model.ParseName`. Neither applies a host allowlist, IP filter, or IMDS
  guard.
- `model.ParseName` (`types/model/name.go:140`) -> `ParseNameBare` splits
  on `:` (tag), `/` (namespace, model), then treats the remainder as host
  (optionally with `scheme://` prefix). Validation is `isValidPart(kindHost,
  s)` at `types/model/name.go:344-372`. That function permits digits, `.`,
  `-`, `_`, `:` for `kindHost`. No allowlist, no private-IP guard, no IMDS
  blocker. Confirmed empirically: `model.ParseName("169.254.169.254/ns/m:t")`
  returns valid with `Host="169.254.169.254"`.
- `PullModel` (`server/images.go:596-708`): at line 615 enforces
  `http` scheme only when `!regOpts.Insecure`. With `Insecure=true`, an
  explicit `http://` scheme is permitted; with no scheme, the default is
  `https` so this guard is trivially satisfied.
- `pullModelManifest` (`server/images.go:853-875`): builds
  `n.BaseURL().JoinPath("v2", n.DisplayNamespaceModel(), "manifests", n.Tag)`.
  `BaseURL()` is `{Scheme: n.ProtocolScheme, Host: n.Host}`.
- `makeRequest` (`server/images.go:951-993`): if scheme is not `http` and
  `regOpts.Insecure`, forcibly downgrades to `http`. Issues the request.
  No host filtering.
- `makeRequestWithRetry` (`server/images.go:890-934`): on status >= 400 it
  reads the response body and returns `fmt.Errorf("%d: %s", resp.StatusCode,
  responseBody)`. That error flows up to `PullModel:622`
  `return fmt.Errorf("pull model manifest: %s", err)` and then to
  `PullHandler:960` `ch <- gin.H{"error": err.Error()}`.

No validation or sanitization steps of the destination exist on this path.

## Step 3 — Protection surface search

| Layer | Found | Blocks attack? |
|-------|-------|----------------|
| Language (Go) | `net/http` client uses system resolver | No — IMDS/private IPs resolvable |
| Framework (gin) | `allowedHostsMiddleware` (routes.go:1608) restricts INBOUND Host header only | No — does not affect outbound |
| Name parser | `isValidPart(kindHost)` (name.go:344) allows IP literals and `:` port suffix | No — explicitly permits target IPs |
| Scheme guard | `if n.ProtocolScheme == "http" && !regOpts.Insecure` (images.go:615) | No — bypassed by `insecure:true` |
| Outbound dialer | Standard `http.Client`, no DialContext override in production | No — no private-IP rejection |
| Redirect policy | `regOpts.CheckRedirect` is nil for pulls unless download.go path triggers | No |
| Authentication | `OLLAMA_AUTH` only affects client-side signing; no server-side auth gate on `/api/pull` | No — attacker does not need auth |
| Documentation | Not inspected in depth; finding draft asserts no documented acceptance | N/A |

No layer blocks the attack. `allowedHostsMiddleware` is the only superficially
similar control and it only scopes inbound Host headers to a loopback-or-
allowlist set when binding to loopback — completely unrelated to outbound
destinations.

## Step 4 — Real-environment reproduction

Environment: in-tree Go test against main (commit 57653b8e, clean). Go 1.26.1
darwin/arm64. The `Ollama` daemon's full service binary is expensive to boot
because of llama.cpp linkage, so I instead exercised the exact vulnerable
function (`pullModelManifest`, the internal API called by the goroutine
in `PullHandler`) directly with the same `registryOptions` shape the handler
populates from user input.

Test file (temporary, since removed): `server/ssrf_adversarial_test.go`.
Command: `go test -vet=off ./server/ -run TestSSRFAdversarial -v`.

Result: PASS. Logged:
- `model.ParseName("127.0.0.1:<port>/ns/model:tag")` returns valid.
- The listener received `GET /v2/ns/model/manifests/tag`.
- The listener's 500 body `{"AccessKeyId":"AKIA_STOLEN",...}` was returned
  to the caller as
  `pull model manifest: 500: {"AccessKeyId":"AKIA_STOLEN","SecretAccessKey":"STOLEN_SECRET"}`.

Evidence: `archon/real-env-evidence/api-pull-ssrf/repro-output.txt`.

Important observation not captured by the finding draft: the raw curl PoC
in the draft (`"169.254.169.254/latest/meta-data/iam/security-credentials/
default:x"`) does NOT parse to a valid `model.Name` — the slashes after
the IP are absorbed into the host part which then fails `isValidPart`
because `/` is not in the host alphabet. The attacker is constrained to
the 3-part form `HOST/NS/MODEL:TAG` and the outbound path is always
`/v2/{ns}/{model}/manifests/{tag}`. IMDSv1 AWS credential theft via the
standard `/latest/meta-data/...` URL path is therefore NOT directly
achievable without DNS/redirect tricks or a target that yields secrets on
the fixed `/v2/.../manifests/...` path (internal docker-distribution
registries trivially qualify).

This constraint reduces, but does not eliminate, exploitability. Response-
body leakage and internal-service probing remain fully demonstrated.

## Step 5 — Briefs

### Prosecution brief

The vulnerable path is undefended end-to-end. An unauthenticated remote
caller (default `OLLAMA_HOST` is loopback, but containerized and remote-dev
deployments commonly expose `0.0.0.0:11434`; and for internal attackers
or post-CSRF-like contexts via same-origin inbound Host allow-list abuse
the loopback binding is also reachable) can submit
`POST /api/pull {"name":"169.254.169.254/ns/m:t","insecure":true}`.

`isValidPart(kindHost)` at `types/model/name.go:344-372` explicitly permits
numeric + `.` + `:` tokens, including AWS IMDS (`169.254.169.254`), Azure
IMDS (`169.254.169.254` with `Metadata: true` header - not sent by
ollama, so some IMDSv1/Azure variants WILL respond regardless of headers),
GCE metadata (`metadata.google.internal` or `169.254.169.254`), and any
private subnet endpoint.

`server/images.go:615` is the sole scheme guard and is silenced by
`regOpts.Insecure=true`. `server/images.go:952-954` then forces the scheme
to `http` unconditionally when Insecure is set. The request reaches the
chosen host. On any status >= 400, `server/images.go:921-927` returns
`fmt.Errorf("%d: %s", resp.StatusCode, responseBody)`, surfacing the raw
body. That error is wrapped at `server/images.go:622-623` and streamed to
the caller at `server/routes.go:960`.

Reproduction confirmed in Step 4.

### Defense brief

The draft's illustrative curl PoC does not parse — `isValidPart(kindHost)`
rejects slashes in the host component, so the attacker cannot freely pick
the URL path. The outbound path is always `/v2/{ns}/{model}/manifests/{tag}`,
which coincides with docker-distribution v2 but not with AWS/GCP/Azure IMDS
paths. Direct IMDSv1 credential retrieval as stated in Impact is therefore
not a straight-forward PoC. Additionally, `insecure:true` is required for
the HTTP downgrade needed to reach IMDSv1 (which is HTTP-only).

Authentication on `/api/pull` is absent by default, which the defense does
not dispute. However, the default bind is `127.0.0.1:11434`, so the attack
requires local-host access OR a misconfigured `OLLAMA_HOST=0.0.0.0`, which
the draft acknowledges. This limits remote-unauthenticated reachability to
misconfigured deployments.

Finally, the `allowedHostsMiddleware` indirectly constrains attack surface
via DNS rebinding by rejecting inbound requests whose `Host` header is not
loopback/private/allowlisted. Combined with CORS, this narrows the browser-
driven attack pathway for loopback-only deployments.

### Balance

The defense correctly narrows the impact surface (path-constrained, cannot
directly read IMDSv1 meta-data URL, requires insecure flag) but does not
identify a protection that BLOCKS outbound SSRF to arbitrary internal hosts.
Response-body reflection of internal services is reproduced; that alone is
a meaningful SSRF.

## Step 6 — Severity challenge

Starting at MEDIUM.

Upgrade factors:
- Remotely triggerable (on 0.0.0.0 deployments) without authentication: YES
- Trust-boundary crossing (external caller reaches internal/loopback/cloud
  metadata services): YES
- No significant preconditions (just `insecure:true` and a valid 3-part
  name): YES

Downgrade factors:
- URL path is fixed at `/v2/.../manifests/...`, so direct IMDSv1 credential
  exfil is not trivially achievable without DNS/redirect gymnastics.
- Default bind is loopback; remote-unauthenticated reachability requires
  operator misconfiguration (`OLLAMA_HOST=0.0.0.0`, which is common in
  containers).

Net: HIGH is justified. Raising to CRITICAL would require a credible,
unconditional RCE/creds-exfil chain from this alone. The finding gives
strong SSRF with body-reflection but the fixed URL-path constraint plus
need for the `insecure` flag stops short of CRITICAL on its own.

Severity-Final: HIGH (matches original).

## Step 7 — Verdict

CONFIRMED.

- Prosecution survived: no protection found that blocks outbound SSRF to
  attacker-chosen private/loopback/link-local hosts.
- Reproduction executed: outbound request reached attacker host; response
  body reflected back through the error channel.

Severity-Final: HIGH.
PoC-Status: executed.
