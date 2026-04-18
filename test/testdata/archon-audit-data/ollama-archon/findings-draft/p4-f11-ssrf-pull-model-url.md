# p4-f11: SSRF via /api/pull — User-Controlled Model Registry Host

**Severity**: MEDIUM
**CWE**: CWE-918 (Server-Side Request Forgery)
**DFD Slice**: DFD-1 (model name -> registry URL)
**CVE**: CVE-2026-5530

## Location

- `server/routes.go:914-962`: `PullHandler` — model name from request body
- `types/model/name.go:317-321`: `BaseURL()` — constructs registry URL from parsed Name.Host
- `types/model/name.go:146-176`: `ParseNameBare()` — accepts arbitrary host part

## Description

The `/api/pull` endpoint accepts a `model` field in the request body (no authentication). The model name is parsed with `ParseNameBare()`, which extracts the host portion with only a length check (`len(s) >= 1 && len(s) <= 350`). No validation that the host is an allowed registry.

`Name.BaseURL()` constructs:
```go
return &url.URL{
    Scheme: n.ProtocolScheme,
    Host:   n.Host,
}
```

This URL is used for all registry operations (manifest fetch, blob downloads). An attacker can specify:
- `http://169.254.169.254/latest/meta-data` — AWS IMDS
- `http://10.0.0.1/internal-api` — internal services
- Any host reachable from the server

The `registryOptions.Insecure` field from the request body can also force HTTP.

## Attack

```bash
curl -X POST http://localhost:11434/api/pull \
  -d '{"model":"169.254.169.254/latest/meta-data:tag"}'
```
Server makes outbound request to AWS IMDS, response visible via error messages or timing.

## Evidence

- `types/model/name.go:333-336` — host length check only, no allowlist
- `types/model/name.go:317-321` — `BaseURL()` directly uses Name.Host
- `server/images.go:717` — `base := n.BaseURL()` used for registry requests

---

## Phase 7 Enrichment Verdict

**Classification**: SECURITY — likely security

**Attacker Control**: Any client with HTTP access to `POST /api/pull` can specify an arbitrary host in the `model` field. No authentication is required in default Ollama configuration. The host parsing in `ParseNameBare` does length-check only; arbitrary IP addresses and hostnames are accepted.

**Runtime**: `ollama serve` Go process — the SSRF occurs on the server side during `PullModel()` execution, making outbound connections from the server's network context.

**Trust Boundary Crossed**: Client-to-server trust boundary AND server's network boundary. A client that can only reach the Ollama API (e.g., localhost) can use Ollama as a proxy to reach hosts that the client cannot directly access — internal network services, cloud metadata endpoints, etc.

**Effect**: 
- In cloud deployments: AWS IMDS credential theft (`169.254.169.254`), GCP metadata API access (`metadata.google.internal`), Azure IMDS (`169.254.169.254`). These endpoints return instance credentials that grant cloud-level access.
- In enterprise deployments: internal service scanning, port probing, reaching services protected by network segmentation.
- Error message oracle: even if the response body is not returned to the attacker, timing differences and error messages can confirm host reachability.

**CodeQL Reachability**: No pre-computed slice. Manual trace: `POST /api/pull` -> `PullHandler` -> `parseNormalizePullModelRef(req.Model)` -> `model.ParseName(normalizedName)` -> `ParseNameBare` -> `Name.Host = host` (arbitrary) -> `PullModel()` -> `pullWithTransfer()` -> `server/images.go:717: base := n.BaseURL()` -> `base.Host` used for HTTP request. The `parseNormalizePullModelRef` wrapper adds cloud normalization but does NOT add host validation. Confirmed reachable.

**New Registry Path**: Note that `/api/pull` is also handled by `registry.Local.handlePull` (p4-f08) when the registry client is active. The SSRF applies to both code paths — the host validation gap exists in the model name parsing layer, which is shared.

**KB Cross-Reference**: CVE-2026-5530 — "SSRF via /api/pull model URL" — direct match, rated HIGH. The KB identifies this as an active CVE. The finding is currently classified MEDIUM, but the CVE advisory rates it HIGH. Severity alignment note: this finding should potentially be escalated to HIGH given the CVE rating and cloud metadata credential theft impact.

**Severity Re-Assessment**: The original MEDIUM classification was conservative. Given:
1. Cloud metadata credential theft is a HIGH-impact outcome (full cloud account takeover in worst case)
2. Zero authentication required
3. Direct CVE match (CVE-2026-5530)
Recommend escalating to HIGH in Phase 8.

**Exploit Prerequisites**:
- HTTP access to `POST /api/pull` (localhost by default; any network if OLLAMA_HOST=0.0.0.0)
- No authentication required
- Server must be on a network where the target internal host is reachable (trivially true for cloud IMDS)

**Verdict**: KEEP — MEDIUM security finding (recommend Phase 8 escalation to HIGH based on CVE rating and cloud metadata impact). Fix: implement a registry allowlist (default: `registry.ollama.ai` only) configurable via `OLLAMA_REGISTRIES`. Reject requests where `Name.Host` is not in the allowlist. Block RFC-1918 and link-local addresses in `BaseURL()`.
