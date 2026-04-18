Slug: realm-http-downgrade
Reviewer: Cold verifier (adversarial)
Date: 2026-04-17

## Step 1 — Restated claim and sub-claims

Restatement: When Ollama's registry client receives an HTTP 401 on a pull/push, it
parses the `WWW-Authenticate: Bearer realm=...,service=...,scope=...` header and
calls `getAuthorizationToken`. The function verifies that `realm.Host == originalHost`
but not that `realm.Scheme == "https"`. An attacker who either controls the registry
or can inject into the 401 response can therefore set `realm="http://<originalHost>/..."`,
and Ollama will issue a plaintext HTTP GET to that realm carrying an ed25519
signature + public key in the `Authorization` header.

- Sub-claim A: Attacker can control the `WWW-Authenticate` header's realm value.
- Sub-claim B: Realm URL reaches `makeRequest` without scheme validation.
- Sub-claim C: The ed25519-signed `Authorization` header is transmitted in plaintext.

## Step 2 — Independent code trace

Entry: `server/images.go:890 makeRequestWithRetry` → on 401 calls
`parseRegistryChallenge(resp.Header.Get("www-authenticate"))` (line 906) →
`getAuthorizationToken(ctx, challenge, requestURL.Host)` (line 907). Note:
`requestURL.Host` is passed — this is host:port only, scheme is discarded at this
boundary.

`server/auth.go:28 registryChallenge.URL()` → `url.Parse(r.Realm)`. Go's `url.Parse`
accepts any scheme including `http`. No validation.

`server/auth.go:53 getAuthorizationToken`:
- Line 60: `if redirectURL.Host != originalHost { return ..., error }` — Host only.
- Line 65: builds `data = "GET,<redirectURL>,b64(hex(sha256('')))"`. `redirectURL.String()`
  includes the scheme, so the signed payload is bound to the HTTP URL.
- Line 68: `auth.Sign(ctx, data)` — reads `~/.ollama/id_ed25519`, returns
  `"<pubkey>:<b64sig>"`.
- Line 73: `headers.Add("Authorization", signature)`.
- Line 75: `makeRequest(ctx, "GET", redirectURL, headers, nil, &registryOptions{})`.

`server/images.go:951 makeRequest`:
- Line 952–954: only coerces scheme to `http` when `regOpts.Insecure == true`.
  Otherwise the redirectURL scheme is used verbatim. No enforcement that scheme
  is `https`.
- Line 956: `http.NewRequestWithContext` with the URL as-is.
- Line 992: `c.Do(req)` sends the request. No transport restriction.

No other control layer enforces scheme on this path.

## Step 3 — Protection surface search

| Layer | Control examined | Blocks? |
|-------|------------------|---------|
| Language | `net/http` — no default scheme policy | No |
| Framework | `http.Client` with only `CheckRedirect` set | No |
| Application | `errInsecureProtocol` at `images.go:534,616` — only in PushModel/PullModel, checks `n.ProtocolScheme` of the **model name**, not the realm URL | No |
| Application | `regOpts.Insecure` — only permits downgrade, never requires https | No |
| Test surface | `server/auth_test.go TestGetAuthorizationTokenRejectsCrossDomain` — asserts only `Host` inequality; no scheme coverage | No |
| Docs | `SECURITY.md` — not located as accepting this risk | No |

The only relevant commit `7601f0e9` (mentioned in the prior audit notes that I did not read during review; confirmed by `git log`) added the host check for CVE-2025-51471 but did not add scheme enforcement.

## Step 4 — Real-environment reproduction

Environment: ollama tree at commit 57653b8e (main). Go 1.26.1.

Approach: Wrote a Go test in `server/` that
1. Starts a plaintext HTTP server on 127.0.0.1:<port> with a `/token` handler
   that records the inbound `Authorization` header.
2. Builds `registryChallenge{Realm: "http://127.0.0.1:<port>/token", ...}` and
   calls `getAuthorizationToken(ctx, challenge, "127.0.0.1:<port>")`.

Result: Test PASSED. The function returned the attacker-supplied token with no
error; the plaintext HTTP endpoint received the full ed25519 Authorization
header:

```
=== RUN   TestRealmHTTPDowngrade
    realm_downgrade_test.go:89: PLAINTEXT CAPTURE: URL=/token?nonce=yXDkoYC3genX1C1IHkZ8UA&scope=repository%3Afoo%3Apull&service=127.0.0.1%3A60024&ts=1776413213
    realm_downgrade_test.go:90: PLAINTEXT CAPTURE: Authorization=AAAAC3NzaC1lZDI1NTE5AAAAIINo6MpG/eSbHzvXo84DJ9fbbYHahZtxFyO60ckVYeGQ:dueinsV5idHporbs5YX1v9TZIHStSNZ7SrF9+EMI5N6+F2aNGaRfCGVaddDlS4VAYQfSkn/72nSIxC2jXy6wBw==
--- PASS: TestRealmHTTPDowngrade (0.01s)
```

Evidence saved: `archon/real-env-evidence/realm-http-downgrade/test-output.txt`.
Test source was removed after the run (was not added to the repo).

PoC-Status: **executed**.

## Step 5 — Prosecution and defense briefs

### Prosecution

The code at `server/auth.go:60` implements only a host-equality check. An attacker
who either operates a registry with a TLS certificate for their host, or who can
manipulate the 401 response of a legitimate HTTPS registry (MITM with hostile CA
or cert compromise), can inject `realm="http://<same-host>/token"`. The parser in
`server/images.go:1018 parseRegistryChallenge` does not sanitize the realm.
`getAuthorizationToken` accepts the challenge because `Host` still matches
`originalHost` (scheme is not a component of `url.URL.Host`). `makeRequest`
dispatches the request using `redirectURL` verbatim.

Reproduction confirms the ed25519 `Authorization` header is transmitted in
cleartext. This exposes the user's public identity key (`~/.ollama/id_ed25519`
public half) and a valid nonce/timestamp/service/scope-bound signature on any
network segment between client and the realm endpoint. If the overall network
trust model assumes registry communication is always TLS-protected — which is
reasonable, given the default `https://` scheme in `types/model/name.go:42` and
the explicit `errInsecureProtocol` guard for the initial manifest request —
the scheme-downgrade path silently violates that assumption.

### Defense

Exploitability requires one of: (1) the user to trust an attacker-controlled
registry with a valid TLS cert, or (2) an attacker to defeat TLS on the
legitimate registry connection. In case (1), the attacker already receives the
Authorization header over their own TLS channel; forcing plaintext merely
duplicates the disclosure to passive observers. In case (2), the attacker has
already broken TLS and can read the cleartext anyway.

The leaked material is not directly replayable against the legitimate registry:
`server/auth.go:65` binds the signature to the full redirectURL string, which
includes `http://...`, so the captured signature cannot authenticate a request
whose URL is `https://...`. The signed token response body is attacker-supplied,
so returning a crafted token is equivalent to the attacker simply handing the
client a token — no cryptographic bypass is required.

The leaked public key is, by definition, public; it is the identity used with
ollama.com but exposing it is not a confidentiality breach per se. The
advisory-hunter notes indicate the related CVE-2025-51471 (cross-host realm leak)
was rated MEDIUM, not HIGH.

### Weighing

The prosecution correctly identifies a protocol-integrity violation: ed25519
signatures + identity key are sent in plaintext on a path the surrounding code
clearly intends to be TLS-only. The defense correctly narrows the practical
impact: signatures are URL-bound and the public key is not directly sensitive.
The bug is real but impact is less than "token theft or replay against the
true registry" as the finding's Impact section claims — the Impact overstates
replay feasibility since the signature is URL-bound.

## Step 6 — Severity challenge

Starting at MEDIUM:
- Remotely triggerable: requires attacker-controlled registry (user-initiated pull)
  or TLS MITM. Not a passive internet-wide vector.
- Trust boundary crossing: yes (TLS → plaintext).
- Preconditions: non-default (user must pull a model from attacker host, or
  TLS compromise exists).
- No RCE, no auth bypass, no mass data exfil.

Signals point to MEDIUM. The sibling CVE (CVE-2025-51471, same function, same
class of realm validation gap) was rated MEDIUM 6.9. Setting severity-final
to MEDIUM.

## Step 7 — Verdict

- Prosecution survives the defense on the narrow claim (plaintext transmission
  of signed headers does occur).
- Real-environment reproduction succeeded.

**Verdict: CONFIRMED** — but at lower severity than originally proposed and with
narrower impact than the draft's Impact section asserts.

Recommended fix: in `server/auth.go` after the host check, add
```go
if redirectURL.Scheme != "https" {
    return "", fmt.Errorf("realm scheme %q is not https", redirectURL.Scheme)
}
```
(gated by `regOpts.Insecure` if preserving that escape hatch is desired).
