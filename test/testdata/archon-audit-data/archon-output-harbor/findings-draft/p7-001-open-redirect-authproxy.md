# Phase 7 Enriched Finding: P7-001

## Finding Details

| Field | Value |
|-------|-------|
| **Finding ID** | P7-001 |
| **Source SAST ID** | SAST-001 |
| **Tool** | CodeQL (go/unvalidated-url-redirection) |
| **Title** | Open Redirect via Unvalidated postURI in Auth-Proxy Controller |
| **Severity** | HIGH |
| **Confidence** | HIGH |
| **CWE** | CWE-601 (URL Redirection to Untrusted Site) |

## Vulnerability Classification

**Type**: Security (exploitable vulnerability)

## PoC Status

PoC-Status: theoretical
PoC-Block-Reason: Full Harbor auth-proxy deployment not available. Redirect behavior confirmed via static source analysis showing unvalidated postURI parameter passed directly to Ctx.Redirect() at authproxy_redirect.go:77 with no IsLocalPath() check, unlike the OIDC controller.

## Reachability Assessment

**Status**: CONFIRMED REACHABLE

**Evidence**:
- CodeQL: `go/unvalidated-url-redirection` rule confirmed at `authproxy_redirect.go:77`
- Call Graph Slice: `CFD-1` in `call-graph-slices.json` maps HTTP GET parameter to redirect sink
- Trust Boundary: TB-1 (Internet -> Nginx -> Core API)

## Attacker-Controlled Input Path

**Entry Point**: HTTP GET query parameter
```
GET /c/authproxy/redirect?token=<valid-token>&postURI=<attacker-url>
```

**Attack Flow**:
1. Attacker crafts URL with malicious `postURI` parameter
2. User (authenticated via auth-proxy) clicks link
3. Token is verified (line 61: `helper.VerifyToken()`)
4. User is authenticated (line 67: `helper.PostAuthenticate()`)
5. postURI parameter is read without validation (line 73)
6. Unvalidated URI passed to redirect (line 77)
7. Victim redirected to attacker-controlled URL

## Code Location & Snippet

**File**: `src/core/controllers/authproxy_redirect.go`
**Lines**: 73-77
**Function**: `AuthProxyController.HandleRedirect()`

```go
// Line 73: Read postURI query parameter
uri := apc.Ctx.Request.URL.Query().Get(postURIKey)
if uri == "" {
    uri = "/"
}
// Line 77: Redirect without validation
apc.Ctx.Redirect(http.StatusMovedPermanently, uri)
```

## Vulnerability Analysis

### Trust Boundary Crossing

- **Boundary**: TB-1 (External internet traffic -> Core API)
- **Effect**: Cross-user (victim user redirected to attacker URL)
- **Authentication Context**: User is authenticated but redirect target is unvalidated

### Comparison with Secure Pattern

The OIDC controller (`src/core/controllers/oidc.go`) implements the correct pattern:
```go
// Secure pattern: validation before redirect
if !utils.IsLocalPath(redirectURL) {
    // reject external URLs
}
```

The auth-proxy handler omits this validation entirely.

### Attack Scenarios

1. **Phishing**: Attacker sends link like `https://harbor.example.com/c/authproxy/redirect?token=...&postURI=https://attacker.com/fake-login`. User clicks, authenticates with Harbor, then is silently redirected to fake login page that looks identical. User re-enters credentials thinking session expired.

2. **Credential Harvesting**: Combined with social engineering (e-mail appears to come from Harbor team asking user to re-authenticate).

3. **Malware Distribution**: Redirect to malware-hosting site with drive-by download.

## Data Flow

```
Internet User (authenticated)
    |
GET /c/authproxy/redirect?token=X&postURI=evil.com
    |
AuthProxyController.HandleRedirect()
    |
apc.Ctx.Request.URL.Query().Get("postURI")  [TAINT: attacker-controlled]
    |
uri := "evil.com"  [NO VALIDATION]
    |
apc.Ctx.Redirect(301, uri)  [SINK: unvalidated open redirect]
```

## Recommended Fix

Apply the same validation used in OIDC controller:

```go
uri := apc.Ctx.Request.URL.Query().Get(postURIKey)
if uri == "" {
    uri = "/"
}
// Add validation before redirect
if !utils.IsLocalPath(uri) {
    log.Errorf("Rejecting external redirect URL: %s", uri)
    apc.Ctx.Redirect(http.StatusMovedPermanently, "/")
    return
}
apc.Ctx.Redirect(http.StatusMovedPermanently, uri)
```

## Phase 8 Chamber Assignment

**Chamber**: **Authentication & Trust Boundary (AUTH-001)**

**Rationale**:
- Crosses explicit trust boundary (TB-1)
- Exploitable after authentication
- Similar to 2022 CVE clusters involving auth-proxy bypass
- Affects confidentiality (phishing) and integrity (malware vectors)

## References

- **OWASP**: [Unvalidated Redirects and Forwards](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- **CWE-601**: [URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)
- **KB Report**: TB-1 (Internet <-> Nginx) trust boundary
- **Commit Reference**: `b6c083d73` mentioned in SAST results (prior incomplete fix)

## Notes for Reviewers

1. **Severity Justification**: HIGH because it crosses explicit trust boundary and enables social engineering attacks
2. **Exploitability**: Requires user interaction but no elevated privileges
3. **Impact**: Phishing attacks, credential harvesting, malware distribution
4. **False Positive Risk**: VERY LOW - CodeQL confirmed, pattern identical to secure OIDC handler
