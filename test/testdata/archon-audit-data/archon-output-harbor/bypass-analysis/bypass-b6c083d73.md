# Bypass Analysis: CVE-2024-22244 — Open Redirect on Logout

**Commit:** b6c083d73409d4577b48015423ff0407eec09159  
**Advisory:** CVE-2024-22244  
**Severity:** Medium  
**Cluster ID:** oidc-redirect-cluster-01  
**Related commits:** 4f56f5d27 (post_logout_redirect_uri hardening), 5b832c172 (IsLocalPath introduced), 96ba34a93 (empty-path allowed)

---

## Patch Summary

### What was fixed

`RedirectLogout()` in `src/core/controllers/oidc.go` contained four early-return redirect calls that used the literal `"/"` as the redirect target. The fix replaces all four with the hardcoded string `"/account/sign-in"`.

The commit comment explains the motivation: redirecting to `"/"` caused Harbor's Angular SPA to immediately re-trigger the OIDC login flow when no session existed, creating an implicit open redirect via the OIDC IdP's `post_logout_redirect_uri`. The complementary commit `4f56f5d27` had already hardened the happy-path by changing `url.QueryEscape(baseURL)` to `url.QueryEscape(fmt.Sprintf("%s/account/sign-in", baseURL))` for the `post_logout_redirect_uri` parameter sent to the OIDC IdP.

### Mechanism

The fix is purely string substitution of fallback redirect targets. No new validation logic was added.

---

## Bypass Verdict: **bypassable**

---

## Evidence

### 1. Unprotected `redirect_url` in `Callback()` — most critical surviving path

`RedirectLogin()` at line 81 validates the incoming `redirect_url` query parameter with `utils.IsLocalPath()`:

```go
// src/core/controllers/oidc.go:81-86
redirectURL := oc.Ctx.Request.URL.Query().Get("redirect_url")
if !utils.IsLocalPath(redirectURL) {
    log.Errorf("invalid redirect url: %v", redirectURL)
    oc.SendBadRequestError(fmt.Errorf("cannot redirect to other site"))
    return
}
```

The validated value is stored in session under `redirectURLKey`. Later, in `Callback()` at line 233, it is retrieved and passed directly to `oc.Controller.Redirect()` **without re-validation**:

```go
// src/core/controllers/oidc.go:230-233
if redirectURLStr == "" {
    redirectURLStr = "/"
}
oc.Controller.Redirect(redirectURLStr, http.StatusFound)
```

`IsLocalPath` is defined as:

```go
// src/common/utils/utils.go:309-311
func IsLocalPath(path string) bool {
    return len(path) == 0 || (strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//"))
}
```

**Known bypass vectors against this check:**

| Vector | Input | Result |
|--------|-------|--------|
| Backslash-prefixed protocol-relative | `\/evil.com` | `IsLocalPath` returns `true` (starts with `/`, not `//`). Beego's `Redirect` writes this verbatim into the `Location` header. Whether browsers interpret `\/evil.com` as a cross-origin redirect depends on the browser; Chromium and Firefox both treat `\/` as equivalent to `//` in `Location` headers. |
| URL-encoded slash bypass | `/%2Fevil.com` or `/%5Cevil.com` | `IsLocalPath` returns `true` (starts with `/`). At the HTTP layer the `Location` header value is written raw; most browsers will decode `%2F` → `/` and `%5C` → `\`, resulting in redirect to `//evil.com` or `\/evil.com`. |
| Tab/newline injection (`\t`, `\n`) | `/ \t\nevil.com` (URL-encoded) | `IsLocalPath` returns `true`. Beego does not normalize the string before writing it. Header injection risk exists if the Go HTTP library does not strip `\r\n`. Go's `net/http` does strip `\r\n` in header values since Go 1.14, but `\t` is not stripped. |

The `\/` backslash vector is the highest-confidence live bypass for the `redirect_url` parameter in `RedirectLogin()` → `Callback()`.

### 2. Unprotected `postURI` in `AuthProxyController.HandleRedirect()` — uncovered sibling path

`src/core/controllers/authproxy_redirect.go` line 73–77 reads the `postURI` query parameter and redirects directly with no validation whatsoever:

```go
// authproxy_redirect.go:73-77
uri := apc.Ctx.Request.URL.Query().Get(postURIKey)
if uri == "" {
    uri = "/"
}
apc.Ctx.Redirect(http.StatusMovedPermanently, uri)
```

This endpoint (`/c/authproxy/redirect`) accepts an arbitrary `postURI` value and will redirect to any URL an attacker supplies — including `https://evil.com`, `//evil.com`, `javascript:alert(1)`, etc. This path is entirely unprotected by `IsLocalPath` or any equivalent check. It is reachable only when `auth_mode == HTTPAuth`, but that is a configuration-level gate, not a security boundary the fix addresses.

This is the most severe surviving open redirect in the codebase.

### 3. Angular `router.navigateByUrl(this.redirectUrl)` in `oidc-onboard.component.ts`

In `src/portal/src/app/oidc-onboard/oidc-onboard.component.ts` line 53, after a successful onboard the component calls:

```typescript
this.router.navigateByUrl(this.redirectUrl);
```

`this.redirectUrl` is taken from the `redirect_url` query parameter of the `/oidc-onboard` URL (line 40). The `/oidc-onboard` URL itself is constructed by the server at `oidc.go:203`:

```go
oc.Controller.Redirect(
    fmt.Sprintf("/oidc-onboard?username=%s&redirect_url=%s", username, redirectURLStr),
    http.StatusFound)
```

`redirectURLStr` is the session-stored value that **was** validated on entry in `RedirectLogin()`, so the server-side storage is gated by `IsLocalPath`. However, the `/oidc-onboard` page is a client-rendered Angular route. An attacker can navigate directly to `/oidc-onboard?redirect_url=https://evil.com` without ever going through `RedirectLogin()`. Angular's `router.navigateByUrl()` with an absolute URL including a hostname will typically be rejected by the Angular Router (it only handles in-app routes), but it does not throw an error — it silently falls through. The exploit impact here is limited.

### 4. `window.location.href = redirect_location` in `navigator.component.ts` and `sign-in.component.ts`

Both components (lines 237 and 288 respectively) assign a server-supplied `redirect_location` value directly to `window.location.href`. The server generates this value in `base.go` (lines 88 and 132) by constructing it from `config.ExtEndpoint()` with a hardcoded suffix:

```go
url := strings.TrimSuffix(ep, "/") + common.OIDCLoginPath   // or OIDCLoginoutPath
```

Because the value is entirely server-generated from the configured external endpoint, an external attacker cannot influence it. This vector is only exploitable if `ExtEndpoint` is misconfigured to point at an attacker-controlled domain, which is an admin misconfiguration, not a security boundary concern.

---

## Summary of Surviving Attack Surfaces

| # | Location | Input vector | Gated by `IsLocalPath`? | Exploitable? |
|---|----------|-------------|------------------------|--------------|
| 1 | `oidc.go Callback()` line 233 | `?redirect_url=\/evil.com` passed to `RedirectLogin` | Yes, but backslash bypass exists | Likely — browser-dependent |
| 2 | `authproxy_redirect.go` line 77 | `?postURI=https://evil.com` | **No** | Yes (HTTPAuth mode) |
| 3 | `oidc-onboard.component.ts` line 53 | `?redirect_url=` in direct URL | Angular Router mitigates | Minimal impact |
| 4 | `sign-in.component.ts` + `navigator.component.ts` | `window.location.href = redirect_location` | Server-generated, not attacker-controlled | No |

---

## Undisclosed Tag

Not applicable. CVE-2024-22244 is a known advisory. However, the `authproxy_redirect.go` `postURI` gap and the `IsLocalPath` backslash bypass are not addressed by this commit and do not appear to have a separate advisory — both qualify for `[undisclosed]` labeling.

---

## Recommendations

1. **Apply `IsLocalPath` to `postURI` in `authproxy_redirect.go`** — this is the highest-severity unfixed open redirect.
2. **Add `\/` and `%2F` / `%5C` prefix normalization to `IsLocalPath`**, or replace it with a URL-parse-based check (`url.Parse` + assert `.Host == ""`).
3. **Re-validate `redirectURLStr` at point of use in `Callback()`** rather than trusting the session-stored value was correctly validated at entry.
4. **Add test cases to `TestIsLocalPath`** covering `\/evil.com`, `/%2Fevil.com`, `/%5Cevil.com`, `/\evil.com`.
