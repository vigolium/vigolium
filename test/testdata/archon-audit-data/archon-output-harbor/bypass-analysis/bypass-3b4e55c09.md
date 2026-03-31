# Bypass Analysis: 3b4e55c09 — CVE-2024-GOLANG Dependency Upgrades

## Patch Summary

Commit `3b4e55c0906afb466cff3b7ce56b078dcf82f4e1` is a copilot-generated fix on branch
`origin/copilot/release-2140-fix-golang-cves`. It targets the `release-2.14.0` line and
upgrades four sets of dependencies relative to the **original** `release-2.14.0` baseline
(`origin/release-2.14.0`, head commit `419eba58d`):

| Package | Original release-2.14.0 | Post-patch | CVE(s) addressed |
|---|---|---|---|
| `github.com/gorilla/csrf` | v1.7.2 | v1.7.3 | CVE-2025-24358 |
| `golang.org/x/crypto` | v0.45.0 | v0.47.0 | CVE-2024-45337, CVE-2025-58181 (GO-2025-4134) |
| `go.opentelemetry.io/otel/sdk` | v1.38.0 | v1.40.0 | (no discrete CVE; supply-chain hygiene) |
| `github.com/docker/cli` | v27.1.1+incompatible | v29.2.0+incompatible | CVE-2025-15558 (Windows LPE) |
| Go toolchain (`go.mod` directive) | go 1.25.7 (pre-reset) | go 1.25.8 | Compiler-level CVEs |

The diff is internally confusing because the copilot agent first reset the branch to a snapshot
that already contained higher versions (b56e7299f baseline had v1.42.0 otel/sdk, v0.48.0 x/crypto),
then "fixed" by pinning lower, patched versions. The net change relative to the **original**
release-2.14.0 branch is an upgrade, which is what matters for CVE remediation.

---

## Bypass Verdict: `bypassable` (partially)

Three distinct bypass surfaces were identified.

---

## Evidence

### 1. CVE-2025-47909 — gorilla/csrf: No Fix Exists in gorilla/csrf (CRITICAL RESIDUAL)

**Verdict: bypassable**

The patch upgrades `gorilla/csrf` to v1.7.3, which fixes CVE-2025-24358 (Referer header not
validated under TLS due to `r.URL.Scheme` always being empty for server requests).

However, v1.7.3 introduced CVE-2025-47909: if any host is listed in `TrustedOrigins`,
`gorilla/csrf` allows both its HTTP and HTTPS origins, because only the host portion of the
synthetic URL is checked and the scheme is ignored. **There is no fixed version of
`github.com/gorilla/csrf`.** The upstream advisory explicitly states the library cannot be
patched and recommends migration.

The recommended fixes are:
- Migrate to `net/http.CrossOriginProtection` (Go 1.25 stdlib), OR
- Use the drop-in replacement `filippo.io/csrf/gorilla`

Harbor's CSRF middleware (`src/server/middleware/csrf/csrf.go`) calls:
```go
protect = csrf.Protect([]byte(key), csrf.RequestHeader(tokenHeader),
    csrf.Secure(secureFlag),
    csrf.ErrorHandler(http.HandlerFunc(handleError)),
    csrf.SameSite(csrf.SameSiteStrictMode),
    csrf.Path("/"))
```
Harbor does **not** use `TrustedOrigins`, which means the specific trigger for CVE-2025-47909
does not apply in the default configuration. However, the `gorilla/csrf` library itself is
unmaintained for this class of vulnerability, and the library remains in a known-broken
security state. A Harbor deployment that adds a `TrustedOrigins` option (e.g., for multi-domain
setups) would be immediately exploitable. An open Harbor issue (#22312) specifically tracks
migration away from `gorilla/csrf`.

### 2. Go Toolchain Version Mismatch: go.mod vs CI (MEDIUM CONCERN)

**Verdict: relocated (build-time gap)**

The `go.mod` directive is set to `go 1.25.8`, yet the CI workflow (`CI.yml`) is configured to
build with Go `1.24.13`:

```
# .github/workflows/CI.yml after patch:
go-version: 1.24.13   (5 job definitions)
```

The commit message claims "Go 1.24.13 → 1.25.8" but the actual effect is the opposite in CI:
the go.mod directive was already `1.25.8` on the reset baseline, and CI was set from `1.25.7`
down to `1.24.13`. This means:

- The binary shipped in CI/CD pipelines is compiled with **Go 1.24.13**, not 1.25.8.
- Any Go-compiler-level CVEs fixed in Go 1.25.x are **not** remediated in shipped artifacts.
- The `net/http.CrossOriginProtection` alternative to `gorilla/csrf` (introduced in Go 1.25)
  is unavailable when the binary is compiled with 1.24.13.

### 3. CVE-2024-45337 and CVE-2025-58181 (x/crypto/ssh): Code Path Not Used Directly

**Verdict: sound** (for Harbor's direct usage)

- CVE-2024-45337 (auth bypass via PublicKeyCallback, fixed in x/crypto v0.31.0) — patched by
  v0.47.0. Harbor does **not** directly import `golang.org/x/crypto/ssh` in any Go file.
  No `ssh.ServerConfig.PublicKeyCallback` is configured. Indirect dependency risk is present
  but cannot be triggered through Harbor's own code.
- CVE-2025-58181 (GSSAPI unbounded memory, fixed in x/crypto v0.45.0) — patched by v0.47.0.
  Same analysis: Harbor does not use the SSH server component at all.
- `golang.org/x/crypto/pbkdf2` is used in `src/common/utils/encrypt.go` for PBKDF2 password
  hashing; this sub-package has no known CVEs and the usage is correct.

x/crypto upgrade is sound for Harbor's actual code paths.

### 4. CVE-2025-15558 (docker/cli Windows LPE): Scope-Limited

**Verdict: sound** (for Harbor's deployment context)

docker/cli is upgraded from v27.1.1 to v29.2.0, which is only an **indirect** dependency.
CVE-2025-15558 is a local privilege escalation via uncontrolled search path on **Windows only**
when loading Docker CLI plugins. Harbor runs exclusively on Linux containers and does not invoke
Docker CLI plugin loading. This upgrade is correct but the CVE does not affect Harbor in
practice.

### 5. Indirect Import Reachability Check

The patched `go.sum` contains only one entry for `gorilla/csrf` (v1.7.3) and one for
`x/crypto` (v0.47.0) with a `/go.mod` hash. No older versions are reachable via indirect
imports in the final build graph. The single `src/go.mod` is the only Go module in the
repository — no sub-modules were missed by this patch.

---

## Summary Table

| Vector | Finding | Severity |
|---|---|---|
| CVE-2025-47909: gorilla/csrf v1.7.3 incomplete fix | No fixed version exists; Harbor not using TrustedOrigins so not immediately exploitable but library is in broken state | Medium |
| Go toolchain mismatch (go.mod 1.25.8 vs CI 1.24.13) | Shipped binary compiled under 1.24.13; compiler CVEs in 1.25.x not remediated; CrossOriginProtection migration unavailable | Medium |
| CVE-2024-45337 / CVE-2025-58181 x/crypto/ssh | Patched; Harbor does not use x/crypto/ssh directly | Sound |
| CVE-2025-15558 docker/cli Windows LPE | Patched; Linux-only deployment means not reachable | Sound |
| Indirect import re-introduction | No older versions reachable in build graph | Sound |
| Sub-module go.mod coverage | Only one go.mod; all in scope | Sound |

---

## Recommended Actions

1. **Migrate CSRF middleware** from `github.com/gorilla/csrf` to `filippo.io/csrf/gorilla` or
   to `net/http.CrossOriginProtection` (Go 1.25). Track via Harbor issue #22312.
2. **Align CI Go version with go.mod directive**: either set CI to `go-version: 1.25.8` or
   downgrade the `go` directive in `go.mod` to `1.24.13`. The current mismatch means the
   binary does not benefit from compiler-level fixes in 1.25.x.

---

## Cluster ID: GOLANG-DEP-UPGRADES-RELEASE-2140

Related commits: b56e7299f (initial reset), 419eba58d (original release-2.14.0 baseline)
Advisory references: CVE-2025-24358, CVE-2025-47909, CVE-2024-45337, CVE-2025-58181,
CVE-2025-15558, Harbor issue #22312
