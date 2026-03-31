# Patch T4-01: CVE-2024-45337 — golang.org/x/crypto SSH Auth Bypass

## Patch Summary

**CVE:** CVE-2024-45337 (CRITICAL 9.1)
**Commit:** 0a390cc069f (#97823)
**Fix:** Bumped `golang.org/x/crypto` from a vulnerable version to v0.31.0 (currently at v0.48.0 in the main `go.mod`).

The upstream vulnerability is in `golang.org/x/crypto/ssh`: when using `ServerConfig.PublicKeyCallback`, the SSH library allowed a client to authenticate with one public key while the server made authorization decisions based on a *different* key. This could let an attacker with any valid key impersonate a more-privileged user.

## Bypass Verdict: **sound** (not applicable)

## Evidence

### 1. No Direct Usage of `golang.org/x/crypto/ssh`

An exhaustive search of the entire Grafana Go codebase confirms:

- **Zero imports** of `"golang.org/x/crypto/ssh"` in any `.go` file across `pkg/`, `apps/`, or any other directory.
- **Zero usage** of `ssh.ServerConfig`, `ssh.ClientConfig`, `PublicKeyCallback`, `ssh.Dial`, or `ssh.NewClient`.
- **No SSH tunnel implementation** exists in Grafana's datasource backends (PostgreSQL, MySQL, MSSQL, etc.). Unlike some database tools, Grafana does not implement SSH tunneling for database connections at the application level.

### 2. Dependency is Indirect Only

The `go.mod` entry is explicitly marked `// indirect`:
```
golang.org/x/crypto v0.48.0 // indirect
```

This means `x/crypto` is pulled in as a transitive dependency of other packages (likely gRPC, ACME/TLS, or similar infrastructure libraries), not because Grafana directly uses the SSH subpackage.

### 3. No Frontend SSH Configuration

No frontend code references SSH tunnel configuration, SSH key auth, or SSH-related datasource settings. There is no attack surface exposed through the Grafana UI or API for SSH-based operations.

### 4. LDAP Service — False Positive

Initial grep hits for `ServerConfig` in LDAP and unified storage code were false positives referring to gRPC `AuthenticatorConfig` and LDAP `ServerConfig` types, which are unrelated to SSH.

### 5. Build/CI SSH Usage — Not Runtime

The only SSH references in the codebase are in `pkg/build/daggerbuild/git/container.go`, which handles SSH key mounting for CI/CD git clone operations. This is build-time infrastructure, not part of the running Grafana application, and it uses SSH as a *client* for git, not as a server with `PublicKeyCallback`.

## Risk Assessment

| Hypothesis | Result |
|-----------|--------|
| Grafana uses `x/crypto/ssh` with `ServerConfig.PublicKeyCallback` | **No** — zero SSH server usage |
| Datasource backends use SSH key-based auth via x/crypto | **No** — no SSH tunnel feature exists |
| SSH tunnel config exposed to non-admin users | **N/A** — no SSH tunnel feature |
| Auth-to-authorization key binding issues | **N/A** — no SSH auth code exists |
| SSH connection pool key confusion | **N/A** — no SSH connections exist |

## Conclusion

The CVE-2024-45337 dependency bump is a **supply-chain hygiene fix** with no direct security impact on Grafana. The vulnerable `x/crypto/ssh` subpackage is not used anywhere in the Grafana codebase. The fix is sound by virtue of eliminating the vulnerable dependency version, and no bypass is possible because the vulnerable code path was never reachable from Grafana in the first place.

**Cluster ID:** T4-dependency-bumps
