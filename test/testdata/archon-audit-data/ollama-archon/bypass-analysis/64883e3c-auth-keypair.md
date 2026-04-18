# Bypass Analysis — 64883e3c "auth: fix problems with the ollama keypairs"

- **Type**: undisclosed-fix
- **Cluster ID**: AUTH-KEYPAIR (related: `eb0a5d44` "check the permissions on the private key", `eed58a31` "add local sign-in state storage", `106640b9` "fix lint")
- **Files**: `auth/auth.go`, `cmd/cmd.go`, `server/routes.go`, `api/client.go`, `api/types.go`
- **Commit author/date**: Patrick Devine, 2025-09-22

## Patch Summary

Three independent changes are bundled in this commit:

1. **Removal of the system-path key fallback.** `auth.keyPath()` previously preferred `/usr/share/ollama/.ollama/id_ed25519` (the ollama system-user key in the standard Linux package install) over `~/.ollama/id_ed25519`, but only if the candidate was readable to the current process. Both `GetPublicKey()` and `Sign()` are now hardcoded to `os.UserHomeDir() + "/.ollama/id_ed25519"` and the `keyPath()` helper is gone.
2. **Reshape of the unauthorized-error contract.** The proxied chat/generate handlers no longer leak the local `public_key` in the 401 body and no longer return HTTP 500 when key loading fails on a cold server; instead they return a `signin_url` (URL-encoded hostname + base64 pubkey) computed inside the new `signinURL()` helper in `server/routes.go`. CLI handlers (`RunHandler`, `SigninHandler`, `SignoutHandler`) consume the URL directly rather than recomputing it locally.
3. **Signout-route reshuffle.** A new `POST /api/signout` route is added; the legacy `DELETE /api/user/keys/:encodedKey` is preserved for backwards compatibility but now ignores the path parameter and looks up the key server-side. `client.Signout` and `client.Disconnect` are renamed/split.

The pre-patch security risk modeled by reviewers: on a stock Linux install, `ollama serve` runs as the `ollama` system user, so the registry/cloud identity is bound to the key in `/usr/share/ollama/.ollama/`. Because (a) the home directory is `0755` by default in the Debian/Ubuntu packaging and (b) `/usr/share/ollama/.ollama/id_ed25519` is `0600` only by post-creation chmod, any local user invoking `ollama` (CLI) would silently load that path due to the readability check in `keyPath()`. After the patch each calling UID falls back exclusively to its own `~/.ollama/id_ed25519`, isolating per-user identities.

## Bypass Verdict

**relocated** — the `/usr/share/ollama/...` fallback is gone, but the remaining logic still has multiple residual exposures around the same key, and the new `signinURL` plumbing creates a low-friction public-key oracle on the HTTP API.

## Bypass Hypotheses Tested

### H1. Other system paths still consulted (sound)
- `auth/auth.go` reads `os.UserHomeDir() + "/.ollama/id_ed25519"` only. There is no `OLLAMA_HOME` env override, no `/etc/ollama/...` fallback, no XDG path. `envconfig` does not expose a HOME alias either (`envconfig/config.go:118,390`). On Linux `os.UserHomeDir()` resolves `$HOME` first, then `/etc/passwd` for the EUID — both are user-bound, so a local attacker cannot redirect another user's key path through env manipulation.
- The duplicate registry implementation at `server/internal/client/ollama/registry.go:272` also reads `~/.ollama/id_ed25519` and is consistent with the patch. No leftover system-path callers.

### H2. Symlink hijack of `~/.ollama/id_ed25519` (bypassable in narrow scenario)
- `auth.GetPublicKey`/`Sign` call `os.ReadFile(keyPath)` with no `Lstat` and no `EvalSymlinks` check (compare `parser/parser.go:173` which does call `EvalSymlinks` for blob enumeration). If an attacker can write inside `~/.ollama/` of a target user (e.g., a chrooted process, a misconfigured CI container that mounts the home dir, or another local user when `~` is `0777`), they can replace `id_ed25519` with a symlink to a key they control before the user runs `ollama push`/Cloud signing. This is operator-error territory but the fix did not add any owner/permission verification.
- The companion commit `eb0a5d44` only verified that the system-path file was a *regular* file via `info.Mode().IsRegular()`. After 64883e3c, even that weak check is removed for the home-path case.

### H3. Owner / permission verification missing (bypassable)
- `initializeKeypair()` (cmd/cmd.go:1840) creates the dir as `0o755` and the key as `0o600` only on first run. If the directory or file was pre-created with weaker perms, the server happily loads it. There is **no `Stat`-based perm/owner check at load time** — Ollama loads any readable file at the canonical path regardless of `0o644`, `0o666`, group ownership, etc. SSH itself refuses to use private keys with permissive perms; Ollama does not.

### M13. World-readable directory traversal (bypassable in deployment)
- `MkdirAll(...., 0o755)` — directory mode lets any local user `cd ~user/.ollama`. If the operator does not chmod `0o600` on the file (e.g., umask edits, restoration from a tar with `--no-same-permissions`), the private key is exposed to every local UID. The patch did not narrow the directory permissions to `0o700` and did not add a load-time mode check.

### H3. TOCTOU between create and use (sound — not realistic here)
- `initializeKeypair()` runs once at `RunServer` start and `WriteFile` uses `O_TRUNC|O_CREATE|O_WRONLY` with mode `0o600` — racing this requires winning a window inside a single user's process startup. Cross-user races on `~/.ollama/` were already covered by M13. No additional TOCTOU vector introduced by 64883e3c.

### H6. Public-key oracle via `/api/me` and 401 responses (bypassable / new exposure introduced)
- New behavior: any unauthenticated caller that can reach the Ollama HTTP server can issue `POST /api/me` (`server/routes.go:1696,1981`). When the upstream `ollama.com` whoami returns "no user", the handler synchronously calls `signinURL() -> auth.GetPublicKey()` and returns the base64-encoded **public key** in `signin_url`. The same disclosure happens via `GenerateHandler`/`ChatHandler` proxied 401 paths (`routes.go:328-339`, `1843-...`).
- Because the only network-layer guard is `allowedHostsMiddleware` (`routes.go:1608`), which permits localhost + configured origins (and is widely bypassed in the field — see `archon/knowledge-base-report.md` row 9), the public key (and the hostname via `os.Hostname()`) is recoverable by any LAN-adjacent attacker. The pre-patch behavior leaked the same information in `public_key` JSON; the patch does **not** remove the leak — it relocates it into the `signin_url`. CSRF is also viable because routes are unauthenticated and CORS allows wildcards (`corsConfig.AllowOrigins = envconfig.AllowedOrigins()` with `*` default in many configs).
- Severity is reduced versus a private-key compromise because the public key alone does not authenticate the holder, but it (a) gives an attacker a deterministic device fingerprint to correlate the host to its ollama.com identity and (b) enables a phishing pivot: an attacker who controls a malicious Ollama-compatible server could mint a `signin_url` containing the *attacker's* public key, the *victim's* hostname, and a forged ollama.com origin — a UX condition the CLI accepts verbatim (`cmd/cmd.go: fmt.Printf(ConnectInstructions, sErr.SigninURL)` with no host validation).

### H7. Signature oracle (sound)
- `Sign()` requires a caller inside the local process; there is no HTTP endpoint that accepts arbitrary bytes and returns a signature. Cloud-proxy signing uses `auth.Sign` server-side over server-controlled challenge data only (`server/auth.go:42-68`, `server/cloud_proxy.go:367`). No oracle gadget added.

### M14. Auth-error info leak (relocated)
- The patch fixed a legitimate gap (`HTTP 500` on missing key) by funneling errors through `AuthorizationError` with a `signin_url`. Two side effects:
  - `signinURL()` failures (e.g., key file unreadable) now return `500 "error getting authorization details"` from `routes.go:332-334`, which is itself an existence/permission oracle for the key file — but since the canonical path is well-known per-user, this leaks little.
  - `client.checkError` (`api/client.go:48-52`) silently `json.Unmarshal`s the body into `AuthorizationError` without checking the unmarshal error; a malicious upstream can plant arbitrary `signin_url` content and the CLI will print it via `ConnectInstructions`. Combined with H6 this enables a phishing channel.

### M10. Sibling `id_ed25519.pub` file (sound)
- The patch removes use of the `.pub` sibling entirely (`Sign`/`GetPublicKey` derive the public key from the parsed private key). No code path now reads `id_ed25519.pub`, so a malicious `.pub` file cannot be used as a tampering vector.

### M32. Compatibility branch / deprecated route (sound but trust-shifted)
- `DELETE /api/user/keys/:encodedKey` still exists as a deprecated alias of `/api/signout`. The path parameter `encodedKey` is no longer trusted — the server reads its own pubkey via `auth.GetPublicKey()` and ignores the URL. This closes a prior trust vector where any local caller could have requested deletion of an arbitrary user's key on ollama.com (subject to upstream auth). Sound.

## Evidence

- `auth/auth.go:21-42, 53-85` — current state, no perm/symlink/owner checks.
- `cmd/cmd.go:1840-1884` — keypair init uses `0o755` dir + `0o600` file; no re-check on subsequent reads.
- `server/routes.go:183-192` — `signinURL()` derives public key + hostname for inclusion in unauthenticated responses.
- `server/routes.go:1696-1700` — `/api/me`, `/api/signout`, and `DELETE /api/user/keys/:encodedKey` are mounted with no auth middleware.
- `server/routes.go:1981-2010` — `WhoamiHandler` returns `signin_url` to any caller producing a 401 from upstream.
- `api/client.go:45-52` — `checkError` swallows `json.Unmarshal` errors when populating `AuthorizationError`, enabling upstream-controlled `SigninURL` injection.
- `cmd/cmd.go:RunHandler/SigninHandler` — print `sErr.SigninURL` verbatim with no domain pinning.

## Recommended Hardening (not part of this patch)

1. At key-load time, `Lstat` the path and reject if not a regular file, not owned by EUID, or with `mode & 0o077 != 0`.
2. Tighten `~/.ollama/` to `0o700` on first creation in `initializeKeypair()`.
3. Authenticate `/api/me`, `/api/signout`, and the deprecated DELETE alias (or restrict them to loopback only).
4. Pin `signin_url` host in the CLI to `ollama.com` (or an allowlisted set) before printing.
5. Strict-decode the `AuthorizationError` JSON in `api/client.go:checkError` and validate the `signin_url` scheme/host.

