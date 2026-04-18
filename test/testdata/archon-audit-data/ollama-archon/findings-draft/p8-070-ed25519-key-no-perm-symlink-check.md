Phase: 8
Sequence: 070
Slug: ed25519-key-no-perm-symlink-check
Verdict: FALSE POSITIVE (adversarial)
Rationale: `auth/auth.go:22-42 GetPublicKey` and `auth/auth.go:53-85 Sign` call `os.ReadFile(~/.ollama/id_ed25519)` with no `os.Lstat`, no mode check, no ownership assertion; the directory is created with `0o755` (world-listable). Advocate agrees OpenSSH-style permission checks should apply and concedes multi-user / CI-runner / container scenarios make symlink-swap a real primitive.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-04/debate.md

## Summary

Every signing operation in the cloud-proxy chain reads `~/.ollama/id_ed25519` from disk with no safety checks:

```go
// auth/auth.go:22-42
func GetPublicKey() (ssh.PublicKey, error) {
    home, _ := os.UserHomeDir()
    keyData, err := os.ReadFile(filepath.Join(home, ".ollama", "id_ed25519"))
    ...
}

// auth/auth.go:53-85
func Sign(ctx context.Context, bts []byte) (string, error) {
    ...
    keyData, err := os.ReadFile(keyPath)
    ...
}
```

`os.ReadFile` follows symlinks silently. No `os.Lstat` to detect a symlink. No `info.Mode()&0o077 != 0` world-readable check. No ownership check (`stat.Uid != os.Getuid()`).

The directory containing the key is created with `0o755` (from `cmd/cmd.go ~1840` `initializeKeypair` calling `os.MkdirAll(..., 0o755)`) — world-listable but not world-writable on UNIX. However:

- On shared home (NFS, multi-user CI, some container bind-mounts) the world-readable directory + attacker write access to the directory (from an earlier compromise, a co-tenant, or a misconfigured image) enables symlink-swap: attacker replaces `id_ed25519` with a symlink pointing at a key they control. All subsequent `Sign` calls produce signatures over the attacker's key — ollama.com then attributes requests to the attacker's account instead of the victim, OR if the attacker's key matches one they've previously registered, they claim the victim's traffic.
- On single-user systems with hardening incidents (key copied to home during a backup restore with umask 0022 so file ends up 0o644), the key becomes world-readable — any local process can sign as the user.

OpenSSH refuses to load a private key whose mode includes group/world read bits; Ollama has no such safety.

## Location

- `auth/auth.go:22-42` — `GetPublicKey`
- `auth/auth.go:53-85` — `Sign`
- `cmd/cmd.go` (~1840) — `initializeKeypair`: `os.MkdirAll(..., 0o755)` and `os.WriteFile(..., 0o600)`
- No follow-up mode check on subsequent reads

## Attacker Control

Any local attacker (same user, CI co-tenant, container neighbor) with write access to `~/.ollama/` OR read access to the key file OR ability to create a symlink.

## Trust Boundary Crossed

Local unprivileged user → cryptographic identity.

## Impact

- Private-key exfiltration when file mode is loosened (backup restore, rsync --no-perms, umask 0022 creation paths).
- Identity substitution via symlink when directory is writable (shared home, mounted volumes, multi-tenant containers).
- Feeds the realm-downgrade leg of CHAIN-A (p8-005 / H-00.06) — if the attacker captures a signing oracle, the key permission gap lowers the bar from "network MITM" to "local filesystem access".

## Evidence

Tracer confirmed the code path; `auth/auth.go` contains no permission/symlink checks. Companion fix `eb0a5d44` added `info.Mode().IsRegular()` for the now-removed system-path case but never propagated to the home-path case.

Advocate: "Defense-worth-raising at MEDIUM" — Synthesizer upgrades to HIGH because the consequence of compromise is a cryptographic identity used for cloud-side billing + query attribution, and the mitigation cost is trivial (one `os.Lstat` call plus mode check).

## Reproduction Steps

Symlink-swap scenario (shared home / container bind-mount):
1. As attacker with write access to `~/.ollama/`: `ln -sf /tmp/attacker_id_ed25519 ~/.ollama/id_ed25519`.
2. Victim runs `ollama pull` or any cloud-proxy call.
3. Sign operation reads attacker's key file; requests to ollama.com are signed with attacker's key.

World-readable scenario:
1. Attacker runs `chmod 0644 ~/.ollama/id_ed25519` (or any restore/backup that does the same).
2. Any local process on the machine reads the key: `cat ~/.ollama/id_ed25519`.
3. Offline signing oracle follows.

Remediation: at load time, `os.Lstat` the file, reject if `stat.Mode()&0o077 != 0`, `stat.Mode()&os.ModeSymlink != 0` (unless explicitly opted in via `OLLAMA_ALLOW_SYMLINK_KEY`), or `stat.Uid != os.Getuid()`. Mirror OpenSSH's enforcement.

---

Adversarial-Verdict: DISPROVED
Adversarial-Rationale: Code-level claim verified and symlink-follow primitive reproduced, but every concrete exploitation path requires the attacker to already possess same-uid read/sign access or a specific environmental misconfiguration (shared home, wrong-UID bind mount, post-restore chmod) outside Ollama's trust model — no new trust boundary is crossed.
Severity-Final: LOW
PoC-Status: executed
