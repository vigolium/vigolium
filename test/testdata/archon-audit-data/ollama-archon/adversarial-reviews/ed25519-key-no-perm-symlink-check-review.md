Adversarial Review — p8-070-ed25519-key-no-perm-symlink-check

Reviewer position: independent, no debate context.

## 1. Restated claim

The `auth` package loads the user-level ed25519 private key with `os.ReadFile(~/.ollama/id_ed25519)` and never:
- detects a symlink on the path (no `Lstat`),
- enforces regular-file / non-group/world-readable modes,
- asserts the file's owning UID.

Consequence asserted by the draft: a local attacker who can either swap the key
file with a symlink or relax its mode obtains (a) identity substitution
(ollama.com attributes traffic to a key the attacker controls) or (b) key
exfiltration.

Sub-claims:
- A. Attacker can influence the file at `~/.ollama/id_ed25519` (write / chmod / swap).
- B. `GetPublicKey`/`Sign` consume the file without any safety control.
- C. The library-level signing layer uses the loaded key material, producing a
  signature attackers can redirect or impersonate.

## 2. Independent code trace

`auth/auth.go` (current HEAD, unmodified since 64883e3c 2025-09-22):
  - `GetPublicKey()` L21-42: UserHomeDir + filepath.Join + `os.ReadFile` + `ssh.ParsePrivateKey`.
  - `Sign()` L53-85: identical load path, then `privateKey.Sign` signs the caller-supplied payload.
  - No Lstat, no Mode check, no Stat_t.Uid check, no warning log on loose modes.

`cmd/cmd.go` `initializeKeypair` (L1840-1884):
  - `os.MkdirAll(..., 0o755)` for `~/.ollama`.
  - `os.WriteFile(privKeyPath, ..., 0o600)` for the private key.
  - `os.WriteFile(pubKeyPath, ..., 0o644)` for the public key.
  - No follow-up lockdown on subsequent loads.

Git history:
  - eb0a5d44 introduced a `keyPath()` helper with `info.Mode().IsRegular()`
    regular-file check — but ONLY for the `/usr/share/ollama/.ollama/` system
    path, which was then removed in 64883e3c. The home-path branch never had
    any check applied.
  - Draft's reference to the companion fix is accurate.

Sub-claim B confirmed: no sanitizer on the path.

## 3. Protection surface search

| Layer | Candidate control | Blocks this? |
|-------|-------------------|--------------|
| Go stdlib | `os.ReadFile` semantics | No — it intentionally follows symlinks. |
| crypto/ssh | `ssh.ParsePrivateKey` | No — it parses whatever PEM it's given. |
| Filesystem | Owner-only dir 0o755 + file 0o600 on creation | Partial. Prevents *other local users on a standard single-user host* from writing or reading. Does NOT protect: same-uid processes, mis-mapped container bind-mounts, NFS homes with permissive export/squash, backup restores that rewrite mode. |
| Ollama codebase | Any Lstat/mode/uid check | None found via grep. |
| Docs | SECURITY.md | No carve-out; does not disclaim local-key threats. |
| OS-level | macOS SIP, Linux DAC | Same as filesystem row — gated on attacker already being the same user or on a mishandled multi-tenant setup. |

No protection blocks the claimed loading semantics. Directory ACL is the only
meaningful barrier and it evaporates in every scenario the draft calls out
(shared home, container bind-mount, post-restore with loosened mode, existing
same-uid process already privilege-separated from the user session, etc.).

## 4. Real-environment reproduction

Environment: local Go toolchain mirroring auth/auth.go's load sequence
(`os.ReadFile` -> `ssh.ParsePrivateKey` -> `MarshalAuthorizedKey`).

Healthcheck: victim key generated and loaded successfully before swap.

Attempt 1 — symlink swap:
  - Write victim key at `$TMP/id_ed25519` mode 0o600.
  - Write attacker key at `$TMP/attacker_id_ed25519` mode 0o600.
  - Remove victim, create symlink victim -> attacker.
  - Replay auth-code path `os.ReadFile` + `ssh.ParsePrivateKey`.
  - Result: loaded public key equals attacker public key verbatim.
  - Evidence: archon/real-env-evidence/ed25519-key-no-perm-symlink-check/

Conclusion: symlink-follow primitive is real in Go's stdlib and in the
Ollama auth layer built on top of it. The draft's technical claim about
`os.ReadFile` semantics is correct and reproducible.

## 5. Prosecution brief

- The loader path is verifiably unchecked (Section 2). Not a single branch in
  `auth/auth.go` examines Lstat, mode bits, or uid.
- The symlink-follow primitive is demonstrated end-to-end (Section 4) with
  attacker key substitution succeeding.
- The directory is explicitly world-listable by construction (`0o755`),
  aligning with the draft's premise.
- The downstream signing path (p8-064 cloud-proxy oracle, p8-005 realm
  downgrade) consumes `Sign`'s output as proof of the caller's ollama.com
  identity; a substituted key therefore rewrites the identity.
- The mitigation is trivial (Lstat + Mode & 0o077 check + uid comparison) and
  is industry standard (OpenSSH enforces exactly this on client key loads).
- Remaining exposure classes:
  * CI runners where the image or cache restoration wrote the key from a
    tarball with umask 0022 (reproducible breakage of 0o600).
  * Container images that bind-mount a host `.ollama` dir with a UID that the
    container user neither matches nor respects.
  * Shared-home NFS deployments, which, while unusual for Ollama, are not
    disclaimed in SECURITY.md.

## 6. Defense brief

- All exploitation paths require the attacker to already have write access to
  `~/.ollama/` or read/chmod access to `~/.ollama/id_ed25519`. On a standard
  single-user UNIX host both primitives mean the attacker is already running
  as the key's owner — at which point they can trivially read the key or call
  `auth.Sign` directly via the Ollama binary, with or without a permission
  check. The "vulnerability" does not open a new attack surface; it fails to
  add a hardening check.
- The world-readable scenario presumes an out-of-band action (backup restore,
  manual chmod, rsync --no-perms) that is neither attacker-controlled nor
  produced by Ollama. A check would only log/abort, not prevent exposure that
  already happened the moment the mode was loosened.
- The symlink-swap scenario requires writable `~/.ollama/`. Standard UNIX
  semantics (dir owned by the user, mode 0o755) mean only the user themselves
  can write there; a co-tenant cannot. Cited shared-home / container-bind
  scenarios are explicitly environmental misconfigurations outside Ollama's
  trust boundary, with no evidence that Ollama is deployed at meaningful scale
  into them.
- OpenSSH's strict-perm check is a defence-in-depth behaviour, not a fix for a
  distinct vulnerability class; Go's x/crypto/ssh library deliberately does
  not enforce it for exactly this reason (application trust model varies).
- Severity should reflect realistic exploitation: local, requires prior
  partial compromise, no new cross-trust-boundary primitive.

## 7. Severity challenge

Baseline: MEDIUM.

Applying the rubric:
- Not remotely triggerable. (downgrade signal)
- Requires local filesystem access with nontrivial preconditions (same-uid
  position, shared-home misconfig, or prior chmod by third party). (downgrade)
- When those preconditions are met, the attacker usually already has the key
  or can achieve the outcome without the symlink primitive. (downgrade)
- When they are not met, the exploit does not fire at all. (downgrade)

Even with the confirmed load semantics, the draft's HIGH rating does not
survive the "attacker-already-has-read-access" equivalence in the dominant
scenarios. The remaining genuine gap is defense-in-depth against post-restore
key-mode loosening and exotic container/NFS layouts. That is a LOW-severity
hardening improvement, not a MEDIUM exploitable bug.

Challenged severity: LOW.

## 8. Verdict

The code-level claim is accurate and the symlink-follow primitive is real and
reproducible in isolation. However, every concrete exploitation path the draft
describes collapses into one of:
  (a) the attacker already has key read/sign ability independent of the
      missing check, so the check adds nothing; or
  (b) an environmental misconfiguration (shared home, wrong-UID bind mount,
      post-restore perm loosening) outside Ollama's documented trust model.

Neither supports a HIGH-severity exploitable-vulnerability finding. This is a
hardening / defense-in-depth gap worth fixing but not a vulnerability that
crosses a trust boundary without substantial prior compromise.

Verdict: DISPROVED (as HIGH / exploitable vuln).
Treated as: LOW hardening gap.
PoC status: executed (symlink-follow primitive verified), but end-to-end
  crossing of a trust boundary not demonstrated because the required
  attacker position already yields equivalent access by other means.
