Phase: 8
Sequence: 071
Slug: openclaw-npm-tar-zipslip
Verdict: FALSE POSITIVE (adversarial)
Adversarial-Verdict: DISPROVED
Adversarial-Rationale: Executed 5 ZipSlip attack variants (relative ..-traversal, absolute path, symlink follow, embedded .., hard-link) against bsdtar 3.5.3 and GNU tar 1.35 using the exact argv from cmd/launch/openclaw.go:782; every variant was blocked by the tar binary's default safety behavior (refuses `..` members, strips leading `/`, refuses to extract through symlinks). The finding's premise that `--strip-components=1` provides the only defense is factually incorrect for any tar shipping on current supported platforms.
Severity-Final: LOW (defense-in-depth suggestion only; no working exploit path demonstrated)
PoC-Status: executed
Rationale: `cmd/launch/openclaw.go:782` shells out to `exec.Command("tar","xzf",tgzPath,"--strip-components=1","-C",pluginDir)` with no Go-side `filepath.IsLocal` / absolute-path rejection on archive entries; a malicious `@ollama/openclaw-web-search` npm tarball can include entries like `../../../../home/user/.ssh/authorized_keys`, and `tar` writes them outside `pluginDir` — ZipSlip primitive on first-launch plugin install. Advocate agrees the primitive is real but downgrades from CRITICAL to HIGH because attacker must compromise the @ollama-scoped npm package (a high-bar supply-chain attack on ollama-the-org).
Severity-Original: HIGH
Pre-FP-Flag: check-5-ambiguous (requires supply-chain compromise of @ollama npm scope or MITM of the HTTPS npm connection)
Debate: archon/chamber-workspace/chamber-04/debate.md
Adversarial-Review: archon/adversarial-reviews/openclaw-npm-tar-zipslip-review.md
Adversarial-Evidence: archon/real-env-evidence/openclaw-npm-tar-zipslip/

## Summary

`ensureWebSearchPlugin` at `cmd/launch/openclaw.go:770-786`:

```go
pack := exec.Command(npmBin, "pack", webSearchNpmPackage, "--pack-destination", pluginDir)
out, err := pack.Output()
...
tgzName := strings.TrimSpace(string(out))
tgzPath := filepath.Join(pluginDir, tgzName)
tar := exec.Command("tar", "xzf", tgzPath, "--strip-components=1", "-C", pluginDir)
```

The Go code relies entirely on the external `tar` binary to police path containment. GNU tar's `--strip-components=1` only strips the first path component of each archive entry — it does NOT reject:
- Absolute paths (`/etc/passwd` → strips to `/etc/passwd` as `/etc/passwd` has no first component; with `-C pluginDir` GNU tar interprets it relative to `pluginDir` by default on newer versions, but legacy tar behavior varies).
- Relative traversal (`../../../../home/user/.ssh/authorized_keys`, `a/../../etc/passwd`).
- Symlink entries that then get followed by subsequent entries written through them.

`tar --no-absolute-names` and `--no-same-permissions` are NOT specified in the exec argv. Different tar implementations (GNU vs BSD vs busybox) apply different defenses, so behavior is platform-dependent.

The `filepath.IsLocal` / `strings.HasPrefix(filepath.Clean(path), pluginDir)` Go-side guard is entirely absent. CodeQL query `query-archive-extract-no-islocal.json` does not model subprocess tar and returned 0 findings — a confirmed false-negative.

## Location

- `cmd/launch/openclaw.go:742` — `webSearchNpmPackage = "@ollama/openclaw-web-search"` (hardcoded)
- `cmd/launch/openclaw.go:770-786` — `ensureWebSearchPlugin` npm pack + tar extract
- `cmd/launch/openclaw.go:782` — the tar exec line (no `--no-absolute-names`, no Go-side validation)
- `cmd/launch/openclaw.go:794-806` — `webSearchPluginUpToDate` version gate (bypasses re-install, not first-run)

## Attacker Control

An adversary who compromises the `@ollama/openclaw-web-search` package on npmjs.org, OR an adversary who MITMs the npm registry connection (TLS compromise, bogus `.npmrc` in user env, corporate proxy downgrade) fully controls the tarball bytes. The npm pack stdout provides `tgzName` — also attacker-influenced if the registry can shape filenames.

## Trust Boundary Crossed

External supply chain (npmjs.org) → local host filesystem write.

## Impact

Arbitrary file write on first-run plugin install. Typical victim flow: new user installs ollama; on first `ollama serve` (or `ollama launch`), `ensureWebSearchPlugin` fires; attacker-controlled tarball plants:

- `~/.ssh/authorized_keys` — persistent backdoor SSH access
- `~/.bashrc` / `~/.zshrc` — persistence at every new shell
- `~/.ollama/id_ed25519` swap — identity substitution (chains with p8-070)
- `~/.config/systemd/user/*.service` — persistent systemd units (Linux)
- Writable Launch Agent plists (macOS)

## Evidence

Tracer marked PARTIAL because the attack requires either a compromised npm package or MITM. Synthesizer adopts HIGH per user instruction: "ZipSlip in openclaw.go — CRITICAL per probe, advocate downgrades because hardcoded npm package; retain HIGH with caveat."

Advocate: "attacker must compromise `@ollama/openclaw-web-search`... HTTPS + npm registry integrity provide defense in depth... degrade from CRITICAL to HIGH." Synthesizer accepts HIGH and notes the mitigation is simple (a few lines of Go-side entry validation).

## Reproduction Steps

1. Assume supply-chain compromise of `@ollama/openclaw-web-search`.
2. Attacker publishes a tarball containing an entry `../../../.ssh/authorized_keys` with the attacker's public SSH key.
3. Victim runs `ollama serve` for the first time (or version upgrade triggers re-install).
4. `ensureWebSearchPlugin` runs `npm pack` → downloads attacker tarball → `tar xzf ... --strip-components=1 -C $pluginDir` extracts. With `--strip-components=1`, the entry `../../../.ssh/authorized_keys` becomes `../../.ssh/authorized_keys` relative to pluginDir, which IS writable.
5. Next SSH login as the victim accepts the attacker's key.

Remediation:
- Add `--no-absolute-names` to the tar argv (GNU tar rejects absolute paths).
- After extraction, walk `pluginDir` and reject the installed plugin if any file's real path escapes `pluginDir` (e.g., via `filepath.EvalSymlinks` + `strings.HasPrefix`).
- Better: use Go's `archive/tar` directly with `filepath.IsLocal` on every entry name, skipping subprocess tar entirely.
- Pin the package's sha256 in the Ollama repo and verify before extract.
- Consider `--owner=<current>` + `--no-same-permissions` to avoid restoring dangerous mode bits.

## Adversarial Reproduction Notes

Ran the exact argv `tar xzf <evil.tgz> --strip-components=1 -C <pluginDir>` against five malicious tarballs constructed with Python `tarfile`:

| Variant | Entry | bsdtar 3.5.3 | GNU tar 1.35 |
|---|---|---|---|
| Relative traversal | `package/../escape-target/pwned` | "Path contains '..'" — rejected | "Member name contains '..'" — rejected |
| Absolute path | `/tmp/.../pwned-abs` | silently dropped | leading `/` stripped, path contained |
| Symlink follow | symlink + write through | "Cannot extract through symlink" | "Cannot open: Not a directory" |
| Embedded `..` | `package/foo/../../escape-target/…` | rejected | rejected |
| Hard link escape | hard-link to `/outside/file` | absolute prefix stripped, target nonexistent | ditto |

No file was written outside `pluginDir` in any variant. The premise that modern tar permits the claimed primitive is incorrect. Artifacts in `archon/real-env-evidence/openclaw-npm-tar-zipslip/`.
