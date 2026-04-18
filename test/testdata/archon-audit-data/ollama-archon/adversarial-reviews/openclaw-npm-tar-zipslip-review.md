Adversarial Cold Review — p8-071-openclaw-npm-tar-zipslip

## Step 1 — Restated Claim

The draft alleges that `cmd/launch/openclaw.go:782` shells out to the system `tar` binary to extract an npm tarball without passing `--no-absolute-names` and without Go-side path validation. The claim is that GNU tar's `--strip-components=1` alone does not block absolute paths or relative `..` traversal, so a malicious tarball from a compromised `@ollama/openclaw-web-search` npm release can write files outside the plugin directory (ZipSlip), enabling arbitrary file write such as `~/.ssh/authorized_keys`.

Sub-claims:
- A. Attacker controls the tarball bytes — requires compromising the npm scope `@ollama` or MITMing a TLS-protected npm registry connection.
- B. The bytes reach `tar` extraction without Go-side sanitization — true, Go code only invokes tar and never inspects entries.
- C. The external `tar` command allows path traversal / absolute paths / symlink follow-through with `--strip-components=1` — **this is the load-bearing claim**, and the draft does not prove it, only asserts variability ("legacy tar behavior varies").

## Step 2 — Independent Code Path Trace

Read `cmd/launch/openclaw.go:750-790` directly:

- `ensureWebSearchPlugin()` builds `pluginDir = ~/.openclaw/extensions/openclaw-web-search`.
- Calls `exec.Command(npmBin, "pack", webSearchNpmPackage, "--pack-destination", pluginDir).Output()` — the npm CLI downloads the tarball and prints the filename; returns bytes over HTTPS from registry.npmjs.org.
- Constructs `tgzPath := filepath.Join(pluginDir, tgzName)`.
- Runs `exec.Command("tar", "xzf", tgzPath, "--strip-components=1", "-C", pluginDir)`.

No Go-side entry validation, no `filepath.IsLocal`, no `filepath.EvalSymlinks` post-check. The finding's code trace is accurate on this point.

Caller: `cmd/launch/openclaw.go:101` invokes `ensureWebSearchPlugin` inside `Openclaw.Run` after onboarding, which runs during `ollama launch` (not `ollama serve` as the draft claims — minor inaccuracy).

## Step 3 — Protection Surface Search

The finding itself concedes the security posture depends entirely on what the external `tar` does. I examined tar implementations actually present on modern systems:

**bsdtar 3.5.3 (libarchive 3.7.4) — macOS default**: Default extraction refuses `..` paths. Default refuses to extract through symlinks. Default silently drops absolute-path entries.

**GNU tar 1.35 — modern Linux / Homebrew**: Default refuses `..` paths with "Member name contains '..'". Default strips leading `/` from absolute paths. `-P/--absolute-names` is the option required to DISABLE the default stripping, confirming the default is safe. Default refuses to overwrite through symlinks.

For the attack to work, the tar binary would have to be one that both fails to strip leading `/` AND fails to reject `..` members by default. Such tar versions do exist historically (pre-2011 GNU tar), but they are not present on any current supported Linux distribution. The finding cites no concrete platform where the default tar is unsafe.

No other layer protections needed — the tar binary itself provides sufficient defense.

## Step 4 — Real-Environment Reproduction

Environment: macOS 25.3.0 (Darwin), bsdtar 3.5.3, GNU tar 1.35 also available.

Reproduction attempts (all stored in `archon/real-env-evidence/openclaw-npm-tar-zipslip/`):

**Attempt 1**: Relative traversal `package/../escape-target/pwned` (the exact pattern described in draft step 4).
- bsdtar: `../escape-target/pwned: Path contains '..': Unknown error: -1` — BLOCKED.
- gtar: `package/../escape-target/pwned: Member name contains '..'` — BLOCKED.

**Attempt 2**: Absolute path entry `/tmp/zipslip-test/escape-target/pwned-abs`.
- bsdtar: silently dropped — BLOCKED.
- gtar: `Removing leading '/' from member names` — file would have been written inside `pluginDir` at `tmp/zipslip-test/escape-target/pwned-abs`, but since `--strip-components=1` strips `tmp/`, the entry becomes `zipslip-test/escape-target/pwned-abs` inside pluginDir. Still contained.

**Attempt 3**: Symlink to outside target, then write through symlink.
- bsdtar: `Cannot extract through symlink` — BLOCKED.
- gtar: `Cannot open: Not a directory` (refuses to descend into symlink) — BLOCKED.

**Attempt 4**: Embedded `..` in a deeper path `package/foo/../../escape-target/embedded-pwn`.
- Both tars: rejected with "Member name contains '..'" / "Path contains '..'" — BLOCKED.

**Attempt 5**: Hard link to a file outside the target (`/tmp/zipslip-test/escape-target/existing`).
- Both tars: strip absolute prefix from hard-link target, then fail because the (now relative) target doesn't exist under pluginDir — BLOCKED.

Zero of five attack variants succeeded in writing any file outside `pluginDir`. Evidence files saved to `archon/real-env-evidence/openclaw-npm-tar-zipslip/`.

## Step 5 — Prosecution Brief

The Go code does shell out to tar with no Go-side validation. There is genuine defense-in-depth debt: the safety properties are entirely delegated to whatever tar binary exists on the user's `$PATH` when `ensureWebSearchPlugin` runs, and the Go code neither pins a tar version nor verifies the extracted tree afterwards. If an attacker could compromise the `@ollama` npm scope (possible via credential theft, maintainer account takeover), they would control the tarball bytes. Remediation with `archive/tar` + `filepath.IsLocal` would be straightforward.

However, a prosecution that requires (a) supply-chain compromise of `@ollama` npm account, AND (b) the presence of a historical tar binary that fails to reject `..` by default, has no real-world target. The finding describes no such system.

## Step 6 — Defense Brief

Starting at MEDIUM per the severity challenge rule.

1. All modern tar implementations (GNU tar 1.26+ since ~2011, bsdtar of any recent vintage, busybox tar) reject relative `..` members by default. The draft waves its hand at "legacy tar behavior varies" without naming a single shipping platform where the unsafe behavior is the default.
2. All modern tar implementations strip leading `/` from archive members by default. `-P/--absolute-names` is an opt-in flag; the Go code does not pass it.
3. All modern tar implementations refuse to extract through symlinks by default.
4. The claimed reproduction step ("the entry `../../../.ssh/authorized_keys` becomes `../../.ssh/authorized_keys` relative to pluginDir, which IS writable") is factually wrong: both tested tar binaries explicitly refuse such entries and exit with non-zero status before writing anything.
5. Reproduction executed end-to-end on the same machine the draft was authored on (macOS) with bsdtar, and with a locally-installed GNU tar 1.35. Five attack variants all blocked.
6. Additional precondition: attacker must compromise the ollama-owned npm scope — a supply-chain attack that, if successful, gives the attacker far more direct avenues (install scripts, postinstall hooks executed by `npm pack`... actually `npm pack` only downloads, but the next `npm install` path used by OpenClaw and user-initiated installs would run scripts). ZipSlip is strictly weaker than what they'd already have.

Defense concludes: there is no demonstrable attack path on any platform that a realistic Ollama user runs. The claim rests on unverified speculation about tar implementations.

## Step 7 — Severity Challenge

Starting at MEDIUM. Downgrade signals present: (a) requires supply-chain compromise of `@ollama` npm scope — not a low-privilege remote attack; (b) even if tarball is compromised, the claimed primitive is blocked on every tar tested. Upgrade signals: none present with the documented defenses. Final severity if this were a real finding: LOW / defense-in-depth. But since reproduction failed and a blocking protection is identified in the tar binary itself, the appropriate classification is FALSE POSITIVE.

## Step 7 — Verdict

Reproduction failed across 5 variants with 2 tar binaries on a real environment (not blocked — actively tested). The defense brief identifies a concrete blocking protection (tar's default refusal of `..` members and absolute paths) that the draft incorrectly assumes is absent.

Adversarial-Verdict: DISPROVED
Adversarial-Rationale: Executed 5 attack variants with both bsdtar 3.5.3 and GNU tar 1.35; every variant was blocked by the tar binary's default behavior (refuses `..`, strips leading `/`, refuses symlink follow-through), contradicting the finding's premise that `--strip-components=1` is the only defense.
Severity-Final: LOW (defense-in-depth suggestion only; no working exploit path demonstrated)
PoC-Status: executed (all variants failed to achieve the claimed primitive)
