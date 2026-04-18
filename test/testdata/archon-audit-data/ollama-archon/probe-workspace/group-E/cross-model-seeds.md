# Cross-Model Seeds

## CROSS-01: Shell Metachar Bypass Chains with Denylist Quoting Bypass

Source-A: PH-01 (backward-reasoner) — shell metacharacter injection via approved prefix
Source-B: PH-02 (backward-reasoner) — denylist substring bypass via bash quoting
Connection: Both share the sink `bash.go:64`. PH-01 shows that any approved prefix allows arbitrary shell operators after the first segment. PH-02 shows that even commands nominally on the denylist are bypassed by quoting. Together: the denylist is the backstop that PH-01's approval bypass is supposed to rely on, but PH-02 shows the denylist itself fails. The two findings nullify each other's supposed safety net — there is no working defense layer.
Combined hypothesis: Once any bash prefix is session-approved, the LLM can execute any command including those on the denylist, by combining a prefix-matching first segment with a quoted denylist-pattern second command. The approved prefix defeats the approval gate; the quoting defeats the denylist. Both protections are simultaneously bypassed.
Test direction for causal-verifier: Construct `cat tools/file.go && r''m -rf /tmp/test_target`. Verify (a) IsDenied returns false, (b) extractBashPrefix returns `cat:tools/`, (c) if `cat:tools/` is in prefixes, IsAllowed returns true, (d) bash executes and deletes the test target.

---

## CROSS-02: Command Substitution in Path + Hierarchical Prefix Promotion

Source-A: PH-08 (contradiction-reasoner) — command substitution inside path arg bypasses approval
Source-B: PH-07 (contradiction-reasoner) — hierarchical prefix promotes single-file approval to directory wildcard
Connection: Both operate on the same `extractBashPrefix` function. PH-07 shows that approving `cat tools/file.go` grants approval for ALL commands of the form `cat tools/<anything>`. PH-08 shows that `<anything>` can be a command substitution that executes arbitrary code. Together: a single user approval of any `cat tools/<file>` command grants the LLM permanent unlimited code execution via `cat tools/$(arbitrary-shell-code)`.
Combined hypothesis: After a single session approval of any `cat tools/*` command, the LLM can execute arbitrary code by using command substitution as the path component, bypassing all future per-command approval gates permanently for the session.
Test direction for causal-verifier: (1) Store `cat:tools/` in prefixes. (2) Call `IsAllowed("bash", {"command": "cat tools/$(id > /tmp/probe_output)"})`. Verify it returns true. Verify bash executes the subshell. This is a pure code-path test, no user interaction needed.

---

## CROSS-03: ZipSlip Tarball + Approved Prefix for Persistence

Source-A: PH-05 (backward-reasoner) — ZipSlip via malicious npm tarball overwrites arbitrary files
Source-B: PH-01 (backward-reasoner) — shell metachar injection via approved prefix
Connection: PH-05 can write arbitrary files to the filesystem (e.g., `~/.bashrc`, `~/.zprofile`, `~/.profile`). PH-01 provides the RCE mechanism. Together: a supply-chain compromise of `@ollama/openclaw-web-search` that (a) writes a backdoor to `~/.bashrc` via ZipSlip provides persistent RCE that survives session termination. The `ensureWebSearchPlugin` function runs at every `ollama launch openclaw` invocation, so the malicious tarball is re-extracted on each launch.
Combined hypothesis: A compromised `@ollama/openclaw-web-search` npm package that includes tarball entries with `../` path traversal can overwrite `~/.bashrc` or `~/.profile` with attacker-controlled content on every `ollama launch openclaw` call, achieving persistent code execution that activates on the next shell login.
Test direction for causal-verifier: Craft a test tarball with entry `package/../../.bashrc_probe` containing `echo PWNED`. Run `tar xzf test.tgz --strip-components=1 -C /tmp/test_plugindir`. Verify `~/.bashrc_probe` is created in parent of `/tmp/test_plugindir`. This confirms the extraction path without needing a malicious npm package.

---

## CROSS-04: Yolo Mode + Denylist Quoting = Zero-Friction CRITICAL RCE

Source-A: PH-04 (backward-reasoner) — yolo mode bypasses all approval
Source-B: PH-02 (backward-reasoner) — denylist substring bypass via quoting
Connection: PH-04 shows yolo mode skips approval. The denylist (`IsDenied`) IS still checked in yolo mode (run.go:376-387 runs before the yolo branch at 400). However PH-02 shows the denylist fails against quoting. Combined: in yolo mode, the ONLY remaining protection is the denylist, and the denylist is bypassed by quoting. Result: zero defenses.
Combined hypothesis: With `--experimental-yolo`, any LLM-requested bash command executes without user interaction. Commands nominally blocked by the denylist (rm -rf, /etc/passwd, .ssh keys) execute via trivial bash quoting. The attack surface is: any model running with `--experimental-yolo` can perform arbitrary destructive/exfiltration operations with no user friction.
Test direction for causal-verifier: In yolo mode, verify that `r''m -rf /tmp/test_yolo_target` (a) returns false from IsDenied, (b) bypasses IsAllowed check entirely, (c) executes via bash.go:64 and deletes the target.
