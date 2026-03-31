# Variant Analysis for p7-042 (plugin-zip-symlink-traversal / AP-042)

**Origin finding:** security/findings-draft/p7-042-plugin-zip-symlink-traversal.md
**Pattern:** AP-042 — ZIP Symlink String-Only Path Check
**Search date:** 2026-03-20
**Variant analyst:** Phase 9 agent

---

## Search Strategy Applied

### 1. Registry-Driven Grep (AP-042 detection signature)
Searched for `filepath\.Rel.*filepath\.Clean.*filepath\.Join.*symlink` and `os\.Symlink` across the codebase.

### 2. Archive Extraction Path Survey
Searched for all uses of `archive/zip`, `archive/tar`, symlink creation (`os.Symlink`), and symlink validation patterns.

### 3. Provisioning File Import Check
Read `pkg/services/provisioning/dashboards/file_reader.go` and `pkg/services/provisioning/stubs.go` for path traversal protections.

### 4. Phase 7 Addendum Targets
Cross-referenced Chamber 3 findings; no additional archive surfaces identified.

---

## Candidate Evaluation

### Candidate A: `pkg/infra/fs/copy.go` — `CopyRecursive()` Unchecked Symlink Copy

**File:** `pkg/infra/fs/copy.go:147-154`
**Pattern:** `os.Readlink(srcPath)` result forwarded verbatim to `os.Symlink(link, dstPath)` with no containment check.
**Root cause match:** Symlink target is taken from an existing filesystem file without validating that the target stays within the destination directory tree. No `isSymlinkRelativeTo` equivalent, no `os.EvalSymlinks` check.
**Attacker control:** An attacker who can place a malicious symlink in the source directory (e.g., via a plugin that was already extracted) can cause `CopyRecursive` to replicate that symlink verbatim into the destination.
**Trust boundary:** TB5 (Plugin Boundary) — a plugin that has already been installed (bypassing the ZIP extraction check) can have symlinks pointing outside its directory; copying that plugin directory replicates the traversal.
**Blocking protection:** The original ZIP extraction check (`isSymlinkRelativeTo`) applies at extraction time, not at copy time. If the symlink was created by other means, `CopyRecursive` propagates it. This is a secondary surface, not a primary exploitation vector. Also, this function appears to be used for plugin copying/testing workflows, not production plugin loading.
**Verdict:** REJECTED (LOW severity — requires a prior foothold in the plugin directory; not a standalone bypass)

### Candidate B: Provisioning Dashboard File Import (`pkg/services/provisioning/dashboards/file_reader.go`)
**Pattern:** `resolveSymlink()` at line 437 calls `filepath.EvalSymlinks(path)` — correct OS-level resolution.
**Assessment:** Uses `os.EvalSymlinks` properly. Not vulnerable to the string-only anti-pattern.
**Verdict:** REJECTED (protected by os.EvalSymlinks)

---

## Confirmed Variants

None confirmed at MEDIUM or higher severity. The AP-042 pattern (string-only symlink check without os.EvalSymlinks) exists only in the originally confirmed location at `pkg/plugins/storage/fs.go:165-181`. The provisioning import path uses correct `os.EvalSymlinks` protection. The `infra/fs/copy.go` unchecked symlink replication requires a prior filesystem write primitive and does not independently cross a trust boundary at MEDIUM severity.

**Variants found: 0**
