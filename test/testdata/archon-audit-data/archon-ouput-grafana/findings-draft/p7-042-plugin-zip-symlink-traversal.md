Phase: 7
Sequence: 042
Slug: plugin-zip-symlink-traversal
Verdict: VALID
Rationale: isSymlinkRelativeTo at fs.go:165-181 uses string-based filepath.Clean/filepath.Rel without os.EvalSymlinks, a known weakness in ZIP extraction security. Advocate's three-layer defense (ZipSlip + symlink check + admin-only) is strong and no concrete exploit was constructed. Valid as defense-in-depth finding due to the anti-pattern.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: check-4-ambiguous (admin-only access requirement)
Debate: security/chamber-workspace/chamber-3/debate.md

## Summary

During plugin ZIP extraction at `pkg/plugins/storage/fs.go`, symlink entries are validated by `isSymlinkRelativeTo()` (fs.go:165-181) which checks that the symlink target resolves within the plugin base directory. This function uses `filepath.Clean()` and `filepath.Rel()` for string-based path analysis but does NOT call `os.EvalSymlinks()` to resolve actual filesystem symlinks.

This means the function checks the LOGICAL path, not the resolved filesystem path. While the existing ZipSlip check at fs.go:91-97 independently validates file names, the combination of string-based symlink checking and sequential ZIP extraction creates a theoretical window where a multi-step symlink chain could bypass the checks. CodeQL's `go/unsafe-unzip-symlink` rule confirms this structural pattern.

No concrete exploit was demonstrated during the review, as the dual-layer checking (ZipSlip for file names + isSymlinkRelativeTo for symlink targets) covers the practical attack surface. This is classified as a defense-in-depth finding.

## Location

- **ZIP extraction loop:** `pkg/plugins/storage/fs.go:85-132`
- **ZipSlip check:** `pkg/plugins/storage/fs.go:91-97` -- string-based path validation for file names
- **Symlink extraction:** `pkg/plugins/storage/fs.go:121-127` -> `extractSymlink()` at fs.go:141-161
- **Symlink validation:** `pkg/plugins/storage/fs.go:165-181` -- `isSymlinkRelativeTo()` uses filepath.Clean/filepath.Rel, NOT os.EvalSymlinks
- **Symlink creation:** `pkg/plugins/storage/fs.go:157` -- `os.Symlink(symlinkPath, filePath)`

## Attacker Control

Grafana Server Admin with plugin installation permissions (`pluginaccesscontrol.ActionInstall`). The attacker controls the ZIP archive contents including file names, symlink targets, and extraction order.

## Trust Boundary Crossed

TB5 (Plugin Boundary) -> local filesystem. A successful traversal would allow the plugin to reference or read files outside the plugin installation directory, including server configuration files (grafana.ini, encryption keys, database credentials).

## Impact

Potential arbitrary file read from the Grafana server filesystem. Requires Grafana Server Admin privilege, limiting the threat to insider attacks or compromised admin accounts. Plugin signature verification provides an additional gate (unsigned plugins blocked by default).

## Evidence

1. `fs.go:165-181`: `isSymlinkRelativeTo` uses `filepath.Clean(filepath.Join(fileDir, symlinkDestPath))` and `filepath.Rel(basePath, cleanPath)` -- pure string operations, no filesystem resolution
2. `fs.go:157`: `os.Symlink(symlinkPath, filePath)` -- creates actual symlink on filesystem
3. CodeQL `go/unsafe-unzip-symlink` finding at fs.go:99 (SAST-009)
4. Missing: `os.EvalSymlinks()` call to resolve actual filesystem paths before comparison

## Reproduction Steps

1. Craft a plugin ZIP with entries in specific order:
   - Entry 1: symlink `plugin-name/link` -> `.` (within plugin dir, passes isSymlinkRelativeTo)
   - Entry 2: attempt regular file or symlink through the intermediate symlink
2. Install the plugin as Grafana Server Admin
3. Check if files were created outside the plugin directory
4. Note: no concrete exploit bypassing both ZipSlip and isSymlinkRelativeTo was demonstrated during the review; this requires further research on multi-step symlink resolution chains
