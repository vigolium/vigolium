# CVE-2024-45436 — ZIP Slip Prevention Bypass Analysis

**Commit:** b7ce14c7  
**Advisory:** CVE-2024-45436  
**Cluster ID:** zip-slip-extraction  

## Patch Summary

The patch extracted ZIP file handling into `extractFromZipFile()` in `server/model.go`, adding a `strings.HasPrefix(n, p)` check where `n = filepath.Join(p, f.Name)`. Files whose resolved path does not start with the target directory prefix are skipped. The original vulnerable function (`parseFromZipFile`) was refactored to call this new safe extractor.

Note: In the current HEAD, `server/model.go` no longer contains `extractFromZipFile` or `parseFromZipFile` at all — the model import ZIP path appears to have been removed entirely in a later refactor.

## Bypass Verdict: **bypassable** (sibling paths)

## Evidence

### 1. Sibling ZIP extraction paths lack traversal checks

`app/updater/updater_darwin.go` contains **two** independent ZIP extraction loops (lines ~162 and ~283) that do NOT perform any path traversal validation:

- **Line 170:** `filepath.Join(BundlePath, name)` — no HasPrefix check
- **Line 189:** `filepath.Join(BundlePath, name)` — no HasPrefix check  
- **Line 285:** `filepath.Join(dir, f.Name)` — no HasPrefix check
- **Line 301:** `filepath.Join(dir, f.Name)` — no HasPrefix check

A malicious ZIP entry with `../../etc/cron.d/backdoor` as its name would write outside the target directory in both code paths.

**Mitigating factor:** The updater processes bundles downloaded from Ollama's update server and verifies code signatures (`verifyExtractedBundle`). Exploitation requires either compromising the update server or a MITM on the update download (if not pinned to HTTPS with certificate validation). The ZIP slip would execute before signature verification in the second extraction path (line 283), making it exploitable even with signature checks.

### 2. Original fix normalization analysis

The original fix in `server/model.go` used:
```go
n := filepath.Join(p, f.Name)
if !strings.HasPrefix(n, p) {
```

`filepath.Join` calls `filepath.Clean` internally, which resolves `..` components. So the check is applied **after** normalization — this is correct. However, there is a subtle bug: if `p` does not end with a path separator, a file named `<basename-of-p>-evil` in a sibling directory could match the prefix. For example, if `p = "/tmp/abc"`, a path resolving to `/tmp/abcdef` would pass the HasPrefix check. The standard safe pattern is `strings.HasPrefix(n, p + string(filepath.Separator))`. In practice this is unlikely exploitable here since `p` is a `MkdirTemp` result and the attacker-controlled name gets joined, but it is a correctness gap.

### 3. Symlink handling

The original `extractFromZipFile` fix does NOT check for symlink entries in the ZIP. A ZIP file could contain a symlink entry pointing to `../../` followed by a regular file targeting that symlink — achieving traversal via symlink-based indirection. The updater code does handle symlinks separately but only blocks absolute symlinks and obvious `..` prefixed links (line 332), missing cases where the resolved symlink target escapes after joining with a subdirectory.

### 4. Windows backslash differential

`filepath.Join` on Windows normalizes forward slashes to backslashes, but `strings.HasPrefix` operates on the result of `filepath.Join`, so this is consistent. Not bypassable via slash differentials on the same OS. Cross-platform is not a concern since the updater is darwin-only.

### 5. Config-gated checks

No configuration gates exist for the path validation. The fix is unconditional.

## Recommendations

1. Add `strings.HasPrefix` path traversal checks to both ZIP extraction loops in `app/updater/updater_darwin.go`.
2. Use `filepath.Clean(p) + string(filepath.Separator)` as the prefix to avoid the prefix-collision edge case.
3. Consider adding symlink target validation in ZIP extraction to prevent symlink-based traversal.
