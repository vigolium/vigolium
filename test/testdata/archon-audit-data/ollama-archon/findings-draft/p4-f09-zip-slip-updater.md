# p4-f09: ZIP Slip in Auto-Updater (updater_darwin.go) — Path Traversal Before Signature Verification

**Severity**: HIGH (MEDIUM if update server not compromised)
**CWE**: CWE-22 (Path Traversal)
**DFD Slice**: TB9 (Update Server -> Updater)
**CVE Pattern**: CVE-2024-45436 bypass — sibling paths unpatched

## Location

- `app/updater/updater_darwin.go:162-209`: First extraction loop — no `strings.HasPrefix` check
- `app/updater/updater_darwin.go:282-318`: Second extraction loop — no `strings.HasPrefix` check, extraction occurs BEFORE `verifyExtractedBundle` at line 340

## Description

Two independent ZIP extraction loops in `updater_darwin.go` lack path traversal validation:

**Loop 1 (line ~162):**
```go
name := s[1]  // ZIP entry name after stripping "Ollama.app/" prefix
destName := filepath.Join(BundlePath, name)  // No HasPrefix check
destFile, err := os.OpenFile(destName, ...)   // Writes to traversed path
```
A ZIP entry named `Ollama.app/../../Library/LaunchAgents/backdoor.plist` writes to `~/Library/LaunchAgents/backdoor.plist`.

**Loop 2 (line ~282):**
```go
destName := filepath.Join(dir, f.Name)  // No HasPrefix check
// ... file extraction ...
```
`verifyExtractedBundle` is called AFTER extraction (line 340), so a traversal-based write is permanent even if signature verification fails.

**Symlink Bypass:**
Both loops handle symlinks but only block absolute symlinks and symlinks starting with `..`. A symlink like `frameworks/link -> ../../.ssh/` (where the resolved path escapes through multiple hops) is not caught.

**The standard fix (HasPrefix check) present in the original `server/model.go` patch is absent here.**

## Attack Path

Compromise update server OR perform MITM on update download → serve malicious ZIP → files extracted outside app bundle before signature check.

## Evidence

- `app/updater/updater_darwin.go:170,189` — `filepath.Join(BundlePath, name)` without HasPrefix
- `app/updater/updater_darwin.go:285,301` — `filepath.Join(dir, f.Name)` without HasPrefix
- `app/updater/updater_darwin.go:340` — `verifyExtractedBundle` AFTER extraction in loop 2

---

## Phase 7 Enrichment Verdict

**Classification**: ENVIRONMENT — likely environment/deployment/admin-only (requires update server compromise or MITM)

**Attacker Control**: The attacker must control the content of the ZIP archive delivered via the update mechanism. This requires either: (a) compromising the Ollama update server (supply-chain position), or (b) a MITM attack on the update download (requires network position between victim and update server). Standard users with no network position cannot exploit this.

**Runtime**: The macOS auto-updater (`app/updater/updater_darwin.go`) — runs as the user who installed Ollama. Darwin-specific; not relevant to Linux/Windows deployments.

**Trust Boundary Crossed**: Update server-to-client trust boundary. The updater's signature verification (`verifyExtractedBundle`) is the intended trust enforcement mechanism, but the traversal occurs before verification in Loop 2.

**Effect**: Arbitrary file write with user privileges before signature check. Enables persistence (LaunchAgent plist), credential theft (.ssh/ overwrite), or library injection (Frameworks/ replacement). Impact is local-to-the-machine, same-user.

**CodeQL Reachability**: Code is on main branch, darwin-only. The ZIP extraction loops in `updater_darwin.go` are confirmed present without HasPrefix checks (verified via KB Phase 6 bypass analysis, which provides line numbers). The traversal path is direct and reachable during any update operation.

**KB Cross-Reference**: Phase 6 bypass analysis of CVE-2024-45436 (zip-slip-extraction cluster) explicitly identifies this as a bypass: the original patch in `server/model.go` (now removed) had the HasPrefix fix, but `updater_darwin.go` was never patched. The KB rates this as "bypassable (sibling paths)".

**Why ENVIRONMENT (not SECURITY at HIGH)**: The prerequisite — controlling the update server or MITMing the update download — represents a privileged network/supply-chain position. This is not an unauthenticated remote exploit; it requires the attacker to already be in a highly privileged position relative to the update infrastructure. However, the "extraction before signature" ordering in Loop 2 means even a detectable MITM attempt leaves malicious files on disk.

**Downgrade rationale**: This finding is retained (not dropped) because:
1. The "extraction before verification" ordering (Loop 2) means signature verification does NOT prevent the write.
2. If Ollama's update infrastructure is ever compromised, this is a zero-click persistence vector.
3. MITM on HTTP update URLs is feasible in hostile network environments (coffee shop, corporate proxy, etc.).

**Exploit Prerequisites**:
- Attacker controls the update server OR can MITM the update download channel
- Victim's Ollama app must be running and perform an auto-update check
- macOS only

**Revised Severity**: Downgrade from HIGH to MEDIUM given the elevated attacker prerequisites (supply-chain or MITM position required). Not dropped — remains security-relevant.

**Verdict**: KEEP — reclassified as MEDIUM security finding. The "before signature" write ordering is the critical issue; the fix must reorder to verify-then-extract, and add HasPrefix traversal checks to both loops.
