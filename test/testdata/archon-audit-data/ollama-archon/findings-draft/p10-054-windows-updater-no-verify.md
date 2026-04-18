Phase: 10
Sequence: 054
Slug: windows-updater-no-verify
Verdict: VALID
Rationale: The Windows updater's verifyDownload() is a no-op stub returning nil unconditionally, so a downloaded update binary is executed as SYSTEM-level installer with no cryptographic integrity check, enabling MITM or server-compromise to deliver arbitrary executables.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-004-manifest-integrity-bypass.md
Origin-Pattern: AP-004

## Summary

`app/updater/updater_windows.go:186-188` implements `verifyDownload` as:

```go
func verifyDownload() error {
    return nil
}
```

This stub unconditionally passes verification. After `DownloadNewRelease` downloads the update binary from the URL provided by `https://ollama.com/api/update`, it calls `VerifyDownload()` (which is assigned this stub), and on success executes the binary as an installer (`exec.Command(runningInstaller, installArgs...)`).

By contrast, `updater_darwin.go` implements a real `verifyDownload` that extracts the ZIP into a temp directory and calls `verifyExtractedBundle` (macOS code-signing verification via Objective-C). Windows has no equivalent.

The update URL (`updateResp.UpdateURL`) is fetched from the Ollama update server over HTTPS but the binary itself has no hash pinned in the update response, no code-signing verification, and no checksum in the `Content-Digest` header verification. If the update server is compromised or a MITM is present on the download URL (which may redirect to a CDN), any binary can be delivered and executed.

## Location

- `app/updater/updater_windows.go:186-188` -- `verifyDownload()` returns nil always
- `app/updater/updater.go:234` -- `VerifyDownload()` called after download; result accepted; binary executed
- `app/updater/updater.go:126` -- `exec.Command(runningInstaller, installArgs...)` -- installer binary executed
- `app/updater/updater.go:123-133` -- `DownloadNewRelease`: URL comes from server response `updateResp.UpdateURL`

## Attacker Control

Two threat models:
1. **Server compromise**: Attacker compromises `ollama.com/api/update` endpoint and returns a URL pointing to a malicious binary. No verification stops it.
2. **MITM on download**: The download URL from the update response (a GitHub release URL or CDN URL) may be intercepted. No TLS pinning, no checksum verification.

Additionally, `Content-Disposition: filename` from the HTTP response is used unsanitized as the staged filename (line 184-187): a server-controlled `filename` containing `../` sequences would write the binary to an arbitrary path outside `UpdateStageDir`.

## Trust Boundary Crossed

Update server / network (partially trusted) -> local Windows filesystem -> arbitrary code execution with user privileges (installer runs with elevated permissions via Windows UAC).

## Impact

- Arbitrary binary execution with elevated installer privileges on Windows
- Supply-chain RCE: any Windows Ollama user with auto-update enabled is at risk if the update server or CDN is compromised
- `Content-Disposition` filename path traversal can write the binary to arbitrary filesystem locations before execution

## Evidence

1. `app/updater/updater_windows.go:186-188`: `func verifyDownload() error { return nil }` -- no-op stub
2. `app/updater/updater_darwin.go:264-343`: real `verifyDownload` with ZIP extraction and `verifyExtractedBundle` (code-signing check)
3. `app/updater/updater.go:234`: `if err := VerifyDownload(); err != nil { _ = os.Remove(stageFilename); return ... }` -- verification result gates execution, but Windows verification always succeeds
4. `app/updater/updater_windows.go:126`: `cmd := exec.Command(runningInstaller, installArgs...)` -- installer executed directly
5. `app/updater/updater.go:182-187`: `filename = params["filename"]` from Content-Disposition, then `filepath.Join(UpdateStageDir, etag, filename)` -- no path traversal sanitization on filename

## Reproduction Steps

1. MITM the HTTPS connection to `ollama.com/api/update` or the subsequent download URL
2. Return a JSON response pointing to a malicious `OllamaSetup.exe`
3. The Windows Ollama client downloads the binary, calls `verifyDownload()` (returns nil), marks `UpdateDownloaded = true`
4. On next startup or user action, `DoUpgrade` executes `runningInstaller` -- the malicious binary runs with elevated installer permissions
