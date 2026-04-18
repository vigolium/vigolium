Phase: 10
Sequence: 055
Slug: updater-content-disposition-path-traversal
Verdict: VALID
Rationale: The auto-updater uses an unsanitized Content-Disposition filename from the update server HTTP response directly in filepath.Join, enabling a compromised server to write the downloaded binary to arbitrary filesystem paths outside the update staging directory.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p4-f09-zip-slip-updater.md
Origin-Pattern: AP-003

## Summary

`app/updater/updater.go:182-187` extracts the filename from the HTTP `Content-Disposition` response header and uses it directly in `filepath.Join(UpdateStageDir, etag, filename)` with no path traversal sanitization:

```go
_, params, err := mime.ParseMediaType(resp.Header.Get("content-disposition"))
if err == nil {
    filename = params["filename"]
}
stageFilename := filepath.Join(UpdateStageDir, etag, filename)
```

`filepath.Join` cleans `..` segments, but if `filename` is an absolute path (e.g., `/etc/cron.d/ollama` or `C:\Windows\System32\evil.exe`) `filepath.Join` on some Go versions joins it as a component. More practically, a filename like `../../.bashrc` or `../../../AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/evil.exe` traverses out of `UpdateStageDir`. The file is then written with `os.O_WRONLY|os.O_CREATE|os.O_TRUNC` and mode `0o755`.

This is a path traversal in the update download path analogous to the ZIP slip in p4-f09 (ZIP entry names not sanitized) -- here, it is the `Content-Disposition` filename that is not sanitized.

## Location

- `app/updater/updater.go:182-187` -- `filename = params["filename"]` then `filepath.Join(UpdateStageDir, etag, filename)` -- no sanitization
- `app/updater/updater.go:211` -- same join repeated after etag refresh
- `app/updater/updater.go:224` -- `os.OpenFile(stageFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)` -- file written to traversed path

## Attacker Control

A compromised `ollama.com` update server (or MITM) can set `Content-Disposition: attachment; filename=../../evil.exe` in the HEAD or GET response. The auto-updater parses the filename, joins it into the stage path without checking for traversal, and writes the full update binary payload to the resulting path.

## Trust Boundary Crossed

Update server (network) -> local filesystem arbitrary path write. On Windows, `UpdateStageDir` is under `%LOCALAPPDATA%\Ollama\updates_v2`; traversal can reach `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` for persistence.

## Impact

- Arbitrary file write to any path the current user can write
- On Windows: write a binary to the Startup folder for persistence/privilege escalation
- On macOS: write to `~/Library/LaunchAgents/` for persistence
- The written file receives permissions `0o755` (executable)
- Combined with p10-034 (Windows no-verify): the written binary is subsequently executed as installer

## Evidence

1. `app/updater/updater.go:182-184`: `_, params, err := mime.ParseMediaType(resp.Header.Get("content-disposition")); if err == nil { filename = params["filename"] }` -- server-controlled filename accepted without sanitization
2. `app/updater/updater.go:187`: `stageFilename := filepath.Join(UpdateStageDir, etag, filename)` -- filepath.Join does not prevent absolute path injection on Windows if filename starts with a drive letter or UNC path
3. `app/updater/updater.go:224`: `fp, err := os.OpenFile(stageFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)` -- file written to traversed path
4. No call to `filepath.Base(filename)` or path containment check present
5. Analogous to p4-f09: `updater_darwin.go` ZIP extraction does call `strings.SplitN(f.Name, "/", 2)` and checks for symlinks, but does not sanitize the final name component against `..`

## Reproduction Steps

1. Set up a MITM or compromised update server responding to `https://ollama.com/api/update`
2. Return an `UpdateResponse` with `url` pointing to an attacker-controlled server
3. Serve the malicious binary with `Content-Disposition: attachment; filename=../../../AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/evil.exe`
4. The Ollama updater writes the binary to the Startup folder with mode 0755
5. On next Windows login, `evil.exe` executes automatically
