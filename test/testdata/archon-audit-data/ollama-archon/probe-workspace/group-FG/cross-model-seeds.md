# Cross-Model Seeds

## CROSS-01: PH-01 + PH-09 — write-then-cache-hit chain for persistent weight substitution

Source-A: PH-01 (backward-reasoner) — digestToPath write, creates .tmp file at arbitrary path under ollama user
Source-B: PH-09 (contradiction-reasoner) — cache-hit size-match bypass, accepts pre-staged file without hash check
Connection: PH-01 writes attacker-chosen bytes to `<destDir>/sha256-<legit_digest>.tmp` (for blobs >= 64 MB). If the attacker's digest in PH-01 is chosen to match a legitimate blob digest (i.e., the attacker uses the real sha256 of the target payload as the path segment — but the hash check will fail because the content does not match the digest), then the `.tmp` file persists. The next pull attempt sees `fi.Size() == b.Size` (if the attacker controlled the size field in the manifest) and skips re-downloading, BUT the PH-01 path leaves only a `.tmp` file not the final blob path. However, PH-09 operates on the FINAL path (no `.tmp` suffix). The more direct chain: an attacker with any file write to the blob dir (from PH-01 creating directories with `os.MkdirAll(0o755)`) can then write a final file at the correct blob path via a separate mechanism.
Combined hypothesis: PH-01 establishes write capability into the blob directory tree including creating subdirectories. PH-09 establishes that any file at the correct path with the correct size is accepted without re-hashing. Together: attacker uses PH-01 to write a blob file (using a real sha256 of malicious content as the digest field, so the hash check actually PASSES and `os.Rename` to the final path DOES complete), then subsequent pulls accept it via PH-09.
Test direction for causal-verifier: Construct a manifest where `layer.Digest = sha256:<sha256-of-malicious-payload>` and the registry serves exactly `<malicious-payload>` bytes. Verify that `digestToPath` produces a valid-looking path (no colon → no traversal but within destDir), hash check passes, `os.Rename` succeeds, and PH-09 confirms the file is accepted on the next pull without re-download.

---

## CROSS-02: PH-02 + PH-04 — manifest traversal enables arbitrary file read via BlobPath

Source-A: PH-02 (backward-reasoner) — resolveManifestPath allows `..` in model name, reads arbitrary file as manifest
Source-B: PH-04 (backward-reasoner) — BlobPath uses digest from manifest without validation, enables arbitrary file read
Connection: PH-02 reads an arbitrary file as a manifest JSON. If the attacker can find a file at a reachable path that is valid JSON and contains a `layers` array with a `digest` field containing a traversal string, then PH-04 will use that digest to open another arbitrary file. This is a two-hop read gadget.
Combined hypothesis: Any JSON file on the filesystem accessible to the ollama user that can be interpreted as a partial manifest (Go's `json.Unmarshal` is forgiving of extra fields) with a crafted `digest` value enables a two-hop arbitrary file read chain: first hop reads the "manifest" JSON, second hop reads the target file via BlobPath.
Test direction for causal-verifier: Identify a JSON file on a typical Linux system (e.g., `/etc/machine-id` in JSON-adjacent formats, or any app config) that, when unmarshaled into the Manifest struct, produces a non-nil layers array with a digest containing `../`. Confirm the two-hop read completes without error.

---

## CROSS-03: PH-05 + PH-06 — key perm gap undermines auth replay attack surface

Source-A: PH-05 (backward-reasoner) — ed25519 key has no perm check; symlink or world-readable key accepted
Source-B: PH-06 (backward-reasoner) — client-side challenge lacks server nonce; timestamp-only replay window
Connection: PH-05 allows an attacker to control the signing key. PH-06 establishes that the challenge is client-constructed and contains no server nonce. If an attacker controls the signing key (via PH-05) AND can observe a valid Authorization header (e.g., via network sniffing on a plain HTTP connection to localhost, or reading from /proc on a shared host), they can replay that exact signature within the timestamp window OR generate new valid signatures for any challenge.
Combined hypothesis: Key compromise via PH-05 + nonce-free challenge via PH-06 = full signing oracle. An attacker who has read access to `~/.ollama/id_ed25519` (world-readable due to missing perm check) can sign arbitrary API requests for the duration of the key's validity, bypassing whatever OLLAMA_AUTH was meant to protect.
Test direction for causal-verifier: Verify (a) auth/auth.go:Sign() accepts a symlinked or 0o644-permissioned key file; (b) api/client.go challenge does NOT include a server-supplied nonce; (c) whether the server-side OLLAMA_AUTH verification validates the timestamp window strictly enough to limit replay.

---

## CROSS-04: PH-01 + PH-11 — arbitrary write enables manifest plant that triggers signinURL injection

Source-A: PH-01 (backward-reasoner) — arbitrary file write (`.tmp`) into any ollama-accessible path
Source-B: PH-11 (contradiction-reasoner) — SigninURL from server response is displayed verbatim by CLI
Connection: PH-01 can write bytes to a path that resolves to within the manifest directory (if `OLLAMA_MODELS/manifests/` is reachable from `OLLAMA_MODELS/blobs/` via `../`). If an attacker plants a crafted manifest JSON at a recognized path, subsequent model operations read it, and if the manifest causes the local server to return a 401 with a crafted `signin_url`, PH-11 delivers the phishing URL to the user.
Combined hypothesis: The write chain (PH-01) + serving modified manifest locally + server returning 401 with attacker `signin_url` (PH-11) creates a self-contained local phishing gadget: no outbound network access needed; the attacker only needs write access to the blob store (shared host scenario).
Test direction for causal-verifier: Confirm whether `os.MkdirAll(filepath.Dir(dest), 0o755)` in save() can create `../manifests/` subdirectory from the blobs directory. If yes, a `.tmp` file plant in the manifest directory is achievable.
