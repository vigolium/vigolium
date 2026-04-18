# Evidence Assessment — All Rounds

## PH-01: digestToPath arbitrary file write
- Evidence: `x/imagegen/transfer/transfer.go:165` — no validation in digestToPath
- Evidence: `x/imagegen/transfer/download.go:213-215` — os.MkdirAll + os.Create using unvalidated path
- Evidence: KB bypass analysis for CVE-2024-37032 — explicitly confirms this gap and the dispatch via pullWithTransfer
- Evidence: Mechanical path computation confirms escape from blobs dir with sufficient `../` repetitions
- Fragility: SOUND (not fragile — code path is deterministic, no race condition)
- Verdict: VALIDATED

## PH-02: resolveManifestPath traversal (x/imagegen/manifest)
- Evidence: `x/imagegen/manifest/manifest.go:71-97` — strings.Split + filepath.Join with no sanitization
- Evidence: `x/imagegen/manifest/manifest.go:52` — LoadManifest calls resolveManifestPath directly
- Fragility: SOUND
- Verdict: VALIDATED

## PH-03: loadModelConfig blob path escape via digest
- Evidence: `x/create/create.go:102-103` — strings.Replace + filepath.Join on manifest.Config.Digest
- Evidence: `x/create/create.go:157-159` — same pattern for layer.Digest in GetModelArchitecture
- Fragility: SOUND
- Verdict: VALIDATED

## PH-04: BlobPath read-side arbitrary file read
- Evidence: `x/imagegen/manifest/manifest.go:101-104` — BlobPath = strings.Replace + filepath.Join
- Evidence: callers at lines 141, 156, 240 all pass unvalidated digests to os.ReadFile / os.Open
- Fragility: SOUND
- Verdict: VALIDATED

## PH-05: ed25519 key perm check missing
- Evidence: `auth/auth.go:27-31` — os.ReadFile with no Lstat/mode check
- Evidence: `cmd/cmd.go:1840` — MkdirAll with 0o755 (confirmed in KB analysis)
- Evidence: KB bypass analysis H2/H3 for 64883e3c explicitly documents this gap
- Fragility: SOUND
- Verdict: VALIDATED

## PH-06: api/client.go getAuthorizationToken parity gap
- Evidence: `api/client.go:121` — challenge = method+path+ts (no nonce)
- Evidence: `server/auth.go:40-48` — challenge includes server-generated nonce + ts
- Fragility: FRAGILE — severity depends on server-side window enforcement (not readable in this group)
- Verdict: NEEDS-DEEPER

## PH-07: CreateSafetensorsModel modelDir traversal
- Evidence: `x/create/create.go:695-706` — os.ReadDir(modelDir) + filepath.Join(modelDir, entry.Name()) with no containment check
- Evidence: `x/create/client/create.go:119` — modelDir from Modelfile model: directive, no sanitization
- Fragility: SOUND
- Verdict: VALIDATED

## PH-08: tools/template.go findToolCallNode nil-Pipe
- Evidence: `tools/template.go:51-52` — n.Pipe.Cmds dereference without nil check
- Evidence: KB bypass analysis B3 for 1ed2881e explicitly identifies this gap
- Fragility: FRAGILE — requires a nil Pipe on an IfNode, which the stdlib parser does not produce for well-formed templates; requires hand-constructed AST or future code path
- Verdict: NEEDS-DEEPER

## PH-09: cache-hit size-match bypass
- Evidence: `x/imagegen/transfer/download.go:58` — fi.Size() == b.Size accepted without hash check
- Evidence: No call to any hash function on the pre-existing blob in this branch
- Fragility: SOUND
- Verdict: VALIDATED

## PH-10: OLLAMA_MODELS env injection
- Evidence: `envconfig/config.go:113-124` — Var("OLLAMA_MODELS") with no path validation
- Evidence: All blob/manifest path builders derive from Models()
- Fragility: SOUND (requires env control which is a precondition, not an internal assumption)
- Verdict: VALIDATED

## PH-11: SigninURL injection
- Evidence: `api/client.go:222-243` — signin_url extracted from JSON without host validation
- Evidence: KB bypass analysis H6/M14 for 64883e3c explicitly confirms
- Fragility: SOUND
- Verdict: VALIDATED

## PH-12: mlx runner subprocess model name
- Evidence: `x/imagegen/server.go:116` — s.modelName passed as exec.Command arg without path validation
- Fragility: FRAGILE — individual args don't cause shell injection; impact depends on mlx runner behavior which is a subprocess (binary not read in this probe)
- Verdict: NEEDS-DEEPER

## PH-13: upload path traversal
- Evidence: `x/imagegen/transfer/upload.go:181` — digestToPath + filepath.Join with no validation
- Fragility: SOUND
- Verdict: VALIDATED

## PH-17: x/create/create.go resolveManifestPath (second copy)
- Evidence: `x/create/create.go:52-74` — identical pattern to PH-02, independent copy
- Evidence: Called from IsSafetensorsModel, IsImageGenModel, IsSafetensorsLLMModel — all public
- Fragility: SOUND
- Verdict: VALIDATED

## PH-18: Precise path traversal to /etc/cron.d
- Evidence: Mechanical computation shows 6 `../` (root home) or 8 `../` (system ollama user home) escapes to /etc
- Evidence: `download.go:215` — os.MkdirAll creates all intermediate directories with 0o755
- Evidence: `download.go:258` — hash mismatch removes .tmp for digest mismatch; but for blobs>=64MB, CROSS-01 shows a workaround
- Fragility: SOUND — path calculation is deterministic given a known OLLAMA_MODELS location
- Verdict: VALIDATED — CRITICAL

## PH-19: pullWithTransfer dispatch flips ALL layers to unsafe path
- Evidence: KB bypass analysis confirms hasTensorLayers() gate
- Evidence: `server/images.go:710-718` and `721-793` — one tensor layer flips entire manifest
- Fragility: SOUND
- Verdict: VALIDATED

## PH-20: key file accepted regardless of permissions
- Evidence: `auth/auth.go:27` — os.ReadFile follows symlinks
- Evidence: No Lstat, no mode check anywhere in auth package
- Fragility: SOUND
- Verdict: VALIDATED

## PH-21: client challenge no server nonce
- Evidence: `api/client.go:121` — challenge construction
- Evidence: `server/auth.go:40-48` — server-side registry auth uses nonce
- Fragility: FRAGILE — actual exploitability requires determining if server-side OLLAMA_AUTH verification is strict; server verification code path not fully traced
- Verdict: NEEDS-DEEPER

## PH-22: upload arbitrary file read exfiltration
- Evidence: `x/imagegen/transfer/upload.go:181` — os.Open on digestToPath output
- Fragility: SOUND
- Verdict: VALIDATED

## PH-23: CreateSafetensorsModel modelDir file read
- Evidence: `x/create/create.go:695` — os.ReadDir(modelDir), `x/create/create.go:706` — filepath.Join(modelDir, entry.Name())
- Fragility: SOUND
- Verdict: VALIDATED
