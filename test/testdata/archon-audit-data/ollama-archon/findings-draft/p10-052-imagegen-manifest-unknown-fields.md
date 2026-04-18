Phase: 10
Sequence: 052
Slug: imagegen-manifest-unknown-fields
Verdict: VALID
Rationale: x/imagegen manifest loading uses json.Unmarshal without DisallowUnknownFields on both the OCI manifest and config JSON blobs loaded from disk, enabling the same pre-positioning time-bomb pattern as p8-003 when imagegen config structs gain new executable fields.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-003-configv2-time-bomb-rce.md
Origin-Pattern: AP-003

## Summary

`x/imagegen/manifest/manifest.go` loads OCI-style manifests and config JSON from disk using bare `json.Unmarshal` with no `DisallowUnknownFields`. Both the manifest struct (`Manifest`) and the config reader (`ReadConfigJSON`) silently ignore unknown JSON fields. This is the same root cause as p8-003: an attacker pre-positioning fields in a stored blob that activate when the schema evolves to include executable fields.

The imagegen subsystem is actively under development (the package is under `x/` and the TODO in `transfer/transfer.go:7` explicitly states plans to integrate into the main server). New fields such as a `postProcessScript` or `preprocessCommand` added to imagegen config structs in a future version would silently activate on existing poisoned blobs.

Additionally, `x/imagegen/tokenizer/tokenizer.go` unmarshals multiple config files from blobs (`config.json`, `tokenizer_config.json`, `generation_config.json`, `special_tokens_map.json`) without strict parsing.

## Location

- `x/imagegen/manifest/manifest.go:60` -- `json.Unmarshal(data, &manifest)` -- no DisallowUnknownFields on Manifest struct
- `x/imagegen/manifest/manifest.go:151` -- `json.Unmarshal(data, v)` -- ReadConfigJSON passes arbitrary struct without strictness
- `x/imagegen/manifest/manifest.go:203,245,250` -- further bare Unmarshal calls on index/header/meta structs
- `x/imagegen/tokenizer/tokenizer.go:108,125,149,183,316,332,355,389` -- eight separate bare Unmarshal calls on config blobs

## Attacker Control

An attacker controlling a model on a public registry can inject arbitrary unknown JSON fields into manifest and config blobs. These fields are preserved verbatim in the blob store (content-addressed, raw bytes). When a future imagegen version adds executable config fields, they activate without any user action.

## Trust Boundary Crossed

Remote registry (attacker-controlled model blob) -> local blob store -> imagegen config parsing -> future code execution path.

## Impact

- Time-delayed supply-chain attack: unknown fields pre-positioned today activate on imagegen binary upgrade
- Same impact surface as p8-003 if any future imagegen config field triggers command execution or subprocess spawning
- The imagegen subsystem runs as a subprocess with full user privileges (x/imagegen/server.go serves HTTP locally)

## Evidence

1. `x/imagegen/manifest/manifest.go:60`: `json.Unmarshal(data, &manifest)` -- Manifest{SchemaVersion, MediaType, Config, Layers} -- any future field is pre-positionable
2. `x/imagegen/manifest/manifest.go:151`: `return json.Unmarshal(data, v)` -- caller supplies arbitrary struct, no decoder strictness
3. `x/imagegen/cmd/engine/main.go:253,273`: `json.Unmarshal(data, &index)` and `json.Unmarshal(data, &cfg)` -- model_index.json and config.json parsed without strictness
4. Go json.Unmarshal: silently ignores unknown fields (no opt-in DisallowUnknownFields)
5. Blob storage is content-addressed raw bytes -- unknown fields are preserved through round-trips
