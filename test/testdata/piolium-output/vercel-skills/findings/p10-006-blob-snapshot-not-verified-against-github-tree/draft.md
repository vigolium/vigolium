---
id: p10-006
phase: P10
source-draft: p4-006
slug: blob-snapshot-not-verified-against-github-tree
severity: medium
verdict: VALID
debate: piolium/chamber-workspace/c04-skill-identity-and-snapshot/debate.md
---
PoC-Status: executed
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous


# Blob fast-path installs skills.sh snapshots without end-to-end GitHub verification

## Summary

For allowlisted GitHub owners, the blob fast path discovers `SKILL.md` paths and metadata via GitHub/raw, but installs file contents from `skills.sh/api/download`. The client does not verify those snapshot files against the resolved GitHub tree/ref before writing them to agent skill directories.

## Location

- GitHub tree/raw discovery: `src/blob.ts:84-123`, `src/blob.ts:249-265`.
- Snapshot fetch: `src/blob.ts:270-287`.
- Snapshot install write: `src/installer.ts:720-787`.
- Blob path selected for allowlisted owners in `src/add.ts:1018-1038`.

## Attacker Control

An attacker who compromises/misroutes the snapshot service, or controls local `SKILLS_DOWNLOAD_URL`, controls the installed snapshot body.

## Trust Boundary Crossed

Users believe they are installing from an allowlisted GitHub ref, but a separate snapshot service provides the actual installed files.

## Impact

Stale or malicious snapshot content can persist prompt/tool-use instructions that differ from the reviewed GitHub tree/ref.

## Evidence

Stage 02 characterized this as a trust relocation: path traversal is guarded, but content trust moved to `skills.sh`. Stage 04 found remote snapshot paths/content reaching `writeFile`; no hash comparison to GitHub blob contents exists.

## Stage 10 Notes

Owner allowlisting and fallback-on-failure reduce exposure, so severity is MEDIUM, but they do not verify snapshot integrity.

## Recommended Fix

Verify every snapshot file path and content hash against the resolved GitHub tree/blob API, pin verified hashes in lockfiles, or disable blob mode unless the user opts into trusting the snapshot service.
