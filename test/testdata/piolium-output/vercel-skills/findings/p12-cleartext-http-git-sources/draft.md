---
id: p12
slug: cleartext-http-git-sources
severity: info
---

Phase: 12
Sequence: 001
Slug: cleartext-http-git-sources
Verdict: VALID
Rationale: The same cleartext remote-skill trust failure from well-known installs also exists for custom GitLab and direct `.git` sources that are cloned over `http://` without an HTTPS requirement.
Severity-Original: MEDIUM
PoC-Status: executed
Protocol: http
Auth-Required: no
Auth-Roles-Required: anonymous
Origin-Finding: piolium/findings-draft/p10-003-http-well-known-skill-discovery.md
Origin-Pattern: AP-004

## Summary

Custom GitLab tree URLs and direct git URLs can remain `http://` through source parsing and are then cloned and installed like any other remote skill source. A network attacker between the victim and the cleartext Git server can modify the repository contents in transit, causing malicious `SKILL.md` instructions and auxiliary files to be installed into agent skill directories.

## Location

- `src/source-parser.ts:304-325` captures `(https?)` for arbitrary GitLab-style tree URLs and returns `${protocol}://${hostname}/... .git`, preserving `http://`.
- `src/source-parser.ts:394-405` excludes `.git` URLs from well-known handling, after which `src/source-parser.ts:382-386` falls back to `{ type: 'git', url: input }` for direct git URLs.
- `src/add.ts:1051-1056` sends GitLab and generic git sources to `cloneRepo(parsed.url, parsed.ref)`.
- `src/git.ts:59-62` passes that URL to `git.clone()`.

## Attacker Control

An attacker can provide a copied command such as `skills add http://git.local/group/repo/-/tree/dev/skills/demo` or `skills add http://host/repo.git`. A network attacker or malicious proxy controls the cleartext repository bytes returned to git.

## Trust Boundary Crossed

Unauthenticated network content crosses into the local clone, skill discovery, and persistent agent skill directories.

## Impact

MITM-modified skill instructions can persist into `.agents/skills` or global agent directories and later influence coding agents with project/user permissions.

## Evidence

- `src/source-parser.test.ts:34-40` explicitly expects `parseSource('http://git.local/group/repo/-/tree/dev')` to produce a `gitlab` source with an `http://git.local/... .git` clone URL.
- `piolium/tmp/p12-variant-proofs-output.txt` includes `http-custom-gitlab-source-remains-cleartext`, where parsing `http://git.local/group/repo/-/tree/dev/skills/demo` produced `url: "http://git.local/group/repo.git"` and `ref: "dev"`.
- The P12 Semgrep registry scan (`piolium/tmp/p12-semgrep-registry.json`) matched HTTP acceptance in `src/source-parser.ts` and the clone sink in `src/git.ts`.

## Reproduction Steps

1. Run `parseSource('http://git.local/group/repo/-/tree/dev/skills/demo')`.
2. Observe that the parsed source is `{ type: 'gitlab', url: 'http://git.local/group/repo.git', ref: 'dev', subpath: 'skills/demo' }`.
3. Run `skills add` with that source; `runAdd()` reaches the GitLab/generic clone branch and calls `cloneRepo()` with the cleartext URL.
