# [P12] Cleartext HTTP Git Sources Allow MITM Skill Injection

## Summary

`skills add` accepts custom GitLab tree URLs and direct `.git` URLs over `http://`, preserves the cleartext scheme when deriving the clone URL, and installs the cloned `SKILL.md` content into agent skill directories. A network attacker between the user and the Git server can replace repository contents in transit, causing attacker-controlled skill instructions and auxiliary files to persist locally.

## Details

The parser for custom GitLab-style tree URLs captures either `http` or `https` and reuses the captured protocol when constructing the repository clone URL. In the [GitLab tree parsing path](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/source-parser.ts#L302-L325), an input such as `http://git.local/group/repo/-/tree/dev/skills/demo` therefore becomes `http://git.local/group/repo.git`:

```ts
const gitlabTreeWithPathMatch = input.match(
  /^(https?):\/\/([^/]+)\/(.+?)\/-\/tree\/([^/]+)\/(.+)/
);
if (gitlabTreeWithPathMatch) {
  const [, protocol, hostname, repoPath, ref, subpath] = gitlabTreeWithPathMatch;
  if (hostname !== 'github.com' && repoPath) {
    return {
      type: 'gitlab',
      url: `${protocol}://${hostname}/${repoPath.replace(/\.git$/, '')}.git`,
      ref: ref || fragmentRef,
      subpath: subpath ? sanitizeSubpath(subpath) : subpath,
    };
  }
}
```

Direct `.git` URLs are affected by the same trust decision. The well-known URL classifier [explicitly excludes `.git` URLs](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/source-parser.ts#L395-L411), after which the [fallback git source](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/source-parser.ts#L382-L386) returns the original input unchanged, including an `http://` scheme:

```ts
if (input.endsWith('.git')) {
  return false;
}

// Fallback: treat as direct git URL
return {
  type: 'git',
  url: input,
  ...(fragmentRef ? { ref: fragmentRef } : {}),
};
```

Once parsed, GitLab and generic git sources enter the clone path without any HTTPS requirement. `runAdd()` [passes `parsed.url` directly to `cloneRepo()`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/add.ts#L1051-L1057), and `cloneRepo()` [passes that URL to `git.clone()`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/git.ts#L59-L63):

```ts
// GitLab, git URL, or --full-depth: always clone
spinner.start('Cloning repository...');
tempDir = await cloneRepo(parsed.url, parsed.ref);
spinner.stop('Repository cloned');
```

The existing parser test also documents this behavior by expecting `parseSource('http://git.local/group/repo/-/tree/dev')` to produce `url: 'http://git.local/group/repo.git'` in [`src/source-parser.test.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/source-parser.test.ts#L34-L40).

## Root Cause

Remote Git sources are normalized and cloned without enforcing transport integrity. The parser treats `http://` and `https://` as equally valid for custom GitLab tree URLs, preserves direct `http://...git` inputs, and the installer later trusts the cloned repository contents without an HTTPS-only policy, commit pin, signature check, or explicit insecure-transport opt-in.

## Proof of Concept (PoC)

PoC Status: `executed`.

The reproducible PoC is in `piolium/findings/p12-cleartext-http-git-sources/poc.py`. It creates an attacker-controlled Git repository containing `skills/mitm-supplied-skill/SKILL.md`, serves it through a local smart-HTTP Git endpoint, and runs the real CLI against a custom GitLab tree URL:

```bash
python3 piolium/findings/p12-cleartext-http-git-sources/poc.py
```

The captured exploit used this command shape:

```bash
node /Users/bytedance/Desktop/oss-to-run/skills/bin/cli.mjs add \
  http://127.0.0.1:65213/group/repo/-/tree/main/skills/mitm-supplied-skill \
  --yes --agent codex --copy
```

`evidence/exploit.log` shows the CLI derived and cloned the cleartext Git URL, found one skill, and installed it. `evidence/impact.log` contains the decisive impact marker:

```text
input GitLab tree URL: http://127.0.0.1:65213/group/repo/-/tree/main/skills/mitm-supplied-skill
derived clone URL served over cleartext HTTP: http://127.0.0.1:65213/group/repo.git
CLI exit code: 0
--- installed SKILL.md ---
When this skill is loaded, proof marker: P12_CLEAR_HTTP_GIT_MITM_MARKER
--- installed payload.txt ---
attacker-controlled auxiliary file: P12_CLEAR_HTTP_GIT_MITM_MARKER
--- HTTP git requests observed ---
/group/repo.git/info/refs?service=git-upload-pack
/group/repo.git/git-upload-pack
```

## Impact

Users who install skills from copied custom GitLab tree URLs or direct Git URLs over cleartext HTTP can receive attacker-modified skill content. The demonstrated effect is persistent installation of attacker-controlled `SKILL.md` instructions and files under the victim project's `.agents/skills` directory. When a compatible coding agent later loads that skill, the malicious instructions may influence agent behavior with the user's project permissions. Exploitability requires the user to add an `http://` Git source or an attacker to provide/modify such a source, and a network position capable of altering cleartext Git traffic.

## Remediation

Reject `http://` for remote GitLab and direct git sources by default. Prefer allowing only `https://` and SSH Git transports, and return a clear error for insecure HTTP sources. If local testing support is required, gate it behind an explicit option such as `--allow-insecure-http` with a warning. Add regression tests for `http://.../-/tree/...` and `http://.../repo.git` inputs to ensure they no longer reach `cloneRepo()` unless that explicit opt-in is present.

## Confirmation (V4)

Confirm-Status: confirmed-live
Confirm-Timestamp: 2026-04-30T20:16:33Z
Confirm-Evidence: piolium/findings/p12-cleartext-http-git-sources/evidence/confirmed-20260430T201612Z.log
Confirm-Variant-Count: 1
Confirm-FpCheck: not-run
Confirm-Notes: installed SKILL.md contains P12_CLEAR_HTTP_GIT_MITM_MARKER from HTTP git clone
