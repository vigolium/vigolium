# [p12] Unbounded SKILL.md frontmatter parsing from git, local, and package sources

## Summary

This p12 variant of the earlier well-known frontmatter parsing issue lets an attacker-controlled skill repository, local checkout, or npm package provide a large or pathological `SKILL.md` YAML frontmatter block that the `skills` CLI reads and parses without byte, depth, or parser-resource limits. When a victim or CI job runs `skills add`/`skills experimental_sync` against that source, the local Node process can consume excessive memory/CPU and abort.

## Details

The vulnerable path starts when the CLI discovers a `SKILL.md` file from a cloned repository, a local path, or `node_modules`. The `skills add` implementation passes local paths directly into discovery and, for git/GitLab/full-depth or GitHub clone fallback sources, clones the repository and then calls `discoverSkills` on the clone; see the local-path branch in [`src/add.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/add.ts#L999-L1013) and the git clone branch in [`src/add.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/add.ts#L1039-L1058). The same parser is also reached by package sync because `experimental_sync` walks `node_modules` and calls `parseSkillMd` for package-root and nested skill files in [`src/sync.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/sync.ts#L46-L82).

Once discovery reaches a candidate skill file, [`parseSkillMd`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/skills.ts#L29-L35) reads the entire file into a UTF-8 string and immediately parses its frontmatter:

```ts
export async function parseSkillMd(
  skillMdPath: string,
  options?: { includeInternal?: boolean }
): Promise<Skill | null> {
  try {
    const content = await readFile(skillMdPath, 'utf-8');
    const { data } = parseFrontmatter(content);
```

The parser in [`src/frontmatter.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/frontmatter.ts#L8-L15) then applies an unbounded regular expression over the full string and hands the captured YAML document directly to `yaml.parse`:

```ts
export function parseFrontmatter(raw: string): {
  data: Record<string, unknown>;
  content: string;
} {
  const match = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
  if (!match) return { data: {}, content: raw };
  const data = (parseYaml(match[1]!) as Record<string, unknown>) ?? {};
  return { data, content: match[2] ?? '' };
}
```

There is no file-size check before `readFile`, no maximum frontmatter length before the regex/YAML parse, and no YAML resource policy such as depth, key-count, alias, or time limits. The `try/catch` in `parseSkillMd` can convert ordinary parser exceptions into `null`, but it cannot safely recover from V8 out-of-memory termination.

## Root Cause

The implementation treats skill metadata from untrusted repositories and packages as small, trusted local input. It performs full-file reads and unbounded YAML parsing before applying any resource guard, so attacker-controlled `SKILL.md` contents cross the repository/package trust boundary directly into a memory- and CPU-intensive parser. This is an uncontrolled resource consumption issue (CWE-400).

## Proof of Concept (PoC)

PoC status: **executed**. The executed PoC is stored at `piolium/findings/p12-unbounded-git-local-frontmatter-parse/poc.py`. It creates a malicious local git repository whose `SKILL.md` contains 500,000 YAML keys in an approximately 8.5 MiB frontmatter block, verifies that a benign repository works under the same 32 MiB V8 heap cap, and then runs:

```bash
NODE_OPTIONS=--max-old-space-size=32 \
SKILLS_CLONE_TIMEOUT_MS=30000 \
CI=1 \
node src/cli.ts add file://<malicious-repo> --list
```

The exploit log shows the real CLI cloning the attacker-controlled repository and then aborting during skill discovery/parsing:

```text
[exploit] payload_bytes=8500101
[exploit] path: parseSource(type=git) -> cloneRepo -> discoverSkills -> parseSkillMd -> parseFrontmatter
Repository cloned
FATAL ERROR: Ineffective mark-compacts near heap limit Allocation failed - JavaScript heap out of memory
[exploit] cli_exit=134
```

The decisive impact marker recorded in `evidence/impact.log` was:

```text
CONFIRMED: attacker-controlled git SKILL.md aborted the real skills CLI with V8 out-of-memory.
payload_bytes=8500101
node_options=--max-old-space-size=32
cli_exit=134
marker=FATAL ERROR: Ineffective mark-compacts near heap limit Allocation failed - JavaScript heap out of memory
```

## Impact

A malicious skill source can crash or hang noninteractive developer setup, bootstrap, restore, or CI flows that install or sync skills from untrusted git repositories, local checkouts, or npm dependencies. The demonstrated payload is small enough to live in a normal git repository and requires no authentication beyond convincing the victim workflow to process the source. The PoC used a constrained heap to make the abort deterministic; on default heaps, the same absence of limits still allows proportionally larger frontmatter payloads or deeply nested YAML to consume excessive local resources.

## Remediation

Add resource limits before parsing untrusted `SKILL.md` metadata. At minimum, reject or skip files above a conservative maximum size, parse only a bounded frontmatter prefix, cap YAML document size/depth/key/alias counts, and return a controlled validation error instead of continuing into an unbounded parser. Apply the guard in the shared `parseSkillMd`/`parseFrontmatter` path so git, local-path, well-known, and `node_modules` sync surfaces all receive the same protection, and add regression tests for oversized frontmatter from each source type.

## Confirmation (V5 Test Mapping)

Confirm-Status: confirmed-test
Confirm-Method: generated-vitest-reproducer
Confirm-Test: piolium/findings/p12-unbounded-git-local-frontmatter-parse/confirm-test.test.ts
Confirm-Test-Output: piolium/findings/p12-unbounded-git-local-frontmatter-parse/evidence/confirm-test-output.log
Confirm-Evidence: piolium/findings/p12-unbounded-git-local-frontmatter-parse/evidence/confirm-test-output.log; piolium/findings/p12-unbounded-git-local-frontmatter-parse/evidence/confirm-test-evidence.log
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-04-30T20:21:16Z
Confirm-Notes: Vitest reproducer ran the real CLI against a local SKILL.md with 500k frontmatter keys under NODE_OPTIONS=--max-old-space-size=32; the child process aborted with V8 heap out-of-memory stack trace.
