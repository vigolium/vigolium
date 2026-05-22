# [p10-004] Unbounded well-known fetch and frontmatter parsing can hang CLI discovery

## Summary

The well-known skills provider fetches attacker-controlled `index.json`, `SKILL.md`, and auxiliary files without explicit timeouts or response-size limits, then parses the entire `SKILL.md` YAML frontmatter without a size/depth guard. An anonymous malicious well-known host can keep a response open indefinitely or return oversized metadata/files, causing `skills add <url> --list -y` and similar noninteractive setup flows to hang or consume CPU/memory.

## Details

Well-known discovery first fetches the candidate index URL and reads it as JSON without an `AbortSignal` timeout or byte cap. The same implementation only validates the rough shape of `files` and path traversal, not the number of files or total bytes, before fetching skill content from the remote host.

The decisive path is in [`src/providers/wellknown.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/providers/wellknown.ts#L269-L305):

```ts
const skillMdUrl = `${skillBaseUrl}/SKILL.md`;
const response = await fetch(skillMdUrl);

if (!response.ok) {
  return null;
}

const content = await response.text();
const { data } = parseFrontmatter(content);

// Fetch remaining files in parallel
const otherFiles = entry.files.filter((f) => f.toLowerCase() !== 'skill.md');
const filePromises = otherFiles.map(async (filePath) => {
  try {
    const fileUrl = `${skillBaseUrl}/${filePath}`;
    const fileResponse = await fetch(fileUrl);
    if (fileResponse.ok) {
      const fileContent = await fileResponse.text();
      return { path: filePath, content: fileContent };
    }
```

This fully buffers `SKILL.md` via `response.text()`, immediately hands it to frontmatter parsing, and then fully buffers every auxiliary file listed by the untrusted index. The index fetch has the same unbounded pattern in [`fetchIndex`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/providers/wellknown.ts#L132-L140), and the file list validation only requires `files` to be a non-empty array and path-safe strings, with no maximum count, in [`isValidSkillEntry`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/providers/wellknown.ts#L180-L204).

After the body is buffered, [`parseFrontmatter`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/frontmatter.ts#L12-L15) applies an unbounded regex capture and YAML parse to remote content:

```ts
const match = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
if (!match) return { data: {}, content: raw };
const data = (parseYaml(match[1]!) as Record<string, unknown>) ?? {};
return { data, content: match[2] ?? '' };
```

## Root Cause

The well-known provider treats remote discovery content as trusted-sized input. It lacks defense-in-depth resource controls at every boundary: fetch deadlines, streaming byte limits, maximum index/auxiliary file counts, aggregate byte limits, and frontmatter/YAML complexity limits before parsing.

## Proof of Concept (PoC)

PoC status: **executed**. The reproduction script is `piolium/findings/p10-004-unbounded-well-known-fetch-and-frontmatter-parse/poc.js`. It starts a local malicious well-known server, then runs the real CLI against two attacker-controlled sources:

1. `/large/.well-known/agent-skills/index.json` advertises one skill whose `SKILL.md` contains 2 MiB of YAML frontmatter and eight 256 KiB auxiliary files.
2. `/stall/.well-known/agent-skills/hang-skill/SKILL.md` sends valid headers and a prefix, then never terminates the response body.

Run:

```bash
cd /Users/j3ssie/Desktop/oss-to-run/skills
node piolium/findings/p10-004-unbounded-well-known-fetch-and-frontmatter-parse/poc.js
```

The captured evidence shows the CLI fetched and processed attacker-controlled bytes, then remained alive until the PoC's external timeout killed the stalled request:

```text
large_run_confirmed=true
stall_run_confirmed=true
attacker_controlled_bytes_served=4194826
attacker_controlled_yaml_frontmatter_bytes=2097152
attacker_controlled_aux_files_fetched=8
stall_observation=CLI remained alive until external 3005ms timeout while response.text() waited for the attacker-controlled SKILL.md body to end
```

`evidence/exploit.log` also records the stalled run as `timedOut=true`, `signal=SIGKILL`, and `requested_SKILL.md=true`, confirming that the real CLI was waiting on the malicious `SKILL.md` body rather than rejecting it with an internal timeout.

## Impact

This is an availability issue. A malicious or compromised well-known host can slow, hang, or resource-exhaust developer setup, CI bootstrap, or project restore flows that run well-known discovery noninteractively. The demonstrated effect is a CLI hang and unbounded processing of attacker-supplied bytes; no code execution or data disclosure was observed. Because errors are generally caught and the primary consequence is denial of service in automation, medium severity is appropriate.

## Remediation

Apply explicit resource bounds before parsing or storing remote content:

- Pass `AbortSignal.timeout(...)` or equivalent cancellation to every well-known `fetch()`.
- Enforce per-response and aggregate byte limits while streaming `index.json`, `SKILL.md`, and auxiliary files instead of blindly using `response.text()`/`response.json()`.
- Cap `index.skills`, `entry.files`, concurrent fetches, and total fetched files/bytes.
- Reject frontmatter above a small configured size and configure/replace YAML parsing to limit nesting, aliases, and total nodes.
- Add regression tests for oversized indexes, oversized frontmatter, excessive file lists, and never-ending response bodies.

## Confirmation (V4)

Confirm-Status: confirmed-live
Confirm-Timestamp: 2026-04-30T20:16:17Z
Confirm-Evidence: piolium/findings/p10-004-unbounded-well-known-fetch-and-frontmatter-parse/evidence/confirmed-20260430T201612Z.log
Confirm-Variant-Count: 1
Confirm-FpCheck: not-run
Confirm-Notes: CLI hung on never-ending well-known SKILL.md body for 3005ms
