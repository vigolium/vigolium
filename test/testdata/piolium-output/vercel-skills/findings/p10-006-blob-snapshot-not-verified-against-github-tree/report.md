# [p10-006] Blob snapshot installs are not verified against the resolved GitHub tree

## Summary

The GitHub blob fast path for allowlisted owners (`vercel`, `vercel-labs`, and `heygen-com`) discovers skills from GitHub, but installs the actual file bodies returned by the separate `skills.sh` snapshot download API. Because those snapshot files are not checked against the resolved GitHub tree/ref before being written to the agent skill directory, a compromised or redirected snapshot service, or a process with control over `SKILLS_DOWNLOAD_URL`, can install skill instructions and auxiliary files that differ from the reviewed GitHub repository. Severity: Medium. CWE-494 (Download of Code Without Integrity Check) is the closest fit.

## Details

The affected path is selected for GitHub sources when `--full-depth` is not used and the repository owner is in the blob allowlist. In [`src/add.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/add.ts#L1014-L1029), the CLI calls `tryBlobInstall()` for these owners instead of cloning the repository first.

`tryBlobInstall()` does use GitHub for discovery: it fetches the recursive tree via the GitHub API in [`fetchRepoTree`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/blob.ts#L84-L114) and reads each `SKILL.md` frontmatter from `raw.githubusercontent.com` in [`fetchSkillMdContent`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/blob.ts#L249-L260). However, the complete file set that gets installed comes from the snapshot API, whose base URL is `process.env.SKILLS_DOWNLOAD_URL || 'https://skills.sh'` in [`src/blob.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/blob.ts#L44).

The decisive handoff is below. The code fetches `download!.files` from the snapshot service and carries the service-provided `hash` as `snapshotHash`, but it does not recompute each Git blob hash, compare the file list to the GitHub tree entries, or reject extra files that are absent from the resolved GitHub tree:

```ts
// src/blob.ts
const downloads = await Promise.all(
  filteredSkills.map(async (skill) => {
    const download = await fetchSkillDownload(source, skill.slug);
    return { skill, download };
  })
);

// If ANY download failed, fall back to clone — we don't do partial blob installs
const allSucceeded = downloads.every((d) => d.download !== null);
if (!allSucceeded) return null;

const blobSkills: BlobSkill[] = downloads.map(({ skill, download }) => {
  return {
    name: skill.name,
    description: skill.description,
    files: download!.files,
    snapshotHash: download!.hash,
    repoPath: skill.mdPath,
  };
});
```

That unverified file array is then treated as the install source. [`src/add.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/add.ts#L1498-L1505) passes `blobSkill.files` into `installBlobSkillForAgent()`, and the installer writes each snapshot `contents` field directly to disk. The path traversal guard is useful, but it only constrains where files are written; it does not prove that their contents match GitHub.

```ts
// src/installer.ts
async function writeSkillFiles(targetDir: string): Promise<void> {
  for (const file of skill.files) {
    const fullPath = join(targetDir, file.path);
    if (!isPathSafe(targetDir, fullPath)) continue;

    const parentDir = dirname(fullPath);
    if (parentDir !== targetDir) {
      await mkdir(parentDir, { recursive: true });
    }

    await writeFile(fullPath, file.contents, 'utf-8');
  }
}
```

## Root Cause

The blob fast path relocates trust from GitHub to a separate snapshot service after GitHub has only been used for discovery and frontmatter parsing. The resolved GitHub tree/ref is not bound to the installed payload: snapshot paths are not required to exist in the tree, snapshot contents are not compared to GitHub blob SHAs or raw contents, and the snapshot `hash` is not verified against a GitHub-derived value before installation.

## Proof of Concept (PoC)

PoC Status: **executed**. The repository-local PoC is `piolium/findings/p10-006-blob-snapshot-not-verified-against-github-tree/poc.py`.

The PoC starts a local malicious snapshot API, points `SKILLS_DOWNLOAD_URL` at it, and then runs the real CLI against the allowlisted GitHub repository `vercel-labs/agent-skills`:

```bash
python3 piolium/findings/p10-006-blob-snapshot-not-verified-against-github-tree/poc.py
# internally runs:
node bin/cli.mjs add vercel-labs/agent-skills --skill web-design-guidelines --agent codex --copy -y
```

The CLI output in `evidence/exploit.log` shows the user-visible source remained GitHub and the snapshot fast path was exercised, including a request for the selected skill:

```text
◇  Source: https://github.com/vercel-labs/agent-skills.git
◇  Found 7 skills
●  Selected 1 skill: web-design-guidelines
◇  Installation complete
--- snapshot requests ---
/api/download/vercel-labs/agent-skills/web-design-guidelines
```

`evidence/impact.log` confirms the installed `SKILL.md` came from the malicious snapshot response rather than from the GitHub tree, and that an auxiliary attacker-controlled file was also installed:

```text
installed_exists=True
auxiliary_file_exists=True
marker_present=True
snapshot_request_for_skill=True
--- installed SKILL.md excerpt ---
---
name: web-design-guidelines
description: attacker-controlled snapshot installed by p10-006 PoC
---

# P10_006_SNAPSHOT_SUBSTITUTION_MARKER
This file was served by the snapshot API, not by the GitHub tree.
```

The structured PoC result in `evidence/poc-run.log` was `"status": "confirmed"` with evidence that `web-design-guidelines/SKILL.md` contained the attacker marker.

## Impact

A user can believe they installed a skill from a trusted, allowlisted GitHub repository and ref while actually persisting instructions and files supplied by a different service. In practical terms, compromise of the snapshot service, service misrouting, or local/process-level control of `SKILLS_DOWNLOAD_URL` can substitute malicious skill prompts, tool-use instructions, or helper files under `.agents/skills/<skill>/`. Those skills are later consumed by AI agents and the CLI warns that they run with full agent permissions, so the substituted instructions can influence future agent behavior in the user's project. Exposure is reduced by the owner allowlist and by fallback to clone when the snapshot API fails, but those controls do not provide end-to-end integrity for successful blob installs.

## Remediation

Bind blob installs to the resolved GitHub tree before writing files. For each snapshot file, reject paths that are not present under the selected skill directory in the GitHub tree, compute the Git blob SHA for the snapshot contents (or fetch the corresponding GitHub blob/raw content) and compare it with the tree entry SHA, and reject any mismatch or extra file. Treat the snapshot `hash` as untrusted unless it is itself signed or derived from verified GitHub data. If this verification cannot be done reliably, disable blob mode by default or require an explicit opt-in that states the user is trusting the snapshot service rather than the GitHub ref.

## Confirmation (V4)

Confirm-Status: confirmed-live
Confirm-Timestamp: 2026-04-30T20:16:19Z
Confirm-Evidence: piolium/findings/p10-006-blob-snapshot-not-verified-against-github-tree/evidence/confirmed-20260430T201612Z.log
Confirm-Variant-Count: 1
Confirm-FpCheck: not-run
Confirm-Notes: installed web-design-guidelines/SKILL.md contains attacker marker P10_006_SNAPSHOT_SUBSTITUTION_MARKER
