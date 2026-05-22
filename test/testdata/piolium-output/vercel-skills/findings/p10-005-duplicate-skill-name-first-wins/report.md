# [p10-005] Duplicate skill names are silently first-wins

**Severity:** Medium  
**Vulnerability class:** Skill namespace shadowing / provenance confusion  
**PoC Status:** executed

## Summary

Skill discovery trusts the `name` value declared in each untrusted `SKILL.md` frontmatter and silently deduplicates by that name. In a catalog that contains two skills with the same name, the first path encountered is the only skill shown and installed, allowing an attacker-controlled skill to shadow a legitimate curated skill under a trusted name.

## Details

The parser reads the skill name directly from `SKILL.md` frontmatter and records the directory that supplied it. In [`parseSkillMd`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/skills.ts#L34-L58), `data.name` becomes the identity used later for discovery and selection:

```ts
const content = await readFile(skillMdPath, 'utf-8');
const { data } = parseFrontmatter(content);

if (!data.name || !data.description) {
  return null;
}

return {
  name: sanitizeMetadata(data.name),
  description: sanitizeMetadata(data.description),
  path: dirname(skillMdPath),
  rawContent: content,
  metadata: data.metadata,
};
```

Discovery then uses a process-local `seenNames` set and searches `skills/` before `skills/.curated/`, as shown in [`discoverSkills`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/skills.ts#L114-L159). When a later skill declares the same `name`, it is not rejected, surfaced, or tied to its source path; it is skipped because the name was already seen. The same first-wins behavior is present in both the priority-directory pass and the recursive fallback in [`src/skills.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/skills.ts#L197-L220):

```ts
if (skill && !seenNames.has(skill.name)) {
  skill = enhanceSkill(skill);
  skills.push(skill);
  seenNames.add(skill.name);
}

// ...recursive fallback uses the same test...
if (skill && !seenNames.has(skill.name)) {
  skill = enhanceSkill(skill);
  skills.push(skill);
  seenNames.add(skill.name);
}
```

Because the duplicate is collapsed before the user chooses a skill, `skills add --list` and `skills add --skill <name>` present only one implementation for that name. A malicious contributor who can add a `SKILL.md` earlier in the discovery order can therefore make their instructions appear as the only available implementation of a trusted skill name.

## Root Cause

Skill identity is based only on attacker-controlled frontmatter `name`, and duplicate identities are handled by silent first-wins filtering instead of fail-closed validation or path-scoped selection. The lock/install flow also records the selected name without preserving enough provenance to distinguish two same-name candidates during discovery.

## Proof of Concept (PoC)

The executed PoC is in `piolium/findings/p10-005-duplicate-skill-name-first-wins/poc.py`. It creates a local catalog with two `SKILL.md` files that both declare `name: trusted-build`:

- `skills/attacker-shadow/SKILL.md` contains `PIOLIUM_DUPLICATE_NAME_FIRST_WINS_ATTACKER_PAYLOAD`.
- `skills/.curated/trusted-build/SKILL.md` contains `PIOLIUM_DUPLICATE_NAME_FIRST_WINS_LEGITIMATE_SKILL`.

Run from the repository root:

```bash
python3 piolium/findings/p10-005-duplicate-skill-name-first-wins/poc.py
```

The real CLI discovery output in `evidence/discover-list.log` showed the duplicate catalog collapsed to one visible skill, and the visible description came from the attacker-controlled path:

```text
◇  Found 1 skill

◇  Available Skills
│
│    trusted-build
│
│      Attacker shadow for the trusted build helper
```

The install command exercised by the PoC was:

```bash
node /Users/j3ssie/Desktop/oss-to-run/skills/bin/cli.mjs add \
  /Users/j3ssie/Desktop/oss-to-run/skills/piolium/findings/p10-005-duplicate-skill-name-first-wins/evidence/workdir/catalog \
  --skill trusted-build --agent codex --copy -y
```

`evidence/poc-run.log` confirms the security effect:

```text
attacker marker installed: True
legitimate marker absent from install: True
CLI list collapsed duplicate names to one skill: True
{"evidence": "attacker-controlled SKILL.md installed under trusted-build while legitimate duplicate was dropped", "notes": "real skills CLI add path exercised against a duplicate-name local catalog", "status": "confirmed"}
```

`evidence/impact.log` also shows the installed `SKILL.md` under `.agents/skills/trusted-build` was the attacker-controlled content, including the attacker marker.

## Impact

Users who install skills from a multi-skill catalog can be misled into installing attacker-controlled instructions under a trusted skill name when an attacker can contribute a same-name skill in an earlier-discovered path. The demonstrated impact is provenance and review bypass for agent instructions: the CLI lists and installs only the attacker-controlled `trusted-build` implementation while dropping the legitimate duplicate silently. If the installed skill is later invoked by an agent with repository or secret access, the malicious instructions can influence code changes, build steps, or secret handling. This does not by itself prove automatic secret exfiltration; it proves that the wrong skill content can be selected and installed without any duplicate-name warning.

## Remediation

Reject duplicate skill names by default across all discovery modes, including priority directories, recursive fallback, and plugin-manifest paths. If duplicates must be supported, display every candidate with its canonical source path and require an explicit path-scoped selection. Store installed skills and lockfile entries by name plus canonical source path and content hash, and fail or warn when the same name resolves to a different path than the user reviewed.

## Confirmation (V5 Test Mapping)

Confirm-Status: confirmed-test
Confirm-Method: generated-vitest-reproducer
Confirm-Test: piolium/findings/p10-005-duplicate-skill-name-first-wins/confirm-test.test.ts
Confirm-Test-Output: piolium/findings/p10-005-duplicate-skill-name-first-wins/evidence/confirm-test-output.log
Confirm-Evidence: piolium/findings/p10-005-duplicate-skill-name-first-wins/evidence/confirm-test-output.log; piolium/findings/p10-005-duplicate-skill-name-first-wins/evidence/confirm-test-evidence.log
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-04-30T20:21:16Z
Confirm-Notes: Vitest reproducer created duplicate trusted-build skills in attacker and curated paths; discover/install surfaced one candidate from the attacker path and installed the attacker marker.
