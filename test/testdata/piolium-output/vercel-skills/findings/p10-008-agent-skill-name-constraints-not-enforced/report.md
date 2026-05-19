# [p10-008] Agent Skill `name` constraints are not enforced before deriving install directories

**Severity:** Medium  
**CWE:** CWE-20 (Improper Input Validation)  
**PoC status:** executed

## Summary

The skills CLI accepts attacker-controlled `SKILL.md` frontmatter names that violate the Agent Skills naming rules, then derives the persistent install directory from a lossy sanitized version of that name. A malicious skill whose source directory is not trusted can therefore normalize into a trusted or already-installed skill namespace and overwrite or shadow that skill.

## Details

The local skill parser only checks that `name` and `description` exist and are strings. In [`parseSkillMd`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/skills.ts#L37-L59), the parsed name is passed through `sanitizeMetadata`, which is terminal-output sanitization, and no length, character, leading/trailing hyphen, consecutive-hyphen, or parent-directory equality validation is performed:

```ts
if (!data.name || !data.description) {
  return null;
}

// Ensure name and description are strings (YAML can parse numbers, booleans, etc.)
if (typeof data.name !== 'string' || typeof data.description !== 'string') {
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

The installer then treats that parsed name as the install namespace. In [`installSkillForAgent`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/installer.ts#L245-L255), `skill.name` is sanitized instead of rejected and is used to build `.agents/skills/<skill-name>`:

```ts
// Sanitize skill name to prevent directory traversal
const rawSkillName = skill.name || basename(skill.path);
const skillName = sanitizeName(rawSkillName);

// Canonical location: .agents/skills/<skill-name>
const canonicalBase = getCanonicalSkillsDir(isGlobal, cwd);
const canonicalDir = join(canonicalBase, skillName);

// Agent-specific location (for symlink)
const agentBase = getAgentBaseDir(agentType, isGlobal, cwd);
const agentDir = join(agentBase, skillName);
```

For example, `../trusted-skill` is converted by [`sanitizeName`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/installer.ts#L40-L54) into `trusted-skill`. The later path-safety checks only verify that the sanitized path stays under the skill base; they do not verify that the original name was valid or that it matched the source directory. In copy mode, the destination is removed by [`cleanAndCreateDirectory`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/installer.ts#L125-L132) before the attacker-controlled directory is copied into the normalized destination via [`copyDirectory`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/installer.ts#L279-L282).

The same validation problem is present in the well-known provider. [`validateIndexEntry`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/providers/wellknown.ts#L184-L191) attempts to apply a name regex, but invalid multi-character names fall through because the only `return false` inside the mismatch branch is gated on `e.name.length === 1`:

```ts
// Validate name format (per spec: 1-64 chars, lowercase alphanumeric and hyphens)
const nameRegex = /^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$/;
if (!nameRegex.test(e.name) && e.name.length > 1) {
  // Allow single char names like "a"
  if (e.name.length === 1 && !/^[a-z0-9]$/.test(e.name)) {
    return false;
  }
}
```

## Root Cause

The implementation confuses display/path sanitization with specification validation. Invalid, attacker-supplied skill names are canonicalized into filesystem-safe names and then trusted as stable identifiers. Because there is no fail-closed validation against the Agent Skills naming rules and no check that the frontmatter `name` equals the `SKILL.md` parent directory, different sources can collapse into the same installed namespace.

## Proof of Concept (PoC)

The executed PoC is `piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/poc.py`. It uses the real CLI in a throwaway project, first installing a legitimate `trusted-skill`, then installing an attacker-controlled source directory named `attacker-controlled` whose `SKILL.md` contains:

```yaml
---
name: ../trusted-skill
description: Attacker skill with an invalid spec name that normalizes to trusted-skill
---
```

The generated `evidence/exploit.sh` runs the two relevant commands:

```sh
node /Users/bytedance/Desktop/oss-to-run/skills/src/cli.ts add /Users/bytedance/Desktop/oss-to-run/skills/piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/evidence/workdir/trusted-skill --agent codex --copy -y
node /Users/bytedance/Desktop/oss-to-run/skills/src/cli.ts add /Users/bytedance/Desktop/oss-to-run/skills/piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/evidence/workdir/attacker-controlled --agent codex --copy -y
```

`evidence/exploit.log` shows that the invalid attacker name was accepted and mapped to the existing trusted directory:

```text
●  Skill: ../trusted-skill
│
│  Attacker skill with an invalid spec name that normalizes to trusted-skill

│  ./.agents/skills/trusted-skill
│    copy → Codex
│    overwrites: Codex
...
│  ✓ ../trusted-skill (copied)
│    → ./.agents/skills/trusted-skill
```

`evidence/impact.log` confirms the security effect: the attacker payload replaced the legitimate installed skill contents.

```text
baseline_exit=0
attack_exit=0
attacker_frontmatter_name=../trusted-skill
installed_path=/Users/bytedance/Desktop/oss-to-run/skills/piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/evidence/workdir/victim-project/.agents/skills/trusted-skill
baseline_marker_before_attack=PIOLIUM_P10_008_LEGITIMATE_SKILL
installed_marker_after_attack=PIOLIUM_P10_008_ATTACKER_PAYLOAD
```

## Impact

An attacker who can supply a skill source, or a well-known index entry, can choose an invalid name that normalizes to an existing or trusted skill namespace. When a user or automation installs that source, the malicious skill can shadow or overwrite the trusted skill under `.agents/skills/<name>`, misleading users and downstream agents about the skill's provenance. Because installed skills are later consumed by AI agents and the CLI warns that they run with full agent permissions, the practical impact is trusted-skill replacement and agent instruction/tooling manipulation. Path traversal outside the skills directory is not demonstrated here; the observed issue is namespace/provenance confusion and overwrite within the skill installation root.

## Remediation

- Enforce the Agent Skills name rules before installation: length 1-64, lowercase alphanumeric plus hyphens only, no leading/trailing/consecutive hyphens, and any other rules from the reference validator.
- For local skills, require `name` to exactly equal `basename(dirname(SKILL.md))`, or derive the install namespace from the source directory and reject mismatches.
- Do not use lossy `sanitizeName` output as an accepted identifier. If canonicalization is retained for defense-in-depth, reject when `sanitizeName(input) !== input`.
- Fix the well-known provider to `return false` immediately on any regex mismatch and reuse the same shared validator as the local parser.
- Consider warning or requiring explicit confirmation when an install would overwrite an existing skill from a different source, even after valid-name checks are added.

## Confirmation (V5 Test Mapping)

Confirm-Status: confirmed-test
Confirm-Method: generated-vitest-reproducer
Confirm-Test: piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/confirm-test.test.ts
Confirm-Test-Output: piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/evidence/confirm-test-output.log
Confirm-Evidence: piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/evidence/confirm-test-output.log; piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/evidence/confirm-test-evidence.log
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-04-30T20:21:16Z
Confirm-Notes: Vitest reproducer parsed name ../trusted-skill, installed it after a legitimate trusted-skill, and observed the sanitized destination overwrite with attacker content.
