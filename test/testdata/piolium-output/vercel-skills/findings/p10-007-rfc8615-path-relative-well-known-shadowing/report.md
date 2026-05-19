# [p10-007] Path-relative `.well-known` discovery shadows origin-root RFC 8615 metadata

## Summary

The well-known skills provider treats a user-supplied URL path as part of the discovery scope and probes `{requested-path}/.well-known/...` before the origin-root `/.well-known/...` location defined by RFC 8615. On shared or trusted origins where an attacker controls only a path such as `/users/evil/`, the attacker can publish path-local well-known skill metadata and have it selected instead of the vetted origin-root skill index when a victim installs from that path.

## Details

RFC 8615 defines well-known resources under the origin-root `/.well-known/` prefix, but `WellKnownProvider.fetchIndex()` derives `basePath` from the full user-supplied URL and inserts a path-relative candidate before the root candidate. The vulnerable ordering is in [`src/providers/wellknown.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/providers/wellknown.ts#L101-L158):

```ts
const parsed = new URL(baseUrl);
const basePath = parsed.pathname.replace(/\/$/, ''); // Remove trailing slash

for (const wellKnownPath of this.WELL_KNOWN_PATHS) {
  // Path-relative: https://example.com/docs/.well-known/agent-skills/index.json
  urlsToTry.push({
    indexUrl: `${parsed.protocol}//${parsed.host}${basePath}/${wellKnownPath}/${this.INDEX_FILE}`,
    baseUrl: `${parsed.protocol}//${parsed.host}${basePath}`,
    wellKnownPath,
  });

  // Also try root if we have a path
  if (basePath && basePath !== '') {
    urlsToTry.push({
      indexUrl: `${parsed.protocol}//${parsed.host}/${wellKnownPath}/${this.INDEX_FILE}`,
      baseUrl: `${parsed.protocol}//${parsed.host}`,
      wellKnownPath,
    });
  }
}
```

The same method then returns the first structurally valid index it can fetch, before evaluating later candidates, including the origin-root index:

```ts
for (const { indexUrl, baseUrl: resolvedBase, wellKnownPath } of urlsToTry) {
  const response = await fetch(indexUrl);
  if (!response.ok) {
    continue;
  }

  const index = (await response.json()) as WellKnownIndex;
  // ...validate index structure and entries...
  if (allValid) {
    return { index, resolvedBaseUrl: resolvedBase, resolvedWellKnownPath: wellKnownPath };
  }
}
```

After `fetchIndex()` resolves the path-local base URL, skill files are fetched relative to that resolved base in [`fetchSkillByEntry()`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/providers/wellknown.ts#L245-L285), so the selected path-local index also controls the installed `SKILL.md` and auxiliary files.

## Root Cause

The implementation conflates a convenience extension for path-scoped discovery with RFC 8615 origin-root well-known discovery. Because the path-relative candidate is tried first and accepted on basic schema validity alone, path-scoped content can shadow origin-wide metadata on the same host. The trust decision is therefore based on the URL path supplied by the installer rather than the origin-root well-known namespace.

## Proof of Concept (PoC)

PoC-Status: executed.

The executed PoC is available at `piolium/findings/p10-007-rfc8615-path-relative-well-known-shadowing/poc.py`. It starts a local HTTP server that serves both:

1. a vetted origin-root index at `/.well-known/agent-skills/index.json` containing `trusted-root`; and
2. an attacker-controlled path-local index at `/users/evil/.well-known/agent-skills/index.json` containing `evil-shadow`.

It then runs the CLI against the path URL:

```bash
node src/cli.ts add http://127.0.0.1:64740/users/evil --agent codex --copy --yes
```

The exploit log shows that the CLI fetched only the path-local well-known resources during installation:

```text
--- HTTP requests observed during CLI install ---
/users/evil/.well-known/agent-skills/index.json
/users/evil/.well-known/agent-skills/evil-shadow/SKILL.md
/users/evil/.well-known/agent-skills/evil-shadow/payload.txt
```

The impact evidence confirms the root skill was not installed and that the attacker marker persisted in both installed files:

```text
origin_root_index=http://127.0.0.1:64740/.well-known/agent-skills/index.json
victim_input=http://127.0.0.1:64740/users/evil
attacker_path_index=http://127.0.0.1:64740/users/evil/.well-known/agent-skills/index.json
installed_root_skill_exists=False
attacker_marker_in_installed_skill=True
attacker_marker_in_auxiliary_file=True
```

The PoC runner returned a confirmed status:

```json
{"status": "confirmed", "evidence": "attacker path-local evil-shadow skill installed while origin-root trusted-root existed"}
```

## Impact

An attacker who can publish files under a path on a shared or otherwise trusted origin can cause victims installing from that path to receive attacker-controlled agent instructions and skill files, even when the origin root publishes different vetted well-known metadata. The installed skill runs with the normal permissions granted to the target agent, so the practical consequence is malicious or untrusted agent behavior under the apparent trust of the shared hostname. Exploitation requires a shared-origin/path-control setup and a victim installing from the attacker-controlled path, so this is best treated as Medium severity rather than a universal remote compromise.

## Remediation

Use origin-root well-known URLs for RFC 8615 discovery: for `https://example.com/users/evil`, resolve `https://example.com/.well-known/agent-skills/index.json` before, or instead of, any path-relative extension. If path-scoped discovery remains supported as a non-RFC extension, require explicit opt-in and present the exact resolved index URL and trust scope before installation so users can distinguish origin-root metadata from path-local content.

## Confirmation (V4)

Confirm-Status: confirmed-live
Confirm-Timestamp: 2026-04-30T20:16:20Z
Confirm-Evidence: piolium/findings/p10-007-rfc8615-path-relative-well-known-shadowing/evidence/confirmed-20260430T201612Z.log
Confirm-Variant-Count: 1
Confirm-FpCheck: not-run
Confirm-Notes: attacker path-local evil-shadow skill installed while origin-root trusted-root existed
