---
id: p8-041
title: Plugin Catalog Renders Remote Readme/Changelog via dangerouslySetInnerHTML Without Client-Side Sanitization
severity: MEDIUM
status: VALID
verdict: VALID
cluster: Data Isolation & Rendering
---

Phase: 8
Sequence: 041
Slug: plugin-readme-xss-no-sanitize
Verdict: VALID
Rationale: Plugin catalog renders remote GCOM readme and changelog content via dangerouslySetInnerHTML without DOMPurify or any client-side sanitization. While GCOM is Grafana-controlled and likely sanitizes server-side, the missing client-side sanitization is a defense-in-depth violation that creates a supply-chain XSS risk if GCOM is compromised or review is bypassed.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: check-4-ambiguous
Debate: security/chamber-workspace/chamber-3/debate.md

## Summary

The Grafana plugin catalog UI renders plugin README and changelog content from the GCOM (grafana.com) API directly into the DOM using React's `dangerouslySetInnerHTML` without any client-side sanitization (no DOMPurify, no xss library, no `sanitize()` call). While local plugin readmes are sanitized via `renderMarkdown()` -> `sanitizeTextPanelContent()`, remote content from GCOM bypasses this sanitization path entirely.

This creates a supply-chain XSS risk: if a malicious actor can inject unsanitized HTML through the GCOM API (via plugin submission review bypass, GCOM compromise, or MITM), it will execute in the browser of any Grafana user viewing that plugin's catalog page.

## Affected Code

### Missing Sanitization on Render
- **File**: `public/app/features/plugins/admin/components/PluginDetailsBody.tsx:57-59`
```typescript
dangerouslySetInnerHTML={{
    __html: plugin.details?.readme ?? 'No plugin help or readme markdown file was found',
}}
```

### Remote Data Path (No Sanitization)
- **File**: `public/app/features/plugins/admin/api.ts:50`
```typescript
readme: localReadme || remote?.readme,  // remote?.readme is unsanitized
```

### Changelog Same Pattern
- **File**: `public/app/features/plugins/admin/components/Changelog.tsx:15`
```typescript
dangerouslySetInnerHTML={{ __html: sanitizedHTML ?? 'No changelog was found' }}
// "sanitizedHTML" prop name is misleading -- no sanitization in this component
```

### Local Path IS Sanitized (for comparison)
- **File**: `public/app/features/plugins/admin/api.ts:172-173`
```typescript
const markdownAsHtml = markdown ? renderMarkdown(markdown) : '';
// renderMarkdown calls sanitizeTextPanelContent (xss library)
```

## Attack Path

1. Attacker submits a malicious plugin to grafana.com with XSS payload in README markdown
2. If the plugin passes review (or GCOM is compromised), the unsanitized HTML is stored in GCOM
3. Any Grafana admin browsing the plugin catalog triggers `getPluginDetails()` which fetches `remote?.readme`
4. Since the plugin is not installed locally, `localReadme` is empty, so `remote?.readme` is used
5. The unsanitized HTML is injected into the DOM via `dangerouslySetInnerHTML`
6. XSS payload executes in the admin's browser context (session cookies, API keys, etc.)

## Evidence

### api.ts Data Flow
```typescript
// api.ts:19-63
export async function getPluginDetails(id: string): Promise<CatalogPluginDetails> {
  const remote = await getRemotePlugin(id);  // from GCOM
  const [localPlugins, versions, localReadme, localChangelog] = await Promise.all([...]);
  return {
    readme: localReadme || remote?.readme,  // remote used if local is empty
    changelog: remote?.changelog || localChangelog,  // remote preferred
  };
}
```

### PluginDetailsBody.tsx Rendering
```typescript
// Line 57-59
<div
  className={styles.readme}
  dangerouslySetInnerHTML={{
    __html: plugin.details?.readme ?? 'No plugin help or readme markdown file was found',
  }}
/>
```

### Sanitization Available But Not Used
`@grafana/data` exports `sanitize()` (DOMPurify-based) and `sanitizeTextPanelContent()` (xss library-based), both of which are available but not used on the remote content path.

## Reproduction Steps

1. Identify a plugin in the GCOM catalog that is NOT installed locally on the Grafana instance
2. Navigate to the plugin's catalog page in the Grafana UI
3. Observe that `plugin.details?.readme` is rendered via `dangerouslySetInnerHTML`
4. If the GCOM API returns HTML containing `<img onerror=alert(1) src=x>`, it would execute
5. To verify the local path is safe: install a plugin locally and check that its readme is sanitized

**Defense context from Advocate**: The remote readme comes from GCOM, which is Grafana-controlled and likely performs server-side sanitization. This is a defense-in-depth gap rather than an immediately exploitable vulnerability.

## Severity Justification

- **MEDIUM** severity based on:
  - Supply-chain attack requires GCOM compromise or review bypass (not normal attacker position)
  - The `dangerouslySetInnerHTML` usage without sanitization violates secure coding principles
  - Impact is stored XSS in admin context, which would be HIGH if directly exploitable
  - Downgraded from HIGH because exploitation requires GCOM supply chain compromise
