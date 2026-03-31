Phase: 10
Sequence: 058
Slug: panel-description-xss-no-dompurify
Verdict: FALSE_POSITIVE
Rationale: PanelHeaderCorner renders panel.description via renderMarkdown which calls sanitizeTextPanelContent (xss library); the sanitizer is applied before dangerouslySetInnerHTML, and panel descriptions are created by editors/admins who are already trusted to modify dashboard content — this is not a trust boundary crossing that constitutes a security vulnerability in Grafana's threat model.
Severity-Original: N/A
PoC-Status: N/A
Origin-Finding: security/findings-draft/p8-044-plugin-readme-xss-no-sanitization.md
Origin-Pattern: AP-044

## Summary

`PanelHeaderCorner.tsx:51` renders `panel.description` via `renderMarkdown()` and passes the result to `dangerouslySetInnerHTML`. Panel descriptions are saved by authenticated users with Editor or Admin roles. The `renderMarkdown` function applies `sanitizeTextPanelContent` (xss library) sanitization before rendering. Unlike the plugin readme pattern (p8-044), this content originates from within the same Grafana instance by authenticated, privileged users — not from an external supply-chain source. There is no external attacker-controlled path: an attacker who can set a panel description already has Editor-level access, making any XSS self-contained within their own privilege level.

## Location

- `public/app/features/dashboard/components/PanelEditor/PanelHeaderCorner.tsx:46-51`
- Panel description stored in dashboard JSON, editable by users with Editor role or above

## Attacker Control

Limited to users with Editor role or above, who are already trusted to modify dashboards. No external/unauthenticated path to panel descriptions exists.

## Trust Boundary Crossed

None across a meaningful trust boundary — Editor-role users are expected to create content shown to other users.

## Impact

N/A for the core threat model (editors trusted with content creation).

## Evidence

1. `PanelHeaderCorner.tsx:46`: `const markedInterpolatedMarkdown = renderMarkdown(interpolatedMarkdown)` -- sanitizer applied
2. `markdown.ts:44-45`: `renderMarkdown` calls `sanitizeTextPanelContent(html)` -- xss library filters applied
3. Content source is the panel model's `description` field, set by authenticated editors

## Reproduction Steps

N/A — not exploitable via external attacker-controlled path.
