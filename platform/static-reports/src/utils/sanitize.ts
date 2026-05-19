import DOMPurify from "dompurify";
import { marked } from "marked";

// escapeHtml returns the input with the five HTML metacharacters replaced by
// entity references. Use it before applying regex-based syntax highlighting to
// raw markdown so attacker-controlled `<` cannot survive into the DOM.
export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// sanitizeHtml strips script tags, event handlers, javascript:/data: URLs, and
// other XSS vectors from rendered markdown output before it is injected via
// dangerouslySetInnerHTML. Finding descriptions are operator-supplied markdown
// (e.g. archon audit reports) that may legitimately contain code fences with
// `<img>` examples — those survive because the HTML inside fences is already
// entity-escaped by marked. Raw inline `<script>`/`<img onerror>` payloads
// outside fences are converted to code snippets by the marked renderer below
// before reaching this sanitizer; this stage is defense in depth.
export function sanitizeHtml(html: string): string {
  return DOMPurify.sanitize(html, {
    USE_PROFILES: { html: true },
    FORBID_TAGS: ["style", "form", "iframe", "object", "embed", "base", "link"],
    FORBID_ATTR: ["style", "formaction"],
  });
}

// Override marked's `html` renderer so any raw HTML in a finding description
// renders as a code snippet instead of being interpreted by the browser. This
// keeps PoC payloads readable (e.g. `<img src=x onerror=...>` shows verbatim)
// and prevents HTML comments from swallowing surrounding text. Block-level
// HTML keeps newlines via <pre><code>; inline HTML uses inline <code>.
let markedConfigured = false;
function configureMarked(): void {
  if (markedConfigured) return;
  markedConfigured = true;
  marked.use({
    renderer: {
      html(token) {
        const t = token as { text?: string; raw?: string; block?: boolean };
        const escaped = escapeHtml(t.text ?? t.raw ?? "");
        return t.block
          ? `<pre><code class="md-raw-html">${escaped}</code></pre>`
          : `<code class="md-raw-html">${escaped}</code>`;
      },
    },
  });
}

configureMarked();
