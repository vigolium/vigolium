import { NextRequest } from 'next/server';
import fs from 'fs';
import path from 'path';
import { buildPostHogSnippet } from '@/lib/posthogSnippet';
import { validateShowcaseKey } from '@/lib/showcaseKeys';

const POSTHOG_SNIPPET = buildPostHogSnippet({ capturePageview: false });

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ slug: string }> }
) {
  const { slug } = await params;

  const viewKey = req.nextUrl.searchParams.get('view_key');
  const result = validateShowcaseKey(viewKey);

  // No keys configured at all → hide the route entirely.
  if (result.reason === 'no_keys') {
    return new Response('Not Found', { status: 404 });
  }

  if (!result.valid) {
    return new Response(renderForbiddenPage(result.reason === 'expired'), {
      status: 403,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }

  // Sanitize slug: only allow alphanumeric, hyphens, underscores
  if (!/^[a-zA-Z0-9_-]+$/.test(slug)) {
    return new Response('Not Found', { status: 404 });
  }

  const filePath = path.join(process.cwd(), 'showcases', `${slug}.html`);

  if (!fs.existsSync(filePath)) {
    return new Response('Not Found', { status: 404 });
  }

  const html = fs.readFileSync(filePath, 'utf-8');
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

function renderForbiddenPage(expired = false): string {
  const headline = expired
    ? "This view key has expired"
    : "Oops — you're not supposed to peek in here";
  const body = expired
    ? `The <code>view_key</code> on your URL was valid, but it's past its expiry date.`
    : `This showcase report is behind a <code>view_key</code>, and the one on your URL doesn't match (or isn't there at all).`;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>View Key Required — Vigolium Showcases</title>
  ${POSTHOG_SNIPPET}
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { background: #f5f0e8; color: #2c2c2c; font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; }
    .card { max-width: 560px; width: 100%; background: #ebe6dd; border: 1px solid #d5cfc4; padding: 48px 40px; text-align: center; }
    .card img { height: 72px; width: 72px; border-radius: 12px; border: 1px solid rgba(232,123,53,0.4); margin-bottom: 20px; animation: logo-glow 3s ease-in-out infinite; }
    @keyframes logo-glow {
      0%, 100% { box-shadow: 0 0 12px rgba(232,123,53,0.25); }
      50% { box-shadow: 0 0 28px rgba(232,123,53,0.55), 0 0 48px rgba(232,123,53,0.20); }
    }
    .badge { display: block; width: fit-content; margin: 0 auto 16px; font-size: 11px; letter-spacing: 0.8px; text-transform: uppercase; color: #e87b35; border: 1px solid #e87b35; padding: 4px 12px; }
    h1 { font-size: 22px; margin-bottom: 14px; color: #2c2c2c; }
    p { font-size: 14px; line-height: 1.6; color: #6b6b6b; margin-bottom: 12px; }
    p.wink { color: #4a4a4a; }
    .actions { display: flex; gap: 12px; justify-content: center; margin-top: 24px; flex-wrap: wrap; }
    a.btn { display: inline-flex; align-items: center; gap: 8px; font-size: 13px; font-family: inherit; padding: 10px 20px; border: 1px solid #d5cfc4; background: #f5f0e8; color: #2c2c2c; text-decoration: none; }
    a.btn:hover { border-color: #a09888; background: #e2dcd2; }
    a.btn.primary { background: #e87b35; border-color: #e87b35; color: #fff; }
    a.btn.primary:hover { background: #d96b25; border-color: #d96b25; }
    .btn svg, .key-form button svg { width: 14px; height: 14px; flex-shrink: 0; }
    .key-form { margin-top: 24px; display: flex; gap: 0; justify-content: center; align-items: stretch; max-width: 420px; margin-left: auto; margin-right: auto; border: 1px solid #d5cfc4; background: #f5f0e8; }
    .key-form:focus-within { border-color: #e87b35; }
    .key-form input { flex: 1 1 auto; min-width: 0; font-family: inherit; font-size: 13px; padding: 10px 14px; border: 0; background: transparent; color: #2c2c2c; outline: none; }
    .key-form button { font-family: inherit; font-size: 13px; padding: 10px 20px; border: 0; background: #2c2c2c; color: #f5f0e8; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; gap: 8px; min-width: 96px; flex-shrink: 0; }
    .key-form button:hover { background: #1a1a1a; }
    .key-form button[disabled] { cursor: wait; opacity: 0.85; }
    .spinner { display: none; width: 12px; height: 12px; border: 2px solid rgba(245,240,232,0.3); border-top-color: #e87b35; border-radius: 50%; animation: spin 0.7s linear infinite; }
    .key-form.loading .spinner { display: inline-block; }
    .key-form.loading .lock-icon { display: none; }
    .key-form.loading .label { opacity: 0.7; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .meta { margin-top: 16px; font-size: 12px; color: #9a9080; }
    .meta a { color: #2c6fad; text-decoration: none; }
    .meta a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="card">
    <img src="/vigolium-logo-minimal.png" alt="Vigolium" />
    <div class="badge">403 &middot; Locked</div>
    <h1>${headline}</h1>
    <p class="wink">${body}</p>
    <p>If you'd like a proper tour of what Vigolium finds in real open-source projects, we'd love to walk you through it.</p>
    <div class="actions">
      <a class="btn primary" href="https://www.vigolium.com/request-demo" target="_blank" rel="noopener noreferrer" onclick="window.posthog&&window.posthog.capture('request_demo_clicked',{source:'showcases_403'})"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>Request a Demo</a>
      <a class="btn" href="mailto:contact@vigolium.com"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>Contact Us</a>
    </div>
    <form class="key-form" method="get" id="keyForm">
      <input type="text" name="view_key" placeholder="Paste your view_key" autocomplete="off" spellcheck="false" required />
      <button type="submit"><span class="spinner"></span><svg class="lock-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg><span class="label">Unlock</span></button>
    </form>
    <script>
      (function () {
        var f = document.getElementById('keyForm');
        if (!f) return;
        f.addEventListener('submit', function (e) {
          var input = f.querySelector('input[name="view_key"]');
          if (!input || !input.value.trim()) return;
          e.preventDefault();
          f.classList.add('loading');
          var btn = f.querySelector('button');
          if (btn) btn.disabled = true;
          setTimeout(function () {
            var u = new URL(window.location.href);
            u.searchParams.set('view_key', input.value.trim());
            window.location.href = u.toString();
          }, 600);
        });
      })();
    </script>
    <div class="meta">
      Or append <code>?view_key=YOUR_KEY</code> to the URL
    </div>
  </div>
</body>
</html>`;
}
