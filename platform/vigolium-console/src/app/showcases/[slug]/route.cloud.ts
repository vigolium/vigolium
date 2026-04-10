import { NextRequest } from 'next/server';
import fs from 'fs';
import path from 'path';

const SHOWCASES_KEY = process.env.VIGOLIUM_SHOWCASES_KEY || '';

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ slug: string }> }
) {
  const { slug } = await params;

  // Require a showcases key to be configured
  if (!SHOWCASES_KEY) {
    return new Response('Not Found', { status: 404 });
  }

  // Validate view_key
  const viewKey = req.nextUrl.searchParams.get('view_key');
  if (viewKey !== SHOWCASES_KEY) {
    return new Response(renderForbiddenPage(), {
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

function renderForbiddenPage(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>View Key Required — Vigolium Showcases</title>
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
    a.btn { display: inline-block; font-size: 13px; font-family: inherit; padding: 10px 20px; border: 1px solid #d5cfc4; background: #f5f0e8; color: #2c2c2c; text-decoration: none; }
    a.btn:hover { border-color: #a09888; background: #e2dcd2; }
    a.btn.primary { background: #e87b35; border-color: #e87b35; color: #fff; }
    a.btn.primary:hover { background: #d96b25; border-color: #d96b25; }
    .meta { margin-top: 24px; font-size: 12px; color: #9a9080; }
    .meta a { color: #2c6fad; text-decoration: none; }
    .meta a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="card">
    <img src="/vigolium-logo-minimal.png" alt="Vigolium" />
    <div class="badge">403 &middot; Locked</div>
    <h1>Oops — you're not supposed to peek in here</h1>
    <p class="wink">This showcase report is behind a <code>view_key</code>, and the one on your URL doesn't match (or isn't there at all).</p>
    <p>If you'd like a proper tour of what Vigolium finds in real open-source projects, we'd love to walk you through it.</p>
    <div class="actions">
      <a class="btn primary" href="https://www.vigolium.com/request-demo" target="_blank" rel="noopener noreferrer">Request a Demo</a>
      <a class="btn" href="mailto:contact@vigolium.com">Contact Us</a>
    </div>
    <div class="meta">
      Already have a key? Append <code>?view_key=YOUR_KEY</code> to the URL
    </div>
  </div>
</body>
</html>`;
}
