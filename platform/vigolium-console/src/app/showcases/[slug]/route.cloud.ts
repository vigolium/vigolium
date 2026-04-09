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
    return new Response('Forbidden — invalid or missing view_key', { status: 403 });
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
