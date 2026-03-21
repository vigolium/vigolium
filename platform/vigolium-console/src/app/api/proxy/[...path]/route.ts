import { NextRequest, NextResponse } from 'next/server';

const SCAN_SERVER = process.env.VIGOLIUM_SCAN_SERVER || 'http://localhost:9002';
const AUTH_API_KEY = process.env.VIGOLIUM_AUTH_API_KEY || '';

async function proxyRequest(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  const target = new URL(`/${path.join('/')}`, SCAN_SERVER);
  target.search = req.nextUrl.search;

  const headers = new Headers(req.headers);
  // Inject server-side API key — never exposed to the browser
  if (AUTH_API_KEY) {
    headers.set('Authorization', `Bearer ${AUTH_API_KEY}`);
  }
  // Remove host/origin headers so the scan server sees its own
  headers.delete('host');
  headers.delete('origin');

  const res = await fetch(target.toString(), {
    method: req.method,
    headers,
    body: req.body,
    // @ts-expect-error -- Node fetch supports duplex for streaming bodies
    duplex: 'half',
  });

  const responseHeaders = new Headers(res.headers);
  responseHeaders.delete('transfer-encoding');

  return new NextResponse(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers: responseHeaders,
  });
}

export const GET = proxyRequest;
export const POST = proxyRequest;
export const PUT = proxyRequest;
export const DELETE = proxyRequest;
export const PATCH = proxyRequest;
