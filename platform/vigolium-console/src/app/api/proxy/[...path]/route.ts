import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextRequest, NextResponse } from 'next/server';
import { checkAndDeductCredits } from '@/lib/billing';

const SCAN_SERVER = process.env.VIGOLIUM_SCAN_SERVER || 'http://localhost:9002';
const AUTH_API_KEY = process.env.VIGOLIUM_AUTH_API_KEY || '';
const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';

/** Paths that cost credits (POST only). */
const GATED_PATHS = [
  '/api/scan-url',
  '/api/scan-request',
  '/api/scans/run',
  '/api/scan-all-records',
  '/api/scan-records',
  '/api/agent/run/',
];

function isGatedPath(path: string): boolean {
  return GATED_PATHS.some((p) => path === p || path.startsWith(p));
}

async function proxyRequest(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  const apiPath = `/${path.join('/')}`;
  const target = new URL(apiPath, SCAN_SERVER);
  target.search = req.nextUrl.search;

  // Credit gate: check and deduct credits for scan endpoints (POST only)
  if (req.method === 'POST' && isGatedPath(apiPath) && !skipAuth) {
    const session = await withAuth();
    if (!session.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const result = await checkAndDeductCredits(session.user.id, apiPath);
    if (!result.allowed) {
      return NextResponse.json(
        { error: result.error, credits: result.remaining, cost: result.cost },
        { status: 402 },
      );
    }
  }

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
