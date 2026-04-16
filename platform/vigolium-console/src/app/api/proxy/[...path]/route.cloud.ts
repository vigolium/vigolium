import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextRequest, NextResponse } from 'next/server';
import { checkAndDeductCredits } from '@/lib/billing';
import { verifyAccessSession, ACCESS_COOKIE_NAME } from '@/lib/access-session';
import { validateDemoKey } from '@/lib/demoKeys';

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
  // Copy query, but strip demo_key before forwarding to the Go backend.
  const forwardSearch = new URLSearchParams(req.nextUrl.search);
  const demoKeyParam = forwardSearch.get('demo_key');
  forwardSearch.delete('demo_key');
  target.search = forwardSearch.toString() ? `?${forwardSearch.toString()}` : '';

  // Resolve user email for X-User-Email header injection
  let userEmail: string | null = null;
  let isAccessCodeUser = false;
  let isDemoUser = false;

  if (!skipAuth) {
    // Check ?demo_key= query — strict URL source of truth
    if (demoKeyParam) {
      const result = validateDemoKey(demoKeyParam);
      if (result.valid && result.label) {
        userEmail = `demo-${result.label}@vigolium.com`;
        isDemoUser = true;
      } else {
        return NextResponse.json({ error: 'Invalid demo_key' }, { status: 401 });
      }
    }

    // Check access-code cookie next
    if (!isDemoUser) {
      const accessCookie = req.cookies.get(ACCESS_COOKIE_NAME);
      if (accessCookie?.value) {
        const payload = await verifyAccessSession(accessCookie.value);
        if (payload) {
          userEmail = payload.email;
          isAccessCodeUser = true;
        } else {
          return NextResponse.json({ error: 'Invalid access session' }, { status: 401 });
        }
      }
    }

    // Fall back to WorkOS session for email
    if (!isAccessCodeUser && !isDemoUser) {
      try {
        const session = await withAuth();
        if (session.user) {
          userEmail = session.user.email;
        }
      } catch {
        // WorkOS not configured — continue without email
      }
    }
  }

  // Credit gate: check and deduct credits for scan endpoints (POST only)
  if (req.method === 'POST' && isGatedPath(apiPath) && !skipAuth) {
    // Demo and access-code users bypass credit checks (unlimited/read-only)
    if (!isAccessCodeUser && !isDemoUser) {
      if (!userEmail) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
      }

      // WorkOS user — check credits
      let session;
      try {
        session = await withAuth();
      } catch {
        return NextResponse.json(
          { error: 'Authentication is not configured. Check WorkOS environment variables.' },
          { status: 503 },
        );
      }
      if (!session.user) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
      }

      let result;
      try {
        result = await checkAndDeductCredits(session.user.id, apiPath);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return NextResponse.json(
          { error: `Billing check failed: ${msg}` },
          { status: 503 },
        );
      }
      if (!result.allowed) {
        return NextResponse.json(
          { error: result.error, credits: result.remaining, cost: result.cost },
          { status: 402 },
        );
      }
    }
  }

  const headers = new Headers(req.headers);
  // Inject server-side API key — never exposed to the browser
  if (AUTH_API_KEY) {
    headers.set('Authorization', `Bearer ${AUTH_API_KEY}`);
  }
  // Inject user email for per-project access control on the Go backend
  if (userEmail) {
    headers.set('X-User-Email', userEmail);
  }
  // Remove host/origin headers so the scan server sees its own
  headers.delete('host');
  headers.delete('origin');
  // Strip WorkOS internal headers to avoid 431 (header too large) on the scan server
  headers.delete('x-workos-middleware');
  headers.delete('x-workos-session');
  headers.delete('x-redirect-uri');
  headers.delete('x-sign-up-paths');
  headers.delete('x-url');

  let res: Response;
  try {
    res = await fetch(target.toString(), {
      method: req.method,
      headers,
      body: req.body,
      // @ts-expect-error -- Node fetch supports duplex for streaming bodies
      duplex: 'half',
    });
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code
      ?? ((err as AggregateError)?.errors?.[0] as NodeJS.ErrnoException)?.code;
    if (code === 'ECONNREFUSED' || code === 'ENOTFOUND') {
      return NextResponse.json(
        { error: 'Scan server unavailable' },
        { status: 502 },
      );
    }
    throw err;
  }

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
