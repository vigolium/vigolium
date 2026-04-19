import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextRequest, NextResponse } from 'next/server';
import { checkAndDeductCredits } from '@/lib/billing';
import { resolveConvexUser, checkProjectAccessById, checkQuotaById, deductConvexCreditsById } from '@/lib/convex-billing';
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
  const forwardSearch = new URLSearchParams(req.nextUrl.search);
  const demoKeyParam = forwardSearch.get('demo_key');
  forwardSearch.delete('demo_key');
  target.search = forwardSearch.toString() ? `?${forwardSearch.toString()}` : '';

  let userEmail: string | null = null;
  let workosUserId: string | null = null;
  let isAccessCodeUser = false;
  let isDemoUser = false;

  if (!skipAuth) {
    if (demoKeyParam) {
      const result = validateDemoKey(demoKeyParam);
      if (result.valid && result.label) {
        userEmail = `demo-${result.label}@vigolium.com`;
        isDemoUser = true;
      } else {
        return NextResponse.json({ error: 'Invalid demo_key' }, { status: 401 });
      }
    }

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

    if (!isAccessCodeUser && !isDemoUser) {
      try {
        const session = await withAuth();
        if (session.user) {
          userEmail = session.user.email;
          workosUserId = session.user.id;
        }
      } catch {
        // WorkOS not configured
      }
    }
  }

  // Convex gates: resolve user once, reuse for project access + quota + credits
  let convexCreditsHandled = false;
  if (!skipAuth && !isDemoUser && !isAccessCodeUser && workosUserId) {
    let convexUser: Awaited<ReturnType<typeof resolveConvexUser>> = null;
    try {
      convexUser = await resolveConvexUser(workosUserId);
    } catch {
      // Convex not configured
    }

    if (convexUser) {
      const projectUuid = req.headers.get('x-project-uuid');
      if (projectUuid) {
        try {
          const access = await checkProjectAccessById(convexUser._id, convexUser.role, projectUuid);
          if (!access.hasAccess) {
            return NextResponse.json(
              { error: 'You do not have access to this project' },
              { status: 403 },
            );
          }
        } catch {
          // Convex query failed — fall through
        }
      }

      if (req.method === 'POST' && isGatedPath(apiPath)) {
        try {
          const quota = await checkQuotaById(convexUser._id);
          if (!quota.allowed) {
            return NextResponse.json(
              { error: quota.error || 'Daily scan limit reached' },
              { status: 429 },
            );
          }
        } catch {
          // Convex unavailable — skip quota
        }

        try {
          const result = await deductConvexCreditsById(convexUser._id, convexUser.status, apiPath);
          convexCreditsHandled = true;
          if (!result.allowed) {
            return NextResponse.json(
              { error: result.error, credits: result.remaining, cost: result.cost },
              { status: 402 },
            );
          }
        } catch {
          // Convex unavailable — fall through to Stripe
        }
      }
    }
  }

  // Stripe fallback for credit gate when Convex is unavailable
  if (!convexCreditsHandled && req.method === 'POST' && isGatedPath(apiPath) && !skipAuth && !isAccessCodeUser && !isDemoUser) {
    if (!userEmail || !workosUserId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    let result;
    try {
      result = await checkAndDeductCredits(workosUserId, apiPath);
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

  const headers = new Headers(req.headers);
  if (AUTH_API_KEY) {
    headers.set('Authorization', `Bearer ${AUTH_API_KEY}`);
  }
  if (userEmail) {
    headers.set('X-User-Email', userEmail);
  }
  headers.delete('host');
  headers.delete('origin');
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
