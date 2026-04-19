import { authkitMiddleware } from '@workos-inc/authkit-nextjs';
import { jwtVerify } from 'jose';
import { NextRequest, NextResponse } from 'next/server';

const isStatic = process.env.NEXT_PUBLIC_BUILD_MODE === 'static';
const skipAuth = isStatic || process.env.VIGOLIUM_SKIP_AUTH === 'true';
const demoOnlyEnabled = process.env.VIGOLIUM_DEMO_ONLY === 'true';
const demoSkipAuth = demoOnlyEnabled && process.env.VIGOLIUM_DEMO_SKIP_AUTH === 'true';

const hasWorkOSKeys = !!(process.env.WORKOS_API_KEY && process.env.WORKOS_CLIENT_ID);

const ACCESS_COOKIE_NAME = 'vigolium-access-session';
const DEMO_COOKIE_NAME = 'vigolium-demo-session';

function getAccessSecret(): Uint8Array {
  const secret =
    process.env.ACCESS_SESSION_SECRET || process.env.WORKOS_COOKIE_PASSWORD || '';
  return new TextEncoder().encode(secret);
}

/** SHA-256 hex digest — Edge-safe (SubtleCrypto). */
async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Paths always exempt from the demo gate (entry points + static callbacks). */
const DEMO_ALLOW_LIST = new Set<string>([
  '/login',
  '/callback',
  '/unauthorized',
  '/api/config-check',
  '/api/billing/webhook',
  '/api/demo/login',
  '/api/demo/status',
  '/api/demo/logout',
]);

function isDemoAllowed(pathname: string): boolean {
  if (DEMO_ALLOW_LIST.has(pathname)) return true;
  if (pathname.startsWith('/showcases')) return true;
  return false;
}

// Only initialize WorkOS middleware when keys are present to avoid cryptic SDK errors
const workosMiddleware = hasWorkOSKeys
  ? authkitMiddleware({
      middlewareAuth: {
        enabled: true,
        unauthenticatedPaths: [
          '/callback',
          '/api/billing/webhook',
          '/login',
          '/api/auth/signin',
          '/api/auth/access-code',
          '/api/github/callback',
          '/api/config-check',
          '/unauthorized',
          '/showcases',
        ],
      },
    })
  : null;

export default async function proxy(req: NextRequest) {
  if (skipAuth) {
    return NextResponse.next();
  }

  // Allow config-check endpoint through without auth so the UI can detect missing config
  if (req.nextUrl.pathname === '/api/config-check' || req.nextUrl.pathname === '/api/config-check/') {
    return NextResponse.next();
  }

  // Allow showcases routes through without auth (key-gated server-side)
  if (req.nextUrl.pathname.startsWith('/showcases')) {
    return NextResponse.next();
  }

  // ── Demo mode gate ─────────────────────────────────────────────────
  // Strict URL-as-source-of-truth: every request must carry ?demo_key=<key>.
  // The cookie is only a validation cache (bound to sha256(key)) — it never
  // grants access when the URL param is missing.
  if (demoOnlyEnabled) {
    if (isDemoAllowed(req.nextUrl.pathname)) {
      return NextResponse.next();
    }

    const urlDemoKey = req.nextUrl.searchParams.get('demo_key');

    // Skip-auth mode: require user to pass through the login gate first
    if (!urlDemoKey && demoSkipAuth) {
      if (req.cookies.has('vigolium-demo-entered')) {
        return NextResponse.next();
      }
      const loginUrl = new URL('/login', req.url);
      return NextResponse.redirect(loginUrl);
    }

    // No param → always redirect to /login (no cookie fallback)
    if (!urlDemoKey) {
      const returnTo = req.nextUrl.pathname + req.nextUrl.search;
      const loginUrl = new URL('/login', req.url);
      if (returnTo && returnTo !== '/') {
        loginUrl.searchParams.set('return_to', returnTo);
      }
      return NextResponse.redirect(loginUrl);
    }

    // Param present → check validation cache cookie
    const demoCookie = req.cookies.get(DEMO_COOKIE_NAME);
    if (demoCookie?.value) {
      try {
        const { payload } = await jwtVerify(demoCookie.value, getAccessSecret());
        const cookieHash = typeof payload.keyHash === 'string' ? payload.keyHash : null;
        const urlHash = await sha256Hex(urlDemoKey);
        if (cookieHash && cookieHash === urlHash) {
          return NextResponse.next();
        }
      } catch {
        // invalid/expired — fall through to re-validation
      }
    }

    // Needs server-side validation — hand off to Node route, preserve param in return_to
    const loginUrl = new URL('/api/demo/login', req.url);
    loginUrl.searchParams.set('demo_key', urlDemoKey);
    loginUrl.searchParams.set('return_to', req.nextUrl.pathname + req.nextUrl.search);
    return NextResponse.redirect(loginUrl);
  }

  // Check for access-code session cookie — if valid, bypass WorkOS auth
  const accessCookie = req.cookies.get(ACCESS_COOKIE_NAME);
  if (accessCookie?.value) {
    try {
      await jwtVerify(accessCookie.value, getAccessSecret());
      // Valid access-code session — let the request through

      // Redirect authenticated access-code users away from /login
      if (req.nextUrl.pathname === '/login') {
        return NextResponse.redirect(new URL('/select-project', req.url));
      }

      return NextResponse.next();
    } catch {
      // Invalid/expired cookie — fall through to WorkOS or login redirect
    }
  }

  // If WorkOS keys are missing, redirect all page requests to login which will show the config error
  if (!workosMiddleware) {
    // Let API requests through so config-check and other endpoints can respond
    if (req.nextUrl.pathname.startsWith('/api/')) {
      return NextResponse.next();
    }
    // Redirect page requests to /login where the ConfigError will be shown
    if (req.nextUrl.pathname !== '/login') {
      return NextResponse.redirect(new URL('/login', req.url));
    }
    return NextResponse.next();
  }

  const response = await workosMiddleware(req, {} as never);
  if (!response) return NextResponse.next();

  // Intercept WorkOS auto-redirect and send to custom login page instead
  const location = response.headers.get('location');
  if (location && location.includes('workos.com')) {
    const returnTo = req.nextUrl.pathname + req.nextUrl.search;
    const loginUrl = new URL('/login', req.url);
    if (returnTo && returnTo !== '/') {
      loginUrl.searchParams.set('return_to', returnTo);
    }
    return NextResponse.redirect(loginUrl);
  }

  // Redirect authenticated users away from /login
  if (req.nextUrl.pathname === '/login' && req.cookies.has('wos-session')) {
    return NextResponse.redirect(new URL('/select-project', req.url));
  }

  return response;
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|vigolium-logo-minimal.png).*)'],
};
