import { authkitMiddleware } from '@workos-inc/authkit-nextjs';
import { jwtVerify } from 'jose';
import { NextRequest, NextResponse } from 'next/server';

const isStatic = process.env.NEXT_PUBLIC_BUILD_MODE === 'static';
const skipAuth = isStatic || process.env.VIGOLIUM_SKIP_AUTH === 'true';

const hasWorkOSKeys = !!(process.env.WORKOS_API_KEY && process.env.WORKOS_CLIENT_ID);

const ACCESS_COOKIE_NAME = 'vigolium-access-session';

function getAccessSecret(): Uint8Array {
  const secret =
    process.env.ACCESS_SESSION_SECRET || process.env.WORKOS_COOKIE_PASSWORD || '';
  return new TextEncoder().encode(secret);
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
