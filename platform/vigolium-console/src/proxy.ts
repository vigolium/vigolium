import { authkitMiddleware } from '@workos-inc/authkit-nextjs';
import { NextRequest, NextResponse } from 'next/server';

const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';

const workosMiddleware = authkitMiddleware({
  middlewareAuth: {
    enabled: true,
    unauthenticatedPaths: ['/callback', '/api/billing/webhook', '/login', '/api/auth/signin', '/api/github/callback'],
  },
});

export default async function proxy(req: NextRequest) {
  if (skipAuth) {
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
  if (req.nextUrl.pathname === '/login' && response.status !== 307 && response.status !== 302) {
    return NextResponse.redirect(new URL('/', req.url));
  }

  return response;
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|vigolium-logo-minimal.png).*)'],
};
