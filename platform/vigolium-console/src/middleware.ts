import { authkitMiddleware } from '@workos-inc/authkit-nextjs';
import { NextRequest, NextResponse } from 'next/server';

const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';

const workosMiddleware = authkitMiddleware({
  middlewareAuth: {
    enabled: true,
    unauthenticatedPaths: ['/callback', '/api/billing/webhook'],
  },
});

export default function middleware(req: NextRequest) {
  if (skipAuth) {
    return NextResponse.next();
  }
  return workosMiddleware(req, {} as never);
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|vigolium-logo-minimal.png).*)'],
};
