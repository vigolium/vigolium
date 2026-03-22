import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextRequest, NextResponse } from 'next/server';
import { resolveOrgBilling } from '@/lib/billing';
import { exchangeCodeForToken, setAccessToken } from '@/lib/github';

export async function GET(req: NextRequest) {
  const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';
  if (skipAuth) {
    return NextResponse.redirect(new URL('/team?github=skipped', req.url));
  }

  const code = req.nextUrl.searchParams.get('code');
  const state = req.nextUrl.searchParams.get('state');
  const storedState = req.cookies.get('github_oauth_state')?.value;

  // CSRF protection: verify state matches
  if (!state || !storedState || state !== storedState) {
    console.error('[github/callback] State mismatch', { state, storedState: storedState ? '(present)' : '(missing)' });
    return NextResponse.redirect(new URL('/team?github=error&reason=state', req.url));
  }

  if (!code) {
    return NextResponse.redirect(new URL('/team?github=error&reason=nocode', req.url));
  }

  const session = await withAuth();
  if (!session.user) {
    return NextResponse.redirect(new URL('/team?github=unauthorized', req.url));
  }

  try {
    const accessToken = await exchangeCodeForToken(code);
    const billing = await resolveOrgBilling(session.user.id);
    if (!billing) {
      return NextResponse.redirect(new URL('/team?github=error&reason=nobilling', req.url));
    }
    await setAccessToken(billing.customerId, accessToken);

    const response = NextResponse.redirect(new URL('/team?github=connected', req.url));
    // Clear the state cookie
    response.cookies.set('github_oauth_state', '', { maxAge: 0, path: '/' });
    return response;
  } catch (err) {
    console.error('[github/callback] Token exchange failed:', err);
    return NextResponse.redirect(new URL('/team?github=error&reason=exchange', req.url));
  }
}
