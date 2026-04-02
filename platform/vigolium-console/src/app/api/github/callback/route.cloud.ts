import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextRequest, NextResponse } from 'next/server';
import { resolveOrgBilling } from '@/lib/billing';
import { exchangeCodeForToken, setAccessToken, DEV_TOKEN_COOKIE } from '@/lib/github';

function buildRedirect(req: NextRequest, fallbackPath: string): string {
  return req.cookies.get('github_oauth_redirect')?.value || fallbackPath;
}

function clearOAuthCookies(response: NextResponse): void {
  response.cookies.set('github_oauth_state', '', { maxAge: 0, path: '/' });
  response.cookies.set('github_oauth_redirect', '', { maxAge: 0, path: '/' });
}

export async function GET(req: NextRequest) {
  const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';
  const redirectTo = buildRedirect(req, '/settings/team');

  const code = req.nextUrl.searchParams.get('code');
  const state = req.nextUrl.searchParams.get('state');
  const storedState = req.cookies.get('github_oauth_state')?.value;

  // CSRF protection: verify state matches
  if (!state || !storedState || state !== storedState) {
    console.error('[github/callback] State mismatch', { state, storedState: storedState ? '(present)' : '(missing)' });
    const response = NextResponse.redirect(new URL(redirectTo, req.url));
    clearOAuthCookies(response);
    return response;
  }

  if (!code) {
    const response = NextResponse.redirect(new URL(redirectTo, req.url));
    clearOAuthCookies(response);
    return response;
  }

  if (skipAuth) {
    try {
      const accessToken = await exchangeCodeForToken(code);
      const response = NextResponse.redirect(new URL(redirectTo, req.url));
      response.cookies.set(DEV_TOKEN_COOKIE, accessToken, {
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
        maxAge: 60 * 60 * 24 * 30, // 30 days
      });
      clearOAuthCookies(response);
      return response;
    } catch (err) {
      console.error('[github/callback] Token exchange failed:', err);
      const response = NextResponse.redirect(new URL(redirectTo, req.url));
      clearOAuthCookies(response);
      return response;
    }
  }

  const session = await withAuth();
  if (!session.user) {
    const response = NextResponse.redirect(new URL(redirectTo, req.url));
    clearOAuthCookies(response);
    return response;
  }

  try {
    const accessToken = await exchangeCodeForToken(code);
    const billing = await resolveOrgBilling(session.user.id);
    if (!billing) {
      const response = NextResponse.redirect(new URL(redirectTo, req.url));
      clearOAuthCookies(response);
      return response;
    }
    await setAccessToken(billing.customerId, accessToken);

    const response = NextResponse.redirect(new URL(redirectTo, req.url));
    clearOAuthCookies(response);
    return response;
  } catch (err) {
    console.error('[github/callback] Token exchange failed:', err);
    const response = NextResponse.redirect(new URL(redirectTo, req.url));
    clearOAuthCookies(response);
    return response;
  }
}
