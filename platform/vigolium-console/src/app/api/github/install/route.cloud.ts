import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
  const clientId = process.env.GITHUB_CLIENT_ID;
  if (!clientId) {
    return NextResponse.json({ error: 'GitHub OAuth not configured' }, { status: 500 });
  }

  const state = crypto.randomUUID();
  const redirectUri = new URL('/api/github/callback', req.url).toString();

  const authorizeUrl = new URL('https://github.com/login/oauth/authorize');
  authorizeUrl.searchParams.set('client_id', clientId);
  authorizeUrl.searchParams.set('scope', 'repo');
  authorizeUrl.searchParams.set('state', state);
  authorizeUrl.searchParams.set('redirect_uri', redirectUri);

  // Store the page the user came from so we can redirect back after OAuth
  const redirectAfter = req.nextUrl.searchParams.get('redirect') || '/settings/team';

  const response = NextResponse.redirect(authorizeUrl.toString());
  response.cookies.set('github_oauth_state', state, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 600, // 10 minutes
  });
  response.cookies.set('github_oauth_redirect', redirectAfter, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 600,
  });

  return response;
}
