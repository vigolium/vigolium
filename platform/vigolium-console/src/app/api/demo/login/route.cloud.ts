import { NextRequest, NextResponse } from 'next/server';
import { validateDemoKey, isDemoOnlyEnabled } from '@/lib/demoKeys';
import {
  createDemoSession,
  demoCookieOptions,
  hashDemoKey,
  DEMO_COOKIE_NAME,
} from '@/lib/demo-session';

export async function GET(req: NextRequest) {
  const demoKey = req.nextUrl.searchParams.get('demo_key');
  const returnTo = req.nextUrl.searchParams.get('return_to') || '/';

  const safeReturn = returnTo.startsWith('/') && !returnTo.startsWith('//') ? returnTo : '/';
  const redirectTarget = new URL(safeReturn, req.url);

  if (!isDemoOnlyEnabled()) {
    return NextResponse.redirect(redirectTarget);
  }

  const result = validateDemoKey(demoKey);
  if (!result.valid || !result.label || !demoKey) {
    const loginUrl = new URL('/login', req.url);
    // Strip demo_key from return_to on failure so /login renders the unlock page
    const cleanReturn = stripDemoKey(safeReturn);
    if (cleanReturn && cleanReturn !== '/') {
      loginUrl.searchParams.set('return_to', cleanReturn);
    }
    loginUrl.searchParams.set(
      'demo_error',
      result.reason === 'expired' ? 'expired' : 'invalid',
    );
    return NextResponse.redirect(loginUrl);
  }

  // Ensure demo_key is preserved in the final URL so nav/share keep it
  if (!redirectTarget.searchParams.has('demo_key')) {
    redirectTarget.searchParams.set('demo_key', demoKey);
  }

  const keyHash = await hashDemoKey(demoKey);
  const { token, maxAge } = await createDemoSession(result.label, keyHash, result.expires);
  const res = NextResponse.redirect(redirectTarget);
  res.cookies.set(DEMO_COOKIE_NAME, token, demoCookieOptions(maxAge));
  return res;
}

function stripDemoKey(path: string): string {
  const idx = path.indexOf('?');
  if (idx < 0) return path;
  const params = new URLSearchParams(path.slice(idx + 1));
  params.delete('demo_key');
  const qs = params.toString();
  return qs ? `${path.slice(0, idx)}?${qs}` : path.slice(0, idx);
}
