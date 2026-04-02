import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextResponse } from 'next/server';
import { resolveOrgBilling } from '@/lib/billing';
import { removeAccessToken, DEV_TOKEN_COOKIE } from '@/lib/github';

export async function POST() {
  const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';
  if (skipAuth) {
    const response = NextResponse.json({ ok: true });
    response.cookies.set(DEV_TOKEN_COOKIE, '', { maxAge: 0, path: '/' });
    return response;
  }

  const session = await withAuth();
  if (!session.user) {
    return NextResponse.json(null, { status: 401 });
  }

  try {
    const billing = await resolveOrgBilling(session.user.id);
    if (!billing) {
      return NextResponse.json({ ok: true });
    }
    await removeAccessToken(billing.customerId);
    return NextResponse.json({ ok: true });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to disconnect';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
