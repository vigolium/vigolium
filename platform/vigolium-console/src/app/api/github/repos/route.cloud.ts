import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { resolveOrgBilling } from '@/lib/billing';
import { getAccessToken, listRepos, DEV_TOKEN_COOKIE } from '@/lib/github';

export async function GET() {
  const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';
  if (skipAuth) {
    const cookieStore = await cookies();
    const token = cookieStore.get(DEV_TOKEN_COOKIE)?.value;
    if (!token) {
      return NextResponse.json({ error: 'GitHub not connected' }, { status: 400 });
    }
    try {
      const repos = await listRepos(token);
      return NextResponse.json({ repos });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to list repos';
      return NextResponse.json({ error: message }, { status: 500 });
    }
  }

  const session = await withAuth();
  if (!session.user) {
    return NextResponse.json(null, { status: 401 });
  }

  try {
    const billing = await resolveOrgBilling(session.user.id);
    if (!billing) {
      return NextResponse.json({ error: 'Join or create a team to connect GitHub' }, { status: 400 });
    }
    const accessToken = await getAccessToken(billing.customerId);
    if (!accessToken) {
      return NextResponse.json({ error: 'GitHub not connected' }, { status: 400 });
    }

    const repos = await listRepos(accessToken);
    return NextResponse.json({ repos });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to list repos';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
