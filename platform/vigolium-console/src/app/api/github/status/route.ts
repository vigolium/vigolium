import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextResponse } from 'next/server';
import { resolveOrgBilling } from '@/lib/billing';
import { getAccessToken, getGitHubUsername, removeAccessToken } from '@/lib/github';

export async function GET() {
  const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';
  if (skipAuth) {
    return NextResponse.json({ connected: false });
  }

  const session = await withAuth();
  if (!session.user) {
    return NextResponse.json(null, { status: 401 });
  }

  try {
    const billing = await resolveOrgBilling(session.user.id);
    if (!billing) {
      return NextResponse.json({ connected: false });
    }
    const accessToken = await getAccessToken(billing.customerId);
    if (!accessToken) {
      return NextResponse.json({ connected: false });
    }

    // Verify token is still valid by fetching username
    try {
      const username = await getGitHubUsername(accessToken);
      return NextResponse.json({ connected: true, username });
    } catch {
      // Token was revoked — auto-disconnect
      await removeAccessToken(billing.customerId);
      return NextResponse.json({ connected: false });
    }
  } catch {
    return NextResponse.json({ connected: false });
  }
}
