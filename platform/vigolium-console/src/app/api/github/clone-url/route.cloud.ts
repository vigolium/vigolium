import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextRequest, NextResponse } from 'next/server';
import { resolveOrgBilling } from '@/lib/billing';
import { getAccessToken, getCloneUrl, DEV_TOKEN_COOKIE } from '@/lib/github';
import { isDemoRequest } from '@/lib/demoRequest';

export async function POST(req: NextRequest) {
  if (isDemoRequest(req)) {
    return NextResponse.json({ error: 'GitHub is disabled in demo mode' }, { status: 403 });
  }

  const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';

  const body = await req.json();
  const repo = body.repo as string;
  if (!repo || !repo.includes('/')) {
    return NextResponse.json({ error: 'Invalid repo format. Use owner/repo' }, { status: 400 });
  }

  let accessToken: string | null;

  if (skipAuth) {
    accessToken = req.cookies.get(DEV_TOKEN_COOKIE)?.value ?? null;
  } else {
    const session = await withAuth();
    if (!session.user) {
      return NextResponse.json(null, { status: 401 });
    }
    const billing = await resolveOrgBilling(session.user.id);
    if (!billing) {
      return NextResponse.json({ error: 'Join or create a team to use GitHub integration' }, { status: 400 });
    }
    accessToken = await getAccessToken(billing.customerId);
  }

  if (!accessToken) {
    return NextResponse.json({ error: 'GitHub not connected' }, { status: 400 });
  }

  try {
    const cloneUrl = getCloneUrl(accessToken, repo);
    return NextResponse.json({ clone_url: cloneUrl });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to generate clone URL';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
