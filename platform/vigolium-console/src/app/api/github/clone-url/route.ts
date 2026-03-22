import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextRequest, NextResponse } from 'next/server';
import { resolveOrgBilling } from '@/lib/billing';
import { getInstallationId, getCloneUrl } from '@/lib/github';

export async function POST(req: NextRequest) {
  const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';
  if (skipAuth) {
    return NextResponse.json({ error: 'GitHub not available in dev mode' }, { status: 400 });
  }

  const session = await withAuth();
  if (!session.user) {
    return NextResponse.json(null, { status: 401 });
  }

  const body = await req.json();
  const repo = body.repo as string;
  if (!repo || !repo.includes('/')) {
    return NextResponse.json({ error: 'Invalid repo format. Use owner/repo' }, { status: 400 });
  }

  try {
    const billing = await resolveOrgBilling(session.user.id);
    const installationId = await getInstallationId(billing.customerId);
    if (!installationId) {
      return NextResponse.json({ error: 'GitHub not connected' }, { status: 400 });
    }

    const cloneUrl = await getCloneUrl(installationId, repo);
    return NextResponse.json({ clone_url: cloneUrl });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to generate clone URL';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
