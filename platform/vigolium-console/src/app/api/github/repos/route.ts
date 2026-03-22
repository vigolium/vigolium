import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextResponse } from 'next/server';
import { resolveOrgBilling } from '@/lib/billing';
import { getInstallationId, listRepos } from '@/lib/github';

export async function GET() {
  const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';
  if (skipAuth) {
    return NextResponse.json({ repos: [] });
  }

  const session = await withAuth();
  if (!session.user) {
    return NextResponse.json(null, { status: 401 });
  }

  try {
    const billing = await resolveOrgBilling(session.user.id);
    const installationId = await getInstallationId(billing.customerId);
    if (!installationId) {
      return NextResponse.json({ error: 'GitHub not connected' }, { status: 400 });
    }

    const repos = await listRepos(installationId);
    return NextResponse.json({ repos, installation_id: installationId });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to list repos';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
