import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextResponse } from 'next/server';
import { resolveOrgBilling } from '@/lib/billing';
import { getInstallationId } from '@/lib/github';

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
    const installationId = await getInstallationId(billing.customerId);
    return NextResponse.json({
      connected: installationId !== null,
      installation_id: installationId,
    });
  } catch {
    return NextResponse.json({ connected: false });
  }
}
