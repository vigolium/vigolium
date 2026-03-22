import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextResponse } from 'next/server';
import { resolveOrgBilling } from '@/lib/billing';
import { removeInstallationId } from '@/lib/github';

export async function POST() {
  const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';
  if (skipAuth) {
    return NextResponse.json({ ok: true });
  }

  const session = await withAuth();
  if (!session.user) {
    return NextResponse.json(null, { status: 401 });
  }

  try {
    const billing = await resolveOrgBilling(session.user.id);
    await removeInstallationId(billing.customerId);
    return NextResponse.json({ ok: true });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to disconnect';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
