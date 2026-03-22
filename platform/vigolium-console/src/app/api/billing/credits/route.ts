import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextResponse } from 'next/server';
import { resolveOrgBilling } from '@/lib/billing';

export async function GET() {
  const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';
  if (skipAuth) {
    return NextResponse.json({ credits: 999999, org_id: 'dev', org_name: 'Development' });
  }

  const session = await withAuth();
  if (!session.user) {
    return NextResponse.json(null, { status: 401 });
  }

  try {
    const billing = await resolveOrgBilling(session.user.id);
    return NextResponse.json({
      credits: billing.credits,
      org_id: billing.orgId,
      org_name: billing.orgName,
      customer_id: billing.customerId,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to resolve billing';
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
