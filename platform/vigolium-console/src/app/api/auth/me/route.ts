import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextResponse } from 'next/server';
import { resolveOrgBilling } from '@/lib/billing';

export async function GET() {
  const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';
  if (skipAuth) {
    return NextResponse.json({
      name: 'Admin',
      email: 'admin@local',
      role: 'admin',
      credits: 999999,
      organization: null,
    });
  }

  const session = await withAuth();
  if (!session.user) {
    return NextResponse.json(null, { status: 401 });
  }

  const user = session.user;

  const billing = await resolveOrgBilling(user.id);
  const organization = billing?.orgId
    ? { id: billing.orgId, name: billing.orgName! }
    : null;
  const credits = billing?.credits ?? 0;

  return NextResponse.json({
    id: user.id,
    name: user.firstName ? `${user.firstName} ${user.lastName || ''}`.trim() : user.email,
    email: user.email,
    role: 'user',
    credits,
    organization,
  });
}
