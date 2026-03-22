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

  // Try to resolve billing info (org + credits). Gracefully degrade if no org yet.
  let organization: { id: string; name: string } | null = null;
  let credits = 0;
  try {
    const billing = await resolveOrgBilling(user.id);
    organization = { id: billing.orgId, name: billing.orgName };
    credits = billing.credits;
  } catch {
    // User may not have an organization yet — that's OK
  }

  return NextResponse.json({
    id: user.id,
    name: user.firstName ? `${user.firstName} ${user.lastName || ''}`.trim() : user.email,
    email: user.email,
    role: 'user',
    credits,
    organization,
  });
}
