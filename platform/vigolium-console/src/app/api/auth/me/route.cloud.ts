import { withAuth } from '@workos-inc/authkit-nextjs';
import { cookies } from 'next/headers';
import { NextRequest, NextResponse } from 'next/server';
import { resolveOrgBilling } from '@/lib/billing';
import { getUserOrganization } from '@/lib/workos-server';
import { verifyAccessSession, ACCESS_COOKIE_NAME } from '@/lib/access-session';
import { validateDemoKey, isDemoSkipAuth } from '@/lib/demoKeys';

const requireOrg = process.env.REQUIRE_ORG_MEMBERSHIP === 'true';

export async function GET(req: NextRequest) {
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

  // Check for demo session first — strict URL param source of truth
  const demoKey = req.nextUrl.searchParams.get('demo_key');
  if (demoKey) {
    const result = validateDemoKey(demoKey);
    if (result.valid && result.label) {
      return NextResponse.json({
        name: `Demo: ${result.label}`,
        email: `demo-${result.label}@vigolium.com`,
        role: 'demo',
        demo_label: result.label,
        demo_expires: result.expires,
        organization: null,
      });
    }
  }

  // Skip-auth demo: no key required, everyone is a demo user
  if (!demoKey && isDemoSkipAuth()) {
    return NextResponse.json({
      name: 'Demo',
      email: 'demo@vigolium.com',
      role: 'demo',
      demo_label: 'public',
      organization: null,
    });
  }

  const cookieStore = await cookies();

  // Check for access-code session next (bypasses WorkOS entirely)
  const accessCookie = cookieStore.get(ACCESS_COOKIE_NAME);
  if (accessCookie?.value) {
    const payload = await verifyAccessSession(accessCookie.value);
    if (payload) {
      return NextResponse.json({
        name: payload.label,
        email: payload.email,
        role: 'access-code',
        credits: 999999,
        organization: null,
      });
    }
    // Invalid/expired cookie — treat as unauthenticated
    return NextResponse.json(null, { status: 401 });
  }

  // WorkOS authentication
  let session;
  try {
    session = await withAuth();
  } catch {
    return NextResponse.json(
      { error: 'Authentication is not configured. Check WorkOS environment variables.' },
      { status: 503 },
    );
  }

  if (!session.user) {
    return NextResponse.json(null, { status: 401 });
  }

  const user = session.user;

  // Org membership gate (when enabled)
  if (requireOrg) {
    try {
      const org = await getUserOrganization(user.id);
      if (!org) {
        return NextResponse.json(
          { error: 'no_organization', message: 'You must be invited to an organization to access this platform.' },
          { status: 403 },
        );
      }
    } catch {
      // If the org check itself fails, let the user through rather than blocking
    }
  }

  let billing;
  try {
    billing = await resolveOrgBilling(user.id);
  } catch {
    // Billing not configured — return user info without credits
    return NextResponse.json({
      id: user.id,
      name: user.firstName ? `${user.firstName} ${user.lastName || ''}`.trim() : user.email,
      email: user.email,
      role: 'user',
      credits: 0,
      organization: null,
      billingError: 'Billing is not configured. Check Stripe environment variables.',
    });
  }

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
