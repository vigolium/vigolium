import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextRequest, NextResponse } from 'next/server';
import { resolveOrgBilling } from '@/lib/billing';
import { setInstallationId } from '@/lib/github';

export async function GET(req: NextRequest) {
  const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';
  if (skipAuth) {
    return NextResponse.redirect(new URL('/team?github=skipped', req.url));
  }

  const session = await withAuth();
  if (!session.user) {
    return NextResponse.redirect(new URL('/team?github=unauthorized', req.url));
  }

  const installationId = req.nextUrl.searchParams.get('installation_id');
  if (!installationId) {
    return NextResponse.redirect(new URL('/team?github=error', req.url));
  }

  try {
    const billing = await resolveOrgBilling(session.user.id);
    await setInstallationId(billing.customerId, parseInt(installationId, 10));
    return NextResponse.redirect(new URL('/team?github=connected', req.url));
  } catch {
    return NextResponse.redirect(new URL('/team?github=error', req.url));
  }
}
