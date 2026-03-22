import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextRequest, NextResponse } from 'next/server';
import { resolveOrgBilling } from '@/lib/billing';
import { getStripe } from '@/lib/stripe';

export async function POST(req: NextRequest) {
  const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';
  if (skipAuth) {
    return NextResponse.json({ error: 'Billing disabled in dev mode' }, { status: 400 });
  }

  const session = await withAuth();
  if (!session.user) {
    return NextResponse.json(null, { status: 401 });
  }

  try {
    const billing = await resolveOrgBilling(session.user.id);
    const stripe = getStripe();
    const origin = req.headers.get('origin') || 'http://localhost:5002';

    const portalSession = await stripe.billingPortal.sessions.create({
      customer: billing.customerId,
      return_url: `${origin}/billing`,
    });

    return NextResponse.json({ url: portalSession.url });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to create portal session';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
