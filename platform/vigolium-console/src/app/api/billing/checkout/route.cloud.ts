import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextRequest, NextResponse } from 'next/server';
import { resolveOrgBilling } from '@/lib/billing';
import { getStripe } from '@/lib/stripe';
import { isDemoRequest } from '@/lib/demoRequest';

/** Credit packages: credits → price in cents. */
const PACKAGES: Record<number, number> = {
  100: 1000,   // $10
  500: 4000,   // $40
  1000: 7000,  // $70
};

export async function POST(req: NextRequest) {
  if (isDemoRequest(req)) {
    return NextResponse.json({ error: 'Billing is disabled in demo mode' }, { status: 403 });
  }

  const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';
  if (skipAuth) {
    return NextResponse.json({ error: 'Billing disabled in dev mode' }, { status: 400 });
  }

  const session = await withAuth();
  if (!session.user) {
    return NextResponse.json(null, { status: 401 });
  }

  const body = await req.json();
  const creditsAmount = body.credits_amount as number;

  if (!PACKAGES[creditsAmount]) {
    return NextResponse.json(
      { error: `Invalid package. Choose one of: ${Object.keys(PACKAGES).join(', ')}` },
      { status: 400 },
    );
  }

  try {
    const billing = await resolveOrgBilling(session.user.id);
    if (!billing) {
      return NextResponse.json({ error: 'Unable to resolve billing' }, { status: 400 });
    }
    const stripe = getStripe();

    const origin = req.headers.get('origin') || 'http://localhost:5002';
    const checkoutSession = await stripe.checkout.sessions.create({
      customer: billing.customerId,
      mode: 'payment',
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: `${creditsAmount} Scan Credits`,
              description: `Top up ${creditsAmount} scan credits for Vigolium`,
            },
            unit_amount: PACKAGES[creditsAmount],
          },
          quantity: 1,
        },
      ],
      metadata: {
        credits_amount: String(creditsAmount),
        ...(billing.orgId ? { workos_org_id: billing.orgId } : { workos_user_id: session.user.id }),
      },
      success_url: `${origin}/billing?checkout=success`,
      cancel_url: `${origin}/billing?checkout=cancelled`,
    });

    return NextResponse.json({ url: checkoutSession.url });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Checkout failed';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
