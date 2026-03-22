import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextResponse } from 'next/server';
import { resolveOrgBilling } from '@/lib/billing';
import { getStripe } from '@/lib/stripe';

export async function GET() {
  const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';
  if (skipAuth) {
    return NextResponse.json([]);
  }

  const session = await withAuth();
  if (!session.user) {
    return NextResponse.json(null, { status: 401 });
  }

  try {
    const billing = await resolveOrgBilling(session.user.id);
    if (!billing) {
      return NextResponse.json([]);
    }
    const stripe = getStripe();

    const sessions = await stripe.checkout.sessions.list({
      customer: billing.customerId,
      limit: 50,
    });

    const history = sessions.data
      .filter((s) => s.status === 'complete')
      .map((s) => ({
        id: s.id,
        amount: (s.amount_total || 0) / 100,
        credits: parseInt(s.metadata?.credits_amount || '0', 10),
        status: s.payment_status,
        created_at: new Date(s.created * 1000).toISOString(),
      }));

    return NextResponse.json(history);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to fetch history';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
