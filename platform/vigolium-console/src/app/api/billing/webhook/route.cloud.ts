import { NextRequest, NextResponse } from 'next/server';
import { getStripe, addCredits, getOrCreateCustomer } from '@/lib/stripe';
import { resolveConvexUser, addConvexCredits, logAuditEvent } from '@/lib/convex-billing';

export async function POST(req: NextRequest) {
  const stripe = getStripe();
  const body = await req.text();
  const signature = req.headers.get('stripe-signature');

  if (!signature) {
    return NextResponse.json({ error: 'Missing stripe-signature header' }, { status: 400 });
  }

  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!webhookSecret) {
    return NextResponse.json({ error: 'Webhook secret not configured' }, { status: 500 });
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(body, signature, webhookSecret);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Signature verification failed';
    return NextResponse.json({ error: message }, { status: 400 });
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const creditsAmount = parseInt(session.metadata?.credits_amount || '0', 10);
    const orgId = session.metadata?.workos_org_id;

    if (creditsAmount > 0 && session.customer) {
      const customerId = typeof session.customer === 'string'
        ? session.customer
        : session.customer.id;

      await addCredits(customerId, creditsAmount);
    } else if (creditsAmount > 0 && orgId) {
      // Fallback: resolve customer by org ID
      const customer = await getOrCreateCustomer(orgId, '', session.customer_email || '');
      await addCredits(customer.id, creditsAmount);
    }

    // Write purchase to Convex ledger (single source of truth for balance)
    const workosUserId = session.metadata?.workos_user_id;
    if (workosUserId && creditsAmount > 0) {
      try {
        const convexUser = await resolveConvexUser(workosUserId);
        if (convexUser) {
          await Promise.all([
            addConvexCredits(convexUser._id, creditsAmount, 'purchase'),
            logAuditEvent(
              convexUser._id,
              convexUser.email,
              'credit_purchase',
              'billing',
              { amount: creditsAmount, stripeSessionId: session.id },
            ),
          ]);
        }
      } catch {
        // Convex unavailable — Stripe metadata still has the purchase
      }
    }
  }

  return NextResponse.json({ received: true });
}
