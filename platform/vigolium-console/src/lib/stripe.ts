import Stripe from 'stripe';

let _stripe: Stripe | null = null;

export function getStripe(): Stripe {
  if (!_stripe) {
    if (!process.env.STRIPE_SECRET_KEY) {
      throw new Error('STRIPE_SECRET_KEY is not set');
    }
    _stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
      apiVersion: '2026-02-25.clover',
    });
  }
  return _stripe;
}

/** Find or create a Stripe customer for a WorkOS organization. */
export async function getOrCreateCustomer(
  orgId: string,
  orgName: string,
  email: string,
): Promise<Stripe.Customer> {
  const stripe = getStripe();

  // Search for existing customer by WorkOS org ID
  const result = await stripe.customers.search({
    query: `metadata["workos_org_id"]:"${orgId}"`,
  });

  if (result.data.length > 0) {
    return result.data[0];
  }

  // Create new customer
  return stripe.customers.create({
    name: orgName,
    email,
    metadata: {
      workos_org_id: orgId,
      credits: '0',
    },
  });
}

/** Find or create a Stripe customer for an individual user (no org). */
export async function getOrCreateUserCustomer(
  userId: string,
  name: string,
  email: string,
): Promise<Stripe.Customer> {
  const stripe = getStripe();

  const result = await stripe.customers.search({
    query: `metadata["workos_user_id"]:"${userId}"`,
  });

  if (result.data.length > 0) {
    return result.data[0];
  }

  return stripe.customers.create({
    name,
    email,
    metadata: {
      workos_user_id: userId,
      credits: '0',
    },
  });
}

/** Read current credit balance from customer metadata. */
export async function getCredits(customerId: string): Promise<number> {
  const stripe = getStripe();
  const customer = await stripe.customers.retrieve(customerId);
  if (customer.deleted) return 0;
  return parseInt(customer.metadata.credits || '0', 10);
}

/** Add credits to a customer's balance. Returns new balance. */
export async function addCredits(customerId: string, amount: number): Promise<number> {
  const stripe = getStripe();
  const customer = await stripe.customers.retrieve(customerId);
  if (customer.deleted) throw new Error('Customer deleted');

  const current = parseInt(customer.metadata.credits || '0', 10);
  const newBalance = current + amount;

  await stripe.customers.update(customerId, {
    metadata: { credits: String(newBalance) },
  });

  return newBalance;
}

/**
 * Deduct credits from a customer's balance.
 * Returns { success, remaining }. Does NOT deduct if insufficient.
 */
export async function deductCredits(
  customerId: string,
  amount: number,
): Promise<{ success: boolean; remaining: number }> {
  const stripe = getStripe();
  const customer = await stripe.customers.retrieve(customerId);
  if (customer.deleted) return { success: false, remaining: 0 };

  const current = parseInt(customer.metadata.credits || '0', 10);
  if (current < amount) {
    return { success: false, remaining: current };
  }

  const remaining = current - amount;
  await stripe.customers.update(customerId, {
    metadata: { credits: String(remaining) },
  });

  return { success: true, remaining };
}
