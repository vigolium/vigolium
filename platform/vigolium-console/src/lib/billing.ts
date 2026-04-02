import { withAuth } from '@workos-inc/authkit-nextjs';
import { getUserOrganization } from './workos-server';
import { getOrCreateCustomer, getOrCreateUserCustomer, getCredits, deductCredits } from './stripe';
import { getCostForPath } from './billing-costs';

const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';

export interface BillingInfo {
  orgId: string | null;
  orgName: string | null;
  customerId: string;
  credits: number;
}

/** @deprecated Use resolveBilling instead */
export async function resolveOrgBilling(userId: string): Promise<BillingInfo | null> {
  return resolveBilling(userId);
}

/**
 * Resolve a user to their Stripe customer — via org if available, otherwise as individual.
 * Creates the Stripe customer on first access.
 */
export async function resolveBilling(userId: string): Promise<BillingInfo | null> {
  const session = await withAuth();
  if (!session.user) return null;

  const email = session.user.email || '';
  const name = session.user.firstName
    ? `${session.user.firstName} ${session.user.lastName || ''}`.trim()
    : email;

  const org = await getUserOrganization(userId);

  if (org) {
    const customer = await getOrCreateCustomer(org.orgId, org.orgName, email);
    const credits = await getCredits(customer.id);
    return { orgId: org.orgId, orgName: org.orgName, customerId: customer.id, credits };
  }

  // Individual user — create a user-level Stripe customer
  const customer = await getOrCreateUserCustomer(userId, name, email);
  const credits = await getCredits(customer.id);
  return { orgId: null, orgName: null, customerId: customer.id, credits };
}

export interface CreditCheckResult {
  allowed: boolean;
  cost: number;
  remaining: number;
  error?: string;
}

/**
 * Check if a user has enough credits for a scan endpoint and deduct them.
 * In skip-auth mode, always returns allowed with unlimited credits.
 */
export async function checkAndDeductCredits(
  userId: string,
  endpointPath: string,
): Promise<CreditCheckResult> {
  if (skipAuth) {
    return { allowed: true, cost: 0, remaining: 999999 };
  }

  const cost = getCostForPath(endpointPath);
  if (cost === 0) {
    return { allowed: true, cost: 0, remaining: -1 };
  }

  let billing: BillingInfo | null;
  try {
    billing = await resolveBilling(userId);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    // Surface missing Stripe/WorkOS keys as a clear billing error instead of a 500
    if (msg.includes('STRIPE_SECRET_KEY') || msg.includes('WORKOS')) {
      return { allowed: false, cost, remaining: 0, error: `Billing is not configured: ${msg}` };
    }
    throw err;
  }

  if (!billing) {
    return { allowed: false, cost, remaining: 0, error: 'Could not resolve billing information. Check server configuration.' };
  }

  const result = await deductCredits(billing.customerId, cost);

  if (!result.success) {
    return {
      allowed: false,
      cost,
      remaining: result.remaining,
      error: `Insufficient credits. This scan costs ${cost} credits, you have ${result.remaining}.`,
    };
  }

  return { allowed: true, cost, remaining: result.remaining };
}
