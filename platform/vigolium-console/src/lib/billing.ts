import { withAuth } from '@workos-inc/authkit-nextjs';
import { getUserOrganization } from './workos-server';
import { getOrCreateCustomer, getCredits, deductCredits } from './stripe';
import { getCostForPath } from './billing-costs';

const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';

export interface OrgBilling {
  orgId: string;
  orgName: string;
  customerId: string;
  credits: number;
}

/**
 * Resolve a user to their org and Stripe customer.
 * Creates the Stripe customer on first access.
 */
export async function resolveOrgBilling(userId: string): Promise<OrgBilling> {
  const org = await getUserOrganization(userId);
  if (!org) {
    throw new Error('User has no organization. Please create or join a team first.');
  }

  const session = await withAuth();
  const email = session.user?.email || '';
  const customer = await getOrCreateCustomer(org.orgId, org.orgName, email);
  const credits = await getCredits(customer.id);

  return {
    orgId: org.orgId,
    orgName: org.orgName,
    customerId: customer.id,
    credits,
  };
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

  const billing = await resolveOrgBilling(userId);
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
