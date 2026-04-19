import 'server-only';
import { getConvexClient } from './convex-server';
import { api } from '../../convex/_generated/api';
import { getCostForPath } from './billing-costs';
import type { CreditCheckResult } from './billing';
import type { Id } from '../../convex/_generated/dataModel';

export type { CreditCheckResult };

export async function resolveConvexUser(workosUserId: string) {
  const convex = getConvexClient();
  return convex.query(api.users.getByWorkosId, { workosUserId });
}

export async function upsertConvexUser(email: string, workosUserId: string) {
  const convex = getConvexClient();
  return convex.mutation(api.users.upsertOnLogin, { email, workosUserId });
}

const SCAN_SERVER = process.env.VIGOLIUM_SCAN_SERVER || 'http://localhost:9002';
const AUTH_API_KEY = process.env.VIGOLIUM_AUTH_API_KEY || '';

export async function createProjectForNewUser(
  userId: Id<'users'>,
  email: string,
): Promise<string | null> {
  const label = email.toLowerCase().split('@')[0] || 'default';
  const projectName = `${label}-project`;

  const res = await fetch(`${SCAN_SERVER}/api/projects`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(AUTH_API_KEY ? { Authorization: `Bearer ${AUTH_API_KEY}` } : {}),
    },
    body: JSON.stringify({ name: projectName, description: `Default project for ${email}` }),
  });

  if (!res.ok) return null;

  const project = (await res.json()) as { uuid: string };
  const convex = getConvexClient();

  await Promise.all([
    convex.mutation(api.projectAccess.grant, {
      userId,
      projectUuid: project.uuid,
      role: 'owner' as const,
    }),
    convex.mutation(api.auditLog.log, {
      userId,
      userEmail: email,
      action: 'project_created',
      resource: project.uuid,
      metadata: { name: projectName, auto: true },
    }),
  ]);

  return project.uuid;
}

export async function checkProjectAccessById(
  userId: Id<'users'>,
  userRole: string,
  projectUuid: string,
): Promise<{ hasAccess: boolean; role: string | null }> {
  if (userRole === 'admin') return { hasAccess: true, role: 'admin' };

  const convex = getConvexClient();
  return convex.query(api.projectAccess.checkAccess, { userId, projectUuid });
}

export async function deductConvexCreditsById(
  userId: Id<'users'>,
  userStatus: string,
  endpointPath: string,
): Promise<CreditCheckResult> {
  const cost = getCostForPath(endpointPath);
  if (cost === 0) {
    return { allowed: true, cost: 0, remaining: -1 };
  }

  if (userStatus !== 'active') {
    return { allowed: false, cost, remaining: 0, error: `Account is ${userStatus}` };
  }

  const convex = getConvexClient();
  const result = await convex.mutation(api.credits.deduct, {
    userId,
    cost,
    endpoint: endpointPath,
  });

  if (!result.success) {
    return {
      allowed: false,
      cost,
      remaining: result.remaining,
      error: `Insufficient credits. This action costs ${cost} credits, you have ${result.remaining}.`,
    };
  }

  return { allowed: true, cost, remaining: result.remaining };
}

export async function checkQuotaById(
  userId: Id<'users'>,
): Promise<{ allowed: boolean; error?: string }> {
  const convex = getConvexClient();
  const result = await convex.mutation(api.quotas.checkAndIncrement, { userId });

  if (!result.allowed) {
    return { allowed: false, error: result.reason };
  }
  return { allowed: true };
}

export async function addConvexCredits(
  userId: Id<'users'>,
  amount: number,
  reason: 'purchase' | 'refund' | 'grant',
) {
  const convex = getConvexClient();
  return convex.mutation(api.credits.addCredits, { userId, amount, reason });
}

export async function logAuditEvent(
  userId: Id<'users'> | undefined,
  userEmail: string | undefined,
  action: string,
  resource?: string,
  metadata?: Record<string, unknown>,
) {
  const convex = getConvexClient();
  return convex.mutation(api.auditLog.log, {
    userId,
    userEmail,
    action,
    resource,
    metadata,
  });
}
