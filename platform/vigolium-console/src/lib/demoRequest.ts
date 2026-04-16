import 'server-only';
import type { NextRequest } from 'next/server';
import { isDemoOnlyEnabled, validateDemoKey } from './demoKeys';

/**
 * True when the incoming request comes from an active demo session.
 * Use this at the top of cloud-only API routes that call `withAuth()` so they
 * can return safe empty-state responses instead of crashing on the bypassed
 * WorkOS middleware.
 */
export function isDemoRequest(req: NextRequest): boolean {
  if (!isDemoOnlyEnabled()) return false;
  const key = req.nextUrl.searchParams.get('demo_key');
  if (!key) return false;
  return validateDemoKey(key).valid;
}
