import 'server-only';
import { SignJWT, jwtVerify } from 'jose';

export const DEMO_COOKIE_NAME = 'vigolium-demo-session';

export interface DemoSessionPayload {
  label: string;
  keyHash: string;
  expires?: string;
}

/** SHA-256 hex digest of a demo key. Edge + Node compatible (uses SubtleCrypto). */
export async function hashDemoKey(key: string): Promise<string> {
  const data = new TextEncoder().encode(key);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function getSecret(): Uint8Array {
  const secret =
    process.env.ACCESS_SESSION_SECRET || process.env.WORKOS_COOKIE_PASSWORD || '';
  return new TextEncoder().encode(secret);
}

const DEFAULT_TTL_SECONDS = 24 * 60 * 60;
const MAX_TTL_SECONDS = 30 * 24 * 60 * 60;

export async function createDemoSession(
  label: string,
  keyHash: string,
  expiresAt?: string,
): Promise<{ token: string; maxAge: number }> {
  const secret = getSecret();

  const nowMs = Date.now();
  let expMs: number;
  if (expiresAt) {
    const parsed = Date.parse(expiresAt);
    expMs = Number.isNaN(parsed) ? nowMs + DEFAULT_TTL_SECONDS * 1000 : parsed;
  } else {
    expMs = nowMs + DEFAULT_TTL_SECONDS * 1000;
  }

  const maxAge = Math.min(
    MAX_TTL_SECONDS,
    Math.max(60, Math.floor((expMs - nowMs) / 1000)),
  );

  const token = await new SignJWT({ label, keyHash, expires: expiresAt } as Record<string, unknown>)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(new Date(nowMs + maxAge * 1000))
    .sign(secret);

  return { token, maxAge };
}

export async function verifyDemoSession(
  token: string,
): Promise<DemoSessionPayload | null> {
  try {
    const secret = getSecret();
    const { payload } = await jwtVerify(token, secret);
    if (typeof payload.label !== 'string' || typeof payload.keyHash !== 'string') return null;
    return {
      label: payload.label,
      keyHash: payload.keyHash,
      expires: typeof payload.expires === 'string' ? payload.expires : undefined,
    };
  } catch {
    return null;
  }
}

export function demoCookieOptions(maxAge: number) {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax' as const,
    path: '/',
    maxAge,
  };
}
