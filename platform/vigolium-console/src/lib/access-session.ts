import 'server-only';
import { SignJWT, jwtVerify } from 'jose';

export const ACCESS_COOKIE_NAME = 'vigolium-access-session';

export interface AccessSessionPayload {
  label: string;
  email: string;
}

function getSecret(): Uint8Array {
  const secret =
    process.env.ACCESS_SESSION_SECRET || process.env.WORKOS_COOKIE_PASSWORD || '';
  return new TextEncoder().encode(secret);
}

export async function createAccessSession(
  label: string,
  email: string,
  expiresAt?: string,
): Promise<string> {
  const secret = getSecret();

  let exp: Date;
  if (expiresAt) {
    exp = new Date(expiresAt);
  } else {
    exp = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
  }

  return new SignJWT({ label, email } as Record<string, unknown>)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(exp)
    .sign(secret);
}

export async function verifyAccessSession(
  token: string,
): Promise<AccessSessionPayload | null> {
  try {
    const secret = getSecret();
    const { payload } = await jwtVerify(token, secret);
    return {
      label: payload.label as string,
      email: payload.email as string,
    };
  } catch {
    return null;
  }
}

export const ACCESS_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax' as const,
  path: '/',
  maxAge: 86400, // 24 hours
};
