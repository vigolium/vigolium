import { NextRequest, NextResponse } from 'next/server';
import { validateAccessCode, validateEmailForCode } from '@/lib/access-codes';
import {
  createAccessSession,
  ACCESS_COOKIE_NAME,
  ACCESS_COOKIE_OPTIONS,
} from '@/lib/access-session';

export async function POST(req: NextRequest) {
  let body: { code?: string; email?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }

  const code = body.code?.trim();
  if (!code) {
    return NextResponse.json({ error: 'Access code is required' }, { status: 400 });
  }

  const entry = validateAccessCode(code);
  if (!entry) {
    return NextResponse.json(
      { error: 'Invalid or expired access code' },
      { status: 401 },
    );
  }

  const email = body.email?.trim().toLowerCase();

  // Step 1: code only — return validation result and ask for email
  if (!email) {
    return NextResponse.json({
      valid: true,
      requires_email: true,
      allowed_domains: entry.allowed_domains || [],
      allowed_emails: entry.allowed_emails || [],
    });
  }

  // Step 2: code + email — validate email against code restrictions, then create session
  if (!validateEmailForCode(entry, email)) {
    const hints: string[] = [];
    if (entry.allowed_domains?.length) hints.push(...entry.allowed_domains);
    if (entry.allowed_emails?.length) hints.push(...entry.allowed_emails);
    return NextResponse.json(
      {
        error: `Email not allowed for this access code`,
        allowed_domains: entry.allowed_domains || [],
        allowed_emails: entry.allowed_emails || [],
      },
      { status: 403 },
    );
  }

  const token = await createAccessSession(entry.label, email, entry.expires);

  const res = NextResponse.json({
    name: entry.label,
    email,
    role: 'access-code',
    authenticated: true,
  });

  res.cookies.set(ACCESS_COOKIE_NAME, token, ACCESS_COOKIE_OPTIONS);

  return res;
}
