import { NextRequest, NextResponse } from 'next/server';
import { isDemoOnlyEnabled, isDemoSkipAuth, validateDemoKey } from '@/lib/demoKeys';

export async function GET(req: NextRequest) {
  if (!isDemoOnlyEnabled()) {
    return NextResponse.json({ active: false, feature_enabled: false });
  }

  const skipAuth = isDemoSkipAuth();

  const demoKey = req.nextUrl.searchParams.get('demo_key');
  const result = validateDemoKey(demoKey);
  if (!result.valid || !result.label) {
    return NextResponse.json({ active: false, feature_enabled: true, skip_auth: skipAuth });
  }

  return NextResponse.json({
    active: true,
    feature_enabled: true,
    skip_auth: skipAuth,
    label: result.label,
    expires: result.expires,
  });
}
