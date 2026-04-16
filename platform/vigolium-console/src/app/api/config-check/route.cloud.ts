import { NextResponse } from 'next/server';
import { checkCloudEnv, isSSODisabled, isShowcasesEnabled } from '@/lib/envCheck';

const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';

export async function GET() {
  // In skip-auth mode, everything is fine — no secrets needed
  if (skipAuth) {
    return NextResponse.json({
      ok: true,
      issues: [],
      skipAuth: true,
      ssoDisabled: isSSODisabled(),
      showcasesEnabled: isShowcasesEnabled(),
    });
  }

  const result = checkCloudEnv();
  return NextResponse.json({ ...result, skipAuth: false });
}
