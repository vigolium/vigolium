import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextRequest, NextResponse } from 'next/server';
import { resolveConvexUser } from '@/lib/convex-billing';
import { getConvexClient } from '@/lib/convex-server';
import { api } from '../../../../../convex/_generated/api';
import { isDemoRequest } from '@/lib/demoRequest';

const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';

export async function GET(req: NextRequest) {
  if (isDemoRequest(req)) {
    return NextResponse.json({ credits: 0 });
  }
  if (skipAuth) {
    return NextResponse.json({ credits: 999999 });
  }

  const session = await withAuth();
  if (!session.user) {
    return NextResponse.json(null, { status: 401 });
  }

  const user = await resolveConvexUser(session.user.id);
  if (!user) {
    return NextResponse.json({ credits: 0 });
  }

  const convex = getConvexClient();
  const balance = await convex.query(api.credits.getBalance, { userId: user._id });

  return NextResponse.json({ credits: balance });
}
