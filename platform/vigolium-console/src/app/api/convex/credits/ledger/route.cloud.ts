import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextRequest, NextResponse } from 'next/server';
import { resolveConvexUser } from '@/lib/convex-billing';
import { getConvexClient } from '@/lib/convex-server';
import { api } from '../../../../../../convex/_generated/api';

const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';

export async function GET(req: NextRequest) {
  if (skipAuth) {
    return NextResponse.json({ entries: [] });
  }

  const session = await withAuth();
  if (!session.user) {
    return NextResponse.json(null, { status: 401 });
  }

  const user = await resolveConvexUser(session.user.id);
  if (!user) {
    return NextResponse.json({ entries: [] });
  }

  const limit = parseInt(req.nextUrl.searchParams.get('limit') || '50', 10);
  const convex = getConvexClient();
  const entries = await convex.query(api.credits.getLedger, { userId: user._id, limit });

  return NextResponse.json({ entries });
}
