import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextRequest, NextResponse } from 'next/server';
import { getUserOrganization, listOrgMembers, removeMember } from '@/lib/workos-server';

export async function GET() {
  const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';
  if (skipAuth) {
    return NextResponse.json([
      { id: 'dev-1', membership_id: 'mem-1', name: 'Admin', email: 'admin@local', role: 'admin', joined_at: new Date().toISOString() },
    ]);
  }

  const session = await withAuth();
  if (!session.user) {
    return NextResponse.json(null, { status: 401 });
  }

  try {
    const org = await getUserOrganization(session.user.id);
    if (!org) {
      return NextResponse.json({ error: 'No organization found' }, { status: 400 });
    }

    const members = await listOrgMembers(org.orgId);
    return NextResponse.json(
      members.map((m) => ({
        id: m.id,
        membership_id: m.membershipId,
        name: m.name,
        email: m.email,
        role: m.role,
        joined_at: m.joinedAt,
      })),
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to list members';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

export async function DELETE(req: NextRequest) {
  const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';
  if (skipAuth) {
    return NextResponse.json({ ok: true });
  }

  const session = await withAuth();
  if (!session.user) {
    return NextResponse.json(null, { status: 401 });
  }

  const membershipId = req.nextUrl.searchParams.get('membershipId');
  if (!membershipId) {
    return NextResponse.json({ error: 'membershipId is required' }, { status: 400 });
  }

  try {
    await removeMember(membershipId);
    return NextResponse.json({ ok: true });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to remove member';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
