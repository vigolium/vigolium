import { withAuth } from '@workos-inc/authkit-nextjs';
import { NextResponse } from 'next/server';

export async function GET() {
  const skipAuth = process.env.VIGOLIUM_SKIP_AUTH === 'true';
  if (skipAuth) {
    return NextResponse.json({ name: 'Admin', email: 'admin@local', role: 'admin' });
  }

  const session = await withAuth();
  if (!session.user) {
    return NextResponse.json(null, { status: 401 });
  }

  const user = session.user;
  return NextResponse.json({
    id: user.id,
    name: user.firstName ? `${user.firstName} ${user.lastName || ''}`.trim() : user.email,
    email: user.email,
    role: 'user',
  });
}
