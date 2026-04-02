import { signOut } from '@workos-inc/authkit-nextjs';
import { cookies } from 'next/headers';
import { ACCESS_COOKIE_NAME } from '@/lib/access-session';

export async function GET() {
  // Clear access-code session cookie if present
  const cookieStore = await cookies();
  cookieStore.delete(ACCESS_COOKIE_NAME);

  // Sign out of WorkOS (handles its own cookie cleanup + redirect)
  return signOut();
}
