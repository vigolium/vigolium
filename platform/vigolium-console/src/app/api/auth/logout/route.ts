import { signOut } from '@workos-inc/authkit-nextjs';

export function GET() {
  return signOut();
}
