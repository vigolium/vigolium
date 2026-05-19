import { NextRequest, NextResponse } from 'next/server';
import { type BlogPost, getUnpublishedBlogPosts } from '../../../../database/blogPosts';
import { getUserByValidSessionToken } from '../../../../database/users';

export const dynamic = 'force-dynamic';

export type MissingAuthorizationResponseBodyGet =
  | { error: string }
  | { blogPosts: BlogPost[] };

// VULNERABILITY: Checks authentication but NOT authorization.
// Returns ALL users' unpublished blog posts instead of only the current user's.
export async function GET(
  request: NextRequest,
): Promise<NextResponse<MissingAuthorizationResponseBodyGet>> {
  const sessionToken = request.cookies.get('sessionToken')?.value;

  if (!sessionToken) {
    return NextResponse.json(
      { error: 'Session token not provided' },
      { status: 401 },
    );
  }

  const user = await getUserByValidSessionToken(sessionToken);

  if (!user) {
    return NextResponse.json(
      { error: 'Session token not valid' },
      { status: 401 },
    );
  }

  // BUG: Returns ALL unpublished posts, not just the current user's
  const blogPosts = await getUnpublishedBlogPosts();

  return NextResponse.json({ blogPosts: blogPosts });
}
