import { NextRequest, NextResponse } from 'next/server';
import { type BlogPost, getUnpublishedBlogPostsByUserId } from '../../../../database/blogPosts';
import { getUserByValidSessionToken } from '../../../../database/users';

export const dynamic = 'force-dynamic';

export type MissingAuthorizationResponseBodyGet =
  | { error: string }
  | { blogPosts: BlogPost[] };

// SECURE: Validates session and filters by user ID
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

  const blogPosts = await getUnpublishedBlogPostsByUserId(user.id);

  return NextResponse.json({ blogPosts: blogPosts });
}
