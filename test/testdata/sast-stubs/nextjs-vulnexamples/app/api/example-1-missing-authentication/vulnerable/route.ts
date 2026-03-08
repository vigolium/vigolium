import { NextResponse } from 'next/server';
import { type BlogPost, getPublishedBlogPosts } from '../../../../database/blogPosts';

export const dynamic = 'force-dynamic';

export type MissingAuthenticationResponseBodyGet = {
  blogPosts: BlogPost[];
};

// VULNERABILITY: No authentication check - returns data to anyone
export async function GET(): Promise<
  NextResponse<MissingAuthenticationResponseBodyGet>
> {
  const blogPosts = await getPublishedBlogPosts();

  return NextResponse.json({
    blogPosts: blogPosts,
  });
}
