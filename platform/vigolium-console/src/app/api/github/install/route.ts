import { NextResponse } from 'next/server';

export async function GET() {
  const slug = process.env.GITHUB_APP_SLUG;
  if (!slug) {
    return NextResponse.json({ error: 'GitHub App not configured' }, { status: 500 });
  }

  return NextResponse.redirect(`https://github.com/apps/${slug}/installations/new`);
}
