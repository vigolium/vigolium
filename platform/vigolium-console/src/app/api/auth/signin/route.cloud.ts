import { getSignInUrl } from '@workos-inc/authkit-nextjs';
import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  const returnTo = request.nextUrl.searchParams.get('return_to') || '/select-project';
  const url = await getSignInUrl({ returnTo });
  return NextResponse.redirect(url);
}
