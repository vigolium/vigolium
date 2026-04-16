import { cookies } from 'next/headers';
import { NextResponse } from 'next/server';
import { DEMO_COOKIE_NAME } from '@/lib/demo-session';

export async function GET(req: Request) {
  const cookieStore = await cookies();
  cookieStore.delete(DEMO_COOKIE_NAME);

  const url = new URL('/login', req.url);
  return NextResponse.redirect(url);
}
