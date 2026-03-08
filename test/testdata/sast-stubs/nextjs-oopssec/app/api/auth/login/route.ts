import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  const body = await request.json();
  const { email, password } = body;
  return NextResponse.json({ token: 'jwt-token-here' });
}
