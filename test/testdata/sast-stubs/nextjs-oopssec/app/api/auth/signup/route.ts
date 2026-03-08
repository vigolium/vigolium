import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  const body = await request.json();
  const { email, password, name } = body;
  return NextResponse.json({ id: 1, email, name });
}
