import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  const body = await request.json();
  const { trackingId } = body;
  const forwarded = request.headers.get('x-forwarded-for');
  return NextResponse.json({ trackingId, ip: forwarded });
}
