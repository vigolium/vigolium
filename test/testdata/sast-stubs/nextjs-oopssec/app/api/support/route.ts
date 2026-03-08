import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  const body = await request.json();
  const { screenshotUrl, message } = body;
  return NextResponse.json({ received: true, screenshotUrl });
}
