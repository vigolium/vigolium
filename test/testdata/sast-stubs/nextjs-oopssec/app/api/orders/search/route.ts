import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  const body = await request.json();
  const { status } = body;
  return NextResponse.json({ orders: [], status });
}
