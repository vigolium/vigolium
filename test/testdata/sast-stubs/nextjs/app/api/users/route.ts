import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const q = searchParams.get('q');
  return NextResponse.json({ users: [], q });
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  return NextResponse.json({ name: body.name });
}

export async function DELETE(request: NextRequest) {
  return NextResponse.json({ deleted: true });
}
