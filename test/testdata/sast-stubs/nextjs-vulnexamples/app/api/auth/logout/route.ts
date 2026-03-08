import { cookies } from 'next/headers';
import { NextResponse } from 'next/server';
import { deleteSessionByToken } from '../../../../database/sessions';

export async function GET(): Promise<NextResponse<null>> {
  const cookieStore = await cookies();
  const token = cookieStore.get('sessionToken');

  if (token) {
    await deleteSessionByToken(token.value);
  }

  return NextResponse.json(null, { status: 307 });
}
