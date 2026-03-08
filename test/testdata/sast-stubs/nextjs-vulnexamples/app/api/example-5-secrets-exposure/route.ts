import { NextRequest, NextResponse } from 'next/server';
import { getUserByValidSessionToken } from '../../../database/users';

export const dynamic = 'force-dynamic';

type SecretsExposureResponseBodyGet =
  | { error: string }
  | { data: unknown };

// SECURE (solution): Makes the API call server-side, never exposes the key
export async function GET(
  request: NextRequest,
): Promise<NextResponse<SecretsExposureResponseBodyGet>> {
  const sessionToken = request.cookies.get('sessionToken')?.value;

  if (!sessionToken) {
    return NextResponse.json(
      { error: 'Session token not provided' },
      { status: 401 },
    );
  }

  const user = await getUserByValidSessionToken(sessionToken);

  if (!user) {
    return NextResponse.json(
      { error: 'Session token not valid' },
      { status: 401 },
    );
  }

  const colorsResponse = await fetch(
    `https://reqres.in/api/colors?apiKey=${process.env.API_KEY!}`,
  );
  const colors = await colorsResponse.json();

  return NextResponse.json(colors);
}
