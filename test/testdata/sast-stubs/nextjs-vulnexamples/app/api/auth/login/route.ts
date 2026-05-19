import crypto from 'node:crypto';
import bcrypt from 'bcrypt';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { createSession } from '../../../../database/sessions';
import { getUserWithPasswordHashByUsername } from '../../../../database/users';

const userSchema = z.object({
  username: z.string(),
  password: z.string(),
});

export type LoginResponseBodyPost =
  | { errors: { message: string }[] }
  | { user: { username: string } };

export async function POST(
  request: NextRequest,
): Promise<NextResponse<LoginResponseBodyPost>> {
  const body = await request.json();
  const result = userSchema.safeParse(body);

  if (!result.success) {
    return NextResponse.json(
      { errors: result.error.issues },
      { status: 400 },
    );
  }

  if (!result.data.username || !result.data.password) {
    return NextResponse.json(
      { errors: [{ message: 'Username or password is empty' }] },
      { status: 400 },
    );
  }

  const userWithPasswordHash = await getUserWithPasswordHashByUsername(
    result.data.username,
  );

  if (!userWithPasswordHash) {
    return NextResponse.json(
      { errors: [{ message: 'User not found' }] },
      { status: 401 },
    );
  }

  const isPasswordValid = await bcrypt.compare(
    result.data.password,
    userWithPasswordHash.passwordHash,
  );

  if (!isPasswordValid) {
    return NextResponse.json(
      { errors: [{ message: 'Password is not valid' }] },
      { status: 401 },
    );
  }

  const token = crypto.randomBytes(64).toString('base64');
  const session = await createSession(token, userWithPasswordHash.id);

  if (!session) {
    return NextResponse.json(
      { errors: [{ message: 'Session creation failed' }] },
      { status: 500 },
    );
  }

  return NextResponse.json(
    { user: { username: userWithPasswordHash.username } },
    { status: 200 },
  );
}
