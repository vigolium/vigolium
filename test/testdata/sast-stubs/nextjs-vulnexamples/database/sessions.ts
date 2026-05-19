import { cache } from 'react';
import { sql } from './connect';

type Session = {
  id: number;
  token: string;
  userId: number;
};

export const deleteExpiredSessions = cache(async () => {
  const sessions = await sql<Session[]>`
    DELETE FROM sessions WHERE expiry_timestamp < now()
    RETURNING id, token, user_id
  `;
  return sessions;
});

export const getValidSessionByToken = cache(
  async (token: string | undefined) => {
    if (!token) return undefined;
    const [session] = await sql<Session[]>`
      SELECT id, token, user_id FROM sessions
      WHERE token = ${token} AND expiry_timestamp > now()
    `;
    await deleteExpiredSessions();
    return session;
  },
);

export const createSession = cache(async (token: string, userId: number) => {
  const [session] = await sql<Session[]>`
    INSERT INTO sessions (token, user_id)
    VALUES (${token}, ${userId})
    RETURNING id, token, user_id
  `;
  await deleteExpiredSessions();
  return session;
});

export const deleteSessionByToken = cache(async (token: string) => {
  const [session] = await sql<Session[]>`
    DELETE FROM sessions WHERE token = ${token}
    RETURNING id, token, user_id
  `;
  return session;
});
