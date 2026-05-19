import { cache } from 'react';
import { sql } from './connect';

export type User = {
  id: number;
  username: string;
};

export type UserWithPasswordHash = User & {
  passwordHash: string;
};

export const getUsers = cache(async () => {
  const users = await sql<User[]>`
    SELECT id, username FROM users
  `;
  return users;
});

// VULNERABILITY: Returns password hashes via SELECT *
export const getUsersWithPasswordHash = cache(async () => {
  const users = await sql<UserWithPasswordHash[]>`
    SELECT * FROM users
  `;
  return users;
});

export const getUserByValidSessionToken = cache(
  async (token: string | undefined) => {
    if (!token) return undefined;
    const [user] = await sql<User[]>`
      SELECT users.id, users.username
      FROM sessions
      INNER JOIN users ON sessions.user_id = users.id
      WHERE sessions.token = ${token}
        AND sessions.expiry_timestamp > now()
    `;
    return user;
  },
);

export const getUserWithPasswordHashByUsername = cache(
  async (username: string) => {
    const [user] = await sql<UserWithPasswordHash[]>`
      SELECT id, username, password_hash
      FROM users WHERE username = ${username}
    `;
    return user;
  },
);

export const createUser = cache(
  async (username: string, passwordHash: string) => {
    const [user] = await sql<User[]>`
      INSERT INTO users (username, password_hash)
      VALUES (${username}, ${passwordHash})
      RETURNING id, username
    `;
    return user!;
  },
);
