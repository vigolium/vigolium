import { getUsersWithPasswordHash } from '../../../database/users';

export const dynamic = 'force-dynamic';

// VULNERABILITY: Exposes password hashes and API key to the client
export default async function SecretsExposurePage() {
  const users = await getUsersWithPasswordHash();

  return (
    <div>
      <h1>Users</h1>
      {users.map((user) => (
        <div key={`user-${user.id}`}>
          <p>Username: {user.username}</p>
          <p>Password Hash: {user.passwordHash}</p>
        </div>
      ))}
      <div data-api-key={process.env.API_KEY!}>
        API Key is exposed in this page
      </div>
    </div>
  );
}
