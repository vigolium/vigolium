import { getStripe } from './stripe';

/** Cookie name used to store GitHub access token in skip-auth (dev) mode. */
export const DEV_TOKEN_COOKIE = 'github_dev_token';

/** Exchange an OAuth authorization code for an access token. */
export async function exchangeCodeForToken(code: string): Promise<string> {
  const clientId = process.env.GITHUB_CLIENT_ID;
  const clientSecret = process.env.GITHUB_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    throw new Error('GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must be set');
  }

  const res = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      code,
    }),
  });

  const data = await res.json();
  if (data.error) {
    throw new Error(`GitHub OAuth error: ${data.error_description || data.error}`);
  }

  return data.access_token;
}

/** Read github_access_token from Stripe customer metadata. */
export async function getAccessToken(customerId: string): Promise<string | null> {
  const stripe = getStripe();
  const customer = await stripe.customers.retrieve(customerId);
  if (customer.deleted) return null;
  const token = customer.metadata.github_access_token;
  return token || null;
}

/** Store github_access_token in Stripe customer metadata. */
export async function setAccessToken(customerId: string, accessToken: string): Promise<void> {
  const stripe = getStripe();
  await stripe.customers.update(customerId, {
    metadata: { github_access_token: accessToken },
  });
}

/** Remove github_access_token (and legacy github_installation_id) from Stripe customer metadata. */
export async function removeAccessToken(customerId: string): Promise<void> {
  const stripe = getStripe();
  await stripe.customers.update(customerId, {
    metadata: { github_access_token: '', github_installation_id: '' },
  });
}

/** Fetch the authenticated GitHub user's login name. */
export async function getGitHubUsername(accessToken: string): Promise<string> {
  const res = await fetch('https://api.github.com/user', {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/vnd.github+json',
    },
  });
  if (!res.ok) {
    throw new Error(`GitHub API error: ${res.status}`);
  }
  const data = await res.json();
  return data.login;
}

export interface GitHubRepo {
  full_name: string;
  name: string;
  owner: string;
  private: boolean;
  default_branch: string;
  description: string | null;
  url: string;
}

/** List repositories accessible to the authenticated user. */
export async function listRepos(accessToken: string): Promise<GitHubRepo[]> {
  const repos: GitHubRepo[] = [];
  let page = 1;
  const perPage = 100;

  while (true) {
    const res = await fetch(
      `https://api.github.com/user/repos?per_page=${perPage}&page=${page}&sort=updated&type=all`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/vnd.github+json',
        },
      },
    );

    if (!res.ok) {
      throw new Error(`GitHub API error: ${res.status}`);
    }

    const data = await res.json();
    if (!Array.isArray(data) || data.length === 0) break;

    for (const repo of data) {
      repos.push({
        full_name: repo.full_name,
        name: repo.name,
        owner: repo.owner.login,
        private: repo.private,
        default_branch: repo.default_branch,
        description: repo.description,
        url: repo.html_url,
      });
    }

    if (data.length < perPage) break;
    page++;
  }

  return repos;
}

/** Generate an authenticated clone URL for a repo. */
export function getCloneUrl(accessToken: string, repoFullName: string): string {
  return `https://x-access-token:${accessToken}@github.com/${repoFullName}.git`;
}
