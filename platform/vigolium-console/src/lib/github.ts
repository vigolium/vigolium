import { App } from '@octokit/app';
import { getStripe } from './stripe';

let _app: App | null = null;

/** Get the GitHub App singleton. */
export function getGitHubApp(): App {
  if (!_app) {
    const appId = process.env.GITHUB_APP_ID;
    const privateKey = process.env.GITHUB_PRIVATE_KEY;
    if (!appId || !privateKey) {
      throw new Error('GITHUB_APP_ID and GITHUB_PRIVATE_KEY must be set');
    }
    _app = new App({
      appId,
      privateKey: privateKey.replace(/\\n/g, '\n'),
    });
  }
  return _app;
}

/** Read github_installation_id from Stripe customer metadata. */
export async function getInstallationId(customerId: string): Promise<number | null> {
  const stripe = getStripe();
  const customer = await stripe.customers.retrieve(customerId);
  if (customer.deleted) return null;
  const id = customer.metadata.github_installation_id;
  return id ? parseInt(id, 10) : null;
}

/** Store github_installation_id in Stripe customer metadata. */
export async function setInstallationId(customerId: string, installationId: number): Promise<void> {
  const stripe = getStripe();
  await stripe.customers.update(customerId, {
    metadata: { github_installation_id: String(installationId) },
  });
}

/** Remove github_installation_id from Stripe customer metadata. */
export async function removeInstallationId(customerId: string): Promise<void> {
  const stripe = getStripe();
  await stripe.customers.update(customerId, {
    metadata: { github_installation_id: '' },
  });
}

/** Generate a short-lived installation access token (~1 hour TTL). */
export async function getInstallationToken(installationId: number): Promise<string> {
  const app = getGitHubApp();
  const octokit = await app.getInstallationOctokit(installationId);
  const { data } = await octokit.request('POST /app/installations/{installation_id}/access_tokens', {
    installation_id: installationId,
  });
  return data.token;
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

/** List repositories accessible to the installation. */
export async function listRepos(installationId: number): Promise<GitHubRepo[]> {
  const app = getGitHubApp();
  const octokit = await app.getInstallationOctokit(installationId);

  const repos: GitHubRepo[] = [];
  let page = 1;
  const perPage = 100;

  while (true) {
    const { data } = await octokit.request('GET /installation/repositories', {
      per_page: perPage,
      page,
    });

    for (const repo of data.repositories) {
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

    if (repos.length >= data.total_count || data.repositories.length < perPage) {
      break;
    }
    page++;
  }

  return repos;
}

/** Generate an authenticated clone URL for a repo. */
export async function getCloneUrl(installationId: number, repoFullName: string): Promise<string> {
  const token = await getInstallationToken(installationId);
  return `https://x-access-token:${token}@github.com/${repoFullName}.git`;
}
