/**
 * Server-side environment variable validation for cloud mode.
 * Returns a list of missing or misconfigured secrets.
 */

export interface EnvIssue {
  key: string;
  severity: 'error' | 'warning';
  message: string;
}

export interface EnvCheckResult {
  ok: boolean;
  issues: EnvIssue[];
}

export function checkCloudEnv(): EnvCheckResult {
  const issues: EnvIssue[] = [];

  // WorkOS — required for auth in cloud mode
  if (!process.env.WORKOS_API_KEY) {
    issues.push({ key: 'WORKOS_API_KEY', severity: 'error', message: 'WorkOS API key is missing — authentication will not work.' });
  }
  if (!process.env.WORKOS_CLIENT_ID) {
    issues.push({ key: 'WORKOS_CLIENT_ID', severity: 'error', message: 'WorkOS client ID is missing — authentication will not work.' });
  }
  if (!process.env.WORKOS_COOKIE_PASSWORD) {
    issues.push({ key: 'WORKOS_COOKIE_PASSWORD', severity: 'error', message: 'WorkOS cookie password is missing — session encryption will fail.' });
  }

  // Stripe — required for billing
  if (!process.env.STRIPE_SECRET_KEY) {
    issues.push({ key: 'STRIPE_SECRET_KEY', severity: 'warning', message: 'Stripe secret key is missing — billing and credit checks will not work.' });
  }

  // Scan server connection
  if (!process.env.VIGOLIUM_AUTH_API_KEY) {
    issues.push({ key: 'VIGOLIUM_AUTH_API_KEY', severity: 'warning', message: 'Scan server API key is missing — backend requests may be rejected.' });
  }

  // GitHub OAuth — optional but warn
  if (!process.env.GITHUB_CLIENT_ID || !process.env.GITHUB_CLIENT_SECRET) {
    issues.push({ key: 'GITHUB_CLIENT_ID/SECRET', severity: 'warning', message: 'GitHub OAuth credentials are missing — GitHub integration will not work.' });
  }

  const hasError = issues.some((i) => i.severity === 'error');
  return { ok: !hasError, issues };
}
