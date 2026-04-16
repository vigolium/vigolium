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
  ssoDisabled: boolean;
  showcasesEnabled: boolean;
}

/** SSO is disabled when explicitly set OR when WorkOS keys are missing. */
export function isSSODisabled(): boolean {
  if (process.env.VIGOLIUM_DISABLE_SSO === 'true') return true;
  return !process.env.WORKOS_API_KEY || !process.env.WORKOS_CLIENT_ID;
}

/** Showcases listing is gated by its own feature flag. */
export function isShowcasesEnabled(): boolean {
  return process.env.VIGOLIUM_SHOWCASES_ENABLED === 'true';
}

export function checkCloudEnv(): EnvCheckResult {
  const issues: EnvIssue[] = [];
  const ssoDisabled = isSSODisabled();
  const showcasesEnabled = isShowcasesEnabled();

  // WorkOS — required for SSO auth. When SSO is disabled (explicitly or by missing keys),
  // downgrade to warnings so the login page still renders with access-code auth.
  const workOSSeverity: EnvIssue['severity'] = ssoDisabled ? 'warning' : 'error';
  const workOSSuffix = ssoDisabled ? ' SSO login is disabled; access-code login is available.' : '';
  if (!process.env.WORKOS_API_KEY) {
    issues.push({ key: 'WORKOS_API_KEY', severity: workOSSeverity, message: `WorkOS API key is missing — SSO authentication will not work.${workOSSuffix}` });
  }
  if (!process.env.WORKOS_CLIENT_ID) {
    issues.push({ key: 'WORKOS_CLIENT_ID', severity: workOSSeverity, message: `WorkOS client ID is missing — SSO authentication will not work.${workOSSuffix}` });
  }
  if (!process.env.WORKOS_COOKIE_PASSWORD) {
    issues.push({ key: 'WORKOS_COOKIE_PASSWORD', severity: workOSSeverity, message: `WorkOS cookie password is missing — session encryption will fail.${workOSSuffix}` });
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
  return { ok: !hasError, issues, ssoDisabled, showcasesEnabled };
}
