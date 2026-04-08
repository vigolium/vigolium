import 'server-only';
import { readFileSync } from 'fs';
import { join } from 'path';

export interface AccessCodeEntry {
  code: string;
  label: string;
  allowed_domains?: string[];
  allowed_emails?: string[];
  expires?: string;
}

function loadAccessCodes(): AccessCodeEntry[] {
  const filePath =
    process.env.CONSOLE_USERS_PATH || join(process.cwd(), 'config/console-users.json');
  try {
    const raw = readFileSync(filePath, 'utf-8');
    return JSON.parse(raw) as AccessCodeEntry[];
  } catch {
    return [];
  }
}

export function validateAccessCode(code: string): AccessCodeEntry | null {
  const entries = loadAccessCodes();
  const entry = entries.find((e) => e.code === code);
  if (!entry) return null;

  if (entry.expires) {
    const expiry = new Date(entry.expires);
    if (expiry.getTime() < Date.now()) return null;
  }

  return entry;
}

/**
 * Check if an email is allowed for a given access code entry.
 * - If allowed_emails is set, email must match exactly (case-insensitive).
 * - Else if allowed_domains is set, email domain must match.
 * - If both are empty, any email is accepted.
 */
export function validateEmailForCode(entry: AccessCodeEntry, email: string): boolean {
  const normalizedEmail = email.toLowerCase().trim();

  if (entry.allowed_emails && entry.allowed_emails.length > 0) {
    return entry.allowed_emails.some(
      (e) => e.toLowerCase() === normalizedEmail,
    );
  }

  if (entry.allowed_domains && entry.allowed_domains.length > 0) {
    const domain = '@' + normalizedEmail.split('@')[1];
    return entry.allowed_domains.some(
      (d) => d.toLowerCase() === domain,
    );
  }

  // No restrictions — any email accepted
  return true;
}
