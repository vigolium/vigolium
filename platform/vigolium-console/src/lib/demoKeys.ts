import fs from 'fs';
import path from 'path';

export interface DemoKey {
  key: string;
  label?: string;
  expires?: string;
}

export type ValidationReason = 'disabled' | 'no_keys' | 'no_match' | 'expired';

export interface ValidationResult {
  valid: boolean;
  label?: string;
  expires?: string;
  reason?: ValidationReason;
}

export function isDemoOnlyEnabled(): boolean {
  return process.env.VIGOLIUM_DEMO_ONLY === 'true';
}

function parseEntries(raw: unknown): DemoKey[] {
  if (!Array.isArray(raw)) return [];
  const out: DemoKey[] = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const entry = item as Record<string, unknown>;
    if (typeof entry.key !== 'string' || entry.key.length === 0) continue;
    out.push({
      key: entry.key,
      label: typeof entry.label === 'string' ? entry.label : undefined,
      expires: typeof entry.expires === 'string' ? entry.expires : undefined,
    });
  }
  return out;
}

export function loadDemoKeys(): DemoKey[] {
  const filePath = path.join(process.cwd(), 'config', 'demo-view-keys.json');
  if (fs.existsSync(filePath)) {
    try {
      const entries = parseEntries(JSON.parse(fs.readFileSync(filePath, 'utf-8')));
      if (entries.length > 0) return entries;
    } catch {
      // fall through to env
    }
  }

  const envJson = process.env.VIGOLIUM_DEMO_KEYS;
  if (envJson) {
    try {
      const entries = parseEntries(JSON.parse(envJson));
      if (entries.length > 0) return entries;
    } catch {
      // ignore
    }
  }

  return [];
}

export function validateDemoKey(demoKey: string | null | undefined): ValidationResult {
  if (!isDemoOnlyEnabled()) return { valid: false, reason: 'disabled' };

  const keys = loadDemoKeys();
  if (keys.length === 0) return { valid: false, reason: 'no_keys' };
  if (!demoKey) return { valid: false, reason: 'no_match' };

  const match = keys.find((k) => k.key === demoKey);
  if (!match) return { valid: false, reason: 'no_match' };

  if (match.expires) {
    const expiresAt = Date.parse(match.expires);
    if (!Number.isNaN(expiresAt) && Date.now() > expiresAt) {
      return { valid: false, reason: 'expired', label: match.label };
    }
  }

  return { valid: true, label: match.label, expires: match.expires };
}
