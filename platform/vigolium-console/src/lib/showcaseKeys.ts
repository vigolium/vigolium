import fs from 'fs';
import path from 'path';

export interface ShowcaseKey {
  key: string;
  label?: string;
  expires?: string;
}

export type ValidationReason = 'no_keys' | 'no_match' | 'expired';

export interface ValidationResult {
  valid: boolean;
  label?: string;
  reason?: ValidationReason;
}

function parseEntries(raw: unknown): ShowcaseKey[] {
  if (!Array.isArray(raw)) return [];
  const out: ShowcaseKey[] = [];
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

export function loadShowcaseKeys(): ShowcaseKey[] {
  const filePath = path.join(process.cwd(), 'config', 'showcases-view-keys.json');
  if (fs.existsSync(filePath)) {
    try {
      const entries = parseEntries(JSON.parse(fs.readFileSync(filePath, 'utf-8')));
      if (entries.length > 0) return entries;
    } catch {
      // fall through to env-based sources
    }
  }

  const envJson = process.env.VIGOLIUM_SHOWCASES_KEYS;
  if (envJson) {
    try {
      const entries = parseEntries(JSON.parse(envJson));
      if (entries.length > 0) return entries;
    } catch {
      // fall through to legacy single-key
    }
  }

  const legacy = process.env.VIGOLIUM_SHOWCASES_KEY;
  if (legacy) {
    return [{ key: legacy, label: 'default' }];
  }

  return [];
}

export function validateShowcaseKey(viewKey: string | null | undefined): ValidationResult {
  const keys = loadShowcaseKeys();
  if (keys.length === 0) return { valid: false, reason: 'no_keys' };
  if (!viewKey) return { valid: false, reason: 'no_match' };

  const match = keys.find((k) => k.key === viewKey);
  if (!match) return { valid: false, reason: 'no_match' };

  if (match.expires) {
    const expiresAt = Date.parse(match.expires);
    if (!Number.isNaN(expiresAt) && Date.now() > expiresAt) {
      return { valid: false, reason: 'expired', label: match.label };
    }
  }

  return { valid: true, label: match.label };
}
