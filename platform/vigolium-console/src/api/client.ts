import type { ErrorResponse } from './types';

const PROJECT_KEY = 'vigolium_project_uuid';

export function getProjectUUID(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem(PROJECT_KEY);
}

export function setProjectUUID(uuid: string | null) {
  if (uuid) {
    localStorage.setItem(PROJECT_KEY, uuid);
  } else {
    localStorage.removeItem(PROJECT_KEY);
  }
}

export class ApiError extends Error {
  code: number;
  details?: string;

  constructor(error: string, code: number, details?: string) {
    super(error);
    this.name = 'ApiError';
    this.code = code;
    this.details = details;
  }
}

export function getBaseUrl(): string {
  if (typeof window !== 'undefined') {
    // Route through server-side proxy — scan server URL is never exposed to the browser
    return `${window.location.origin}/api/proxy`;
  }
  return process.env.VIGOLIUM_SCAN_SERVER || 'http://localhost:9002';
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const base = getBaseUrl();
  const url = new URL(path, base);

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  const projectUUID = getProjectUUID();
  if (projectUUID) {
    headers['X-Project-UUID'] = projectUUID;
  }

  const res = await fetch(url.toString(), {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    let errBody: ErrorResponse | undefined;
    try {
      errBody = await res.json();
    } catch {
      // ignore parse error
    }
    throw new ApiError(
      errBody?.error || res.statusText,
      errBody?.code || res.status,
      errBody?.details
    );
  }

  return res.json();
}

export function apiGet<T>(path: string, params?: Record<string, string | number | undefined>): Promise<T> {
  let fullPath = path;
  if (params) {
    const sp = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== '') sp.set(k, String(v));
    }
    const qs = sp.toString();
    if (qs) fullPath += '?' + qs;
  }
  return request<T>('GET', fullPath);
}

export function apiPost<T>(path: string, body?: unknown): Promise<T> {
  return request<T>('POST', path, body);
}

export function apiPut<T>(path: string, body?: unknown): Promise<T> {
  return request<T>('PUT', path, body);
}

export function apiDelete<T>(path: string, body?: unknown): Promise<T> {
  return request<T>('DELETE', path, body);
}

export function apiUpload<T>(path: string, file: File): Promise<T> {
  const base = getBaseUrl();
  const url = new URL(path, base);

  const headers: Record<string, string> = {};
  const projectUUID = getProjectUUID();
  if (projectUUID) {
    headers['X-Project-UUID'] = projectUUID;
  }

  const formData = new FormData();
  formData.append('file', file);

  return fetch(url.toString(), {
    method: 'POST',
    headers,
    body: formData,
  }).then(async (res) => {
    if (!res.ok) {
      let errBody: ErrorResponse | undefined;
      try {
        errBody = await res.json();
      } catch {
        // ignore parse error
      }
      throw new ApiError(
        errBody?.error || res.statusText,
        errBody?.code || res.status,
        errBody?.details
      );
    }
    return res.json();
  });
}
