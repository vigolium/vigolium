import type { ErrorResponse } from './types';

const TOKEN_KEY = 'vigolium_api_token';
const URL_KEY = 'vigolium_api_url';
const PROJECT_KEY = 'vigolium_project_uuid';
const USER_KEY = 'vigolium_user_info';

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

// Event emitter for auth state changes
type AuthListener = () => void;
const authListeners: AuthListener[] = [];

export function onAuthRequired(listener: AuthListener) {
  authListeners.push(listener);
  return () => {
    const idx = authListeners.indexOf(listener);
    if (idx >= 0) authListeners.splice(idx, 1);
  };
}

function emitAuthRequired() {
  authListeners.forEach((fn) => fn());
}

export function getBaseUrl(): string {
  if (typeof window !== 'undefined') {
    const stored = localStorage.getItem(URL_KEY);
    if (stored) return stored;
    return process.env.NEXT_PUBLIC_API_BASE_URL || window.location.origin;
  }
  return process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:9002';
}

export function setBaseUrl(url: string) {
  localStorage.setItem(URL_KEY, url);
}

export function getToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearAuth() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

export interface UserInfo {
  uuid: string;
  name: string;
  email: string;
  role: string;
}

export function getUserInfo(): UserInfo | null {
  if (typeof window === 'undefined') return null;
  const stored = localStorage.getItem(USER_KEY);
  if (!stored) return null;
  try { return JSON.parse(stored); } catch { return null; }
}

export function setUserInfo(user: UserInfo) {
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export async function fetchUserInfo(): Promise<UserInfo | null> {
  try {
    const base = getBaseUrl();
    const token = getToken();
    const headers: Record<string, string> = {};
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    const res = await fetch(new URL('/api/user/info', base).toString(), {
      headers,
    });
    if (!res.ok) return null;
    const user: UserInfo = await res.json();
    setUserInfo(user);
    return user;
  } catch {
    return null;
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const base = getBaseUrl();
  const url = new URL(path, base);
  const token = getToken();

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  const projectUUID = getProjectUUID();
  if (projectUUID) {
    headers['X-Project-UUID'] = projectUUID;
  }

  const res = await fetch(url.toString(), {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (res.status === 401) {
    emitAuthRequired();
    throw new ApiError('Unauthorized', 401);
  }

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

export async function apiUpload<T>(path: string, file: File): Promise<T> {
  const base = getBaseUrl();
  const url = new URL(path, base);
  const token = getToken();

  const headers: Record<string, string> = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  const projectUUID = getProjectUUID();
  if (projectUUID) {
    headers['X-Project-UUID'] = projectUUID;
  }

  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(url.toString(), {
    method: 'POST',
    headers,
    body: formData,
  });

  if (res.status === 401) {
    emitAuthRequired();
    throw new ApiError('Unauthorized', 401);
  }

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

// Login with username + access_code via POST /api/auth/login
export async function login(username: string, accessCode: string): Promise<{ token: string; user: { uuid: string; name: string; email: string; role: string } }> {
  const base = getBaseUrl();
  const res = await fetch(new URL('/api/auth/login', base).toString(), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, access_code: accessCode }),
  });

  if (!res.ok) {
    let errBody: ErrorResponse | undefined;
    try {
      errBody = await res.json();
    } catch {
      // ignore
    }
    throw new ApiError(
      errBody?.error || 'login failed',
      errBody?.code || res.status,
    );
  }

  return res.json();
}

// Check if backend requires auth
export async function checkServerInfo(): Promise<{ ok: boolean; noAuth: boolean }> {
  try {
    const base = getBaseUrl();
    const res = await fetch(new URL('/server-info', base).toString());
    return { ok: res.ok, noAuth: res.ok };
  } catch {
    return { ok: false, noAuth: false };
  }
}
