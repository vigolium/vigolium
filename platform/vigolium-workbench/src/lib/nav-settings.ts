import { useSyncExternalStore } from 'react';

const STORAGE_KEY = 'vigolium_hidden_pages';

/** Pages that are hidden from the cloud nav by default. */
const DEFAULT_HIDDEN: string[] = [
  '/oast-interactions',
  '/modules',
  '/extensions',
];

/** All toggleable pages in cloud mode (label → href). */
export const TOGGLEABLE_PAGES: { href: string; label: string }[] = [
  { href: '/oast-interactions', label: 'OAST' },
  { href: '/modules', label: 'MODULES' },
  { href: '/extensions', label: 'EXTENSIONS' },
];

const listeners = new Set<() => void>();
let cachedSnapshot: Set<string> | null = null;
let cachedSerialized: string | null = null;

function readSet(): Set<string> {
  if (typeof window === 'undefined') return new Set(DEFAULT_HIDDEN);
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored === null) return new Set(DEFAULT_HIDDEN);
  try {
    return new Set(JSON.parse(stored) as string[]);
  } catch {
    return new Set(DEFAULT_HIDDEN);
  }
}

function getClientSnapshot(): Set<string> {
  if (typeof window === 'undefined') return new Set(DEFAULT_HIDDEN);
  const raw = localStorage.getItem(STORAGE_KEY) ?? '';
  if (cachedSnapshot && cachedSerialized === raw) return cachedSnapshot;
  cachedSerialized = raw;
  cachedSnapshot = readSet();
  return cachedSnapshot;
}

const SERVER_SNAPSHOT: Set<string> = new Set(DEFAULT_HIDDEN);
function getServerSnapshot(): Set<string> {
  return SERVER_SNAPSHOT;
}

function subscribe(callback: () => void): () => void {
  listeners.add(callback);
  const onStorage = (e: StorageEvent) => {
    if (e.key === STORAGE_KEY) {
      cachedSnapshot = null;
      callback();
    }
  };
  if (typeof window !== 'undefined') {
    window.addEventListener('storage', onStorage);
  }
  return () => {
    listeners.delete(callback);
    if (typeof window !== 'undefined') {
      window.removeEventListener('storage', onStorage);
    }
  };
}

/**
 * Reactive hook for the hidden-pages set. Server and first client render both
 * return DEFAULT_HIDDEN, avoiding hydration mismatch; the actual localStorage
 * value is committed on the next client render.
 */
export function useHiddenPages(): Set<string> {
  return useSyncExternalStore(subscribe, getClientSnapshot, getServerSnapshot);
}

export function setHiddenPages(hidden: Set<string>) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify([...hidden]));
  cachedSnapshot = null;
  for (const listener of listeners) listener();
}
