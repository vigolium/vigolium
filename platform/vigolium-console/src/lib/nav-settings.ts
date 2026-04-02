const STORAGE_KEY = 'vigolium_hidden_pages';

/** Pages that are hidden from the cloud nav by default. */
const DEFAULT_HIDDEN: string[] = [
  '/oast-interactions',
  '/source-repos',
  '/scope',
  '/modules',
  '/extensions',
];

/** All toggleable pages in cloud mode (label → href). */
export const TOGGLEABLE_PAGES: { href: string; label: string }[] = [
  { href: '/oast-interactions', label: 'OAST' },
  { href: '/source-repos', label: 'REPOS' },
  { href: '/scope', label: 'SCOPE' },
  { href: '/modules', label: 'MODULES' },
  { href: '/extensions', label: 'EXTENSIONS' },
];

export function getHiddenPages(): Set<string> {
  if (typeof window === 'undefined') return new Set(DEFAULT_HIDDEN);
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored === null) return new Set(DEFAULT_HIDDEN);
  try {
    return new Set(JSON.parse(stored) as string[]);
  } catch {
    return new Set(DEFAULT_HIDDEN);
  }
}

export function setHiddenPages(hidden: Set<string>) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify([...hidden]));
}

export function isPageHidden(href: string): boolean {
  return getHiddenPages().has(href);
}
