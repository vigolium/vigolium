'use client';

import { createContext, useContext, useState, useEffect, useCallback, useLayoutEffect, useMemo, type ReactNode } from 'react';
import {
  type ColorScheme,
  COLOR_SCHEMES,
  DEFAULT_DARK_SCHEME,
  DEFAULT_LIGHT_SCHEME,
  getScheme,
  applySchemeVars,
} from '@/lib/colorSchemes';

export type ThemeId = 'dark' | 'light';

interface ThemeContextValue {
  themeId: ThemeId;
  schemeId: string;
  scheme: ColorScheme;
  setScheme: (id: string) => void;
  toggleTheme: () => void;
}

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

const SCHEME_KEY = 'vigolium_scheme';
const LAST_DARK_KEY = 'vigolium_last_dark';
const LAST_LIGHT_KEY = 'vigolium_last_light';
const OLD_THEME_KEY = 'vigolium_theme';

// useLayoutEffect on the client (so scheme vars apply before first paint),
// useEffect on the server (no-op — avoids the SSR warning).
const useIsoLayoutEffect = typeof window !== 'undefined' ? useLayoutEffect : useEffect;

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [schemeId, setSchemeId] = useState(DEFAULT_DARK_SCHEME);

  useIsoLayoutEffect(() => {
    const stored = localStorage.getItem(SCHEME_KEY);
    if (stored && COLOR_SCHEMES.some(s => s.id === stored)) {
      if (stored !== schemeId) setSchemeId(stored);
      applySchemeVars(getScheme(stored).colors);
    } else {
      // Migrate from old theme key
      const old = localStorage.getItem(OLD_THEME_KEY);
      const migrated = old === 'light' ? DEFAULT_LIGHT_SCHEME : DEFAULT_DARK_SCHEME;
      if (migrated !== schemeId) setSchemeId(migrated);
      localStorage.setItem(SCHEME_KEY, migrated);
      const s = getScheme(migrated);
      applySchemeVars(s.colors);
      localStorage.setItem(s.base === 'dark' ? LAST_DARK_KEY : LAST_LIGHT_KEY, migrated);
    }
    // Run once on mount; setScheme handles updates afterward.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const scheme = getScheme(schemeId);
  const themeId = scheme.base;

  const setScheme = useCallback((id: string) => {
    const s = getScheme(id);
    setSchemeId(s.id);
    localStorage.setItem(SCHEME_KEY, s.id);
    localStorage.setItem(s.base === 'dark' ? LAST_DARK_KEY : LAST_LIGHT_KEY, s.id);
    applySchemeVars(s.colors);
  }, []);

  const toggleTheme = useCallback(() => {
    if (themeId === 'dark') {
      const target = localStorage.getItem(LAST_LIGHT_KEY) || DEFAULT_LIGHT_SCHEME;
      setScheme(target);
    } else {
      const target = localStorage.getItem(LAST_DARK_KEY) || DEFAULT_DARK_SCHEME;
      setScheme(target);
    }
  }, [themeId, setScheme]);

  const value = useMemo<ThemeContextValue>(
    () => ({ themeId, schemeId, scheme, setScheme, toggleTheme }),
    [themeId, schemeId, scheme, setScheme, toggleTheme],
  );

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error('useTheme must be used within ThemeProvider');
  return ctx;
}
