'use client';

import { createContext, useContext, useState, useEffect, type ReactNode } from 'react';
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

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [schemeId, setSchemeId] = useState(DEFAULT_DARK_SCHEME);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    const stored = localStorage.getItem(SCHEME_KEY);
    if (stored && COLOR_SCHEMES.some(s => s.id === stored)) {
      setSchemeId(stored);
      applySchemeVars(getScheme(stored).colors);
    } else {
      // Migrate from old theme key
      const old = localStorage.getItem(OLD_THEME_KEY);
      const migrated = old === 'light' ? DEFAULT_LIGHT_SCHEME : DEFAULT_DARK_SCHEME;
      setSchemeId(migrated);
      localStorage.setItem(SCHEME_KEY, migrated);
      const s = getScheme(migrated);
      applySchemeVars(s.colors);
      localStorage.setItem(s.base === 'dark' ? LAST_DARK_KEY : LAST_LIGHT_KEY, migrated);
    }
    setMounted(true);
  }, []);

  const scheme = getScheme(schemeId);
  const themeId = scheme.base;

  const setScheme = (id: string) => {
    const s = getScheme(id);
    setSchemeId(s.id);
    localStorage.setItem(SCHEME_KEY, s.id);
    localStorage.setItem(s.base === 'dark' ? LAST_DARK_KEY : LAST_LIGHT_KEY, s.id);
    applySchemeVars(s.colors);
  };

  const toggleTheme = () => {
    if (themeId === 'dark') {
      const target = localStorage.getItem(LAST_LIGHT_KEY) || DEFAULT_LIGHT_SCHEME;
      setScheme(target);
    } else {
      const target = localStorage.getItem(LAST_DARK_KEY) || DEFAULT_DARK_SCHEME;
      setScheme(target);
    }
  };

  if (!mounted) return null;

  return (
    <ThemeContext.Provider value={{ themeId, schemeId, scheme, setScheme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error('useTheme must be used within ThemeProvider');
  return ctx;
}
