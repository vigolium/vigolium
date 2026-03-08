'use client';

import { createContext, useContext, useState, useEffect, type ReactNode } from 'react';

export type ThemeId = 'dark' | 'light';

interface ThemeContextValue {
  themeId: ThemeId;
  toggleTheme: () => void;
}

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

const STORAGE_KEY = 'vigolium_theme';

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [themeId, setThemeId] = useState<ThemeId>('dark');
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    // Migrate from old design picker key
    const legacy = localStorage.getItem('vigolium_last_design');
    if (stored === 'dark' || stored === 'light') {
      setThemeId(stored);
    } else if (stored === 'editorial' || legacy === '6') {
      setThemeId('light');
      localStorage.setItem(STORAGE_KEY, 'light');
    } else {
      // default dark or migrated from 'terminal'/'4'
      setThemeId('dark');
      localStorage.setItem(STORAGE_KEY, 'dark');
    }
    setMounted(true);
  }, []);

  const toggleTheme = () => {
    setThemeId((prev) => {
      const next = prev === 'dark' ? 'light' : 'dark';
      localStorage.setItem(STORAGE_KEY, next);
      return next;
    });
  };

  // Avoid hydration mismatch by not rendering until mounted
  if (!mounted) return null;

  return (
    <ThemeContext.Provider value={{ themeId, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error('useTheme must be used within ThemeProvider');
  return ctx;
}
