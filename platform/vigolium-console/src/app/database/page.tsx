'use client';

import { useTheme } from '@/contexts/ThemeContext';
import DarkDatabasePage from '@/designs/dark/DatabasePage';
import LightDatabasePage from '@/designs/light/DatabasePage';

export default function DatabaseRoute() {
  const { themeId } = useTheme();
  return themeId === 'dark' ? <DarkDatabasePage /> : <LightDatabasePage />;
}
