'use client';

import { useTheme } from '@/contexts/ThemeContext';
import DarkModulesPage from '@/designs/dark/ModulesPage';
import LightModulesPage from '@/designs/light/ModulesPage';

export default function ModulesRoute() {
  const { themeId } = useTheme();
  return themeId === 'dark' ? <DarkModulesPage /> : <LightModulesPage />;
}
