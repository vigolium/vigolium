'use client';

import { useTheme } from '@/contexts/ThemeContext';
import DarkConfigPage from '@/designs/dark/ConfigPage';
import LightConfigPage from '@/designs/light/ConfigPage';

export default function ConfigRoute() {
  const { themeId } = useTheme();
  return themeId === 'dark' ? <DarkConfigPage /> : <LightConfigPage />;
}
