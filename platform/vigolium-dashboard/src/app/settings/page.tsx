'use client';

import { useTheme } from '@/contexts/ThemeContext';
import DarkSettingsPage from '@/designs/dark/SettingsPage';
import LightSettingsPage from '@/designs/light/SettingsPage';

export default function SettingsRoute() {
  const { themeId } = useTheme();
  return themeId === 'dark' ? <DarkSettingsPage /> : <LightSettingsPage />;
}
