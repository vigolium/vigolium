'use client';

import { useTheme } from '@/contexts/ThemeContext';
import DarkExtensionsPage from '@/designs/dark/ExtensionsPage';
import LightExtensionsPage from '@/designs/light/ExtensionsPage';

export default function ExtensionsRoute() {
  const { themeId } = useTheme();
  return themeId === 'dark' ? <DarkExtensionsPage /> : <LightExtensionsPage />;
}
