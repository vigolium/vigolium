'use client';

import { useTheme } from '@/contexts/ThemeContext';
import DarkScopePage from '@/designs/dark/ScopePage';
import LightScopePage from '@/designs/light/ScopePage';

export default function ScopeRoute() {
  const { themeId } = useTheme();
  return themeId === 'dark' ? <DarkScopePage /> : <LightScopePage />;
}
