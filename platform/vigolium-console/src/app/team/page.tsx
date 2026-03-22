'use client';

import { useTheme } from '@/contexts/ThemeContext';
import DarkTeamPage from '@/designs/dark/TeamPage';
import LightTeamPage from '@/designs/light/TeamPage';

export default function TeamRoute() {
  const { themeId } = useTheme();
  return themeId === 'dark' ? <DarkTeamPage /> : <LightTeamPage />;
}
