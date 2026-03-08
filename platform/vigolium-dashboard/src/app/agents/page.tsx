'use client';

import { useTheme } from '@/contexts/ThemeContext';
import DarkAgentsPage from '@/designs/dark/AgentsPage';
import LightAgentsPage from '@/designs/light/AgentsPage';

export default function AgentsRoute() {
  const { themeId } = useTheme();
  return themeId === 'dark' ? <DarkAgentsPage /> : <LightAgentsPage />;
}
