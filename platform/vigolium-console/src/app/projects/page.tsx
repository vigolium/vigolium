'use client';

import { useTheme } from '@/contexts/ThemeContext';
import DarkProjectsPage from '@/designs/dark/ProjectsPage';
import LightProjectsPage from '@/designs/light/ProjectsPage';

export default function ProjectsRoute() {
  const { themeId } = useTheme();
  return themeId === 'dark' ? <DarkProjectsPage /> : <LightProjectsPage />;
}
