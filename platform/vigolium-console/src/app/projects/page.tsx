'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useTheme } from '@/contexts/ThemeContext';
import { isStaticBuild } from '@/lib/buildMode';
import DarkProjectsPage from '@/designs/dark/ProjectsPage';
import LightProjectsPage from '@/designs/light/ProjectsPage';

export default function ProjectsRoute() {
  const { themeId } = useTheme();
  const router = useRouter();

  useEffect(() => {
    if (isStaticBuild) router.replace('/settings/projects');
  }, [router]);

  if (isStaticBuild) return null;

  return themeId === 'dark' ? <DarkProjectsPage /> : <LightProjectsPage />;
}
