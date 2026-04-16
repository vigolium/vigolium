'use client';

import { useEffect } from 'react';
import { useTheme } from '@/contexts/ThemeContext';
import { isStaticBuild } from '@/lib/buildMode';
import { useDemoRouter } from '@/lib/useDemoHref';
import DarkProjectSelector from '@/designs/dark/ProjectSelectorPage';
import LightProjectSelector from '@/designs/light/ProjectSelectorPage';

export default function SelectProjectPage() {
  const { themeId } = useTheme();
  const router = useDemoRouter();

  useEffect(() => {
    // Static mode doesn't use this page — redirect to dashboard
    if (isStaticBuild) {
      router.replace('/');
    }
  }, [router]);

  if (isStaticBuild) return null;

  return themeId === 'dark' ? <DarkProjectSelector /> : <LightProjectSelector />;
}
