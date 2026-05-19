'use client';

import { useEffect } from 'react';
import { useTheme } from '@/contexts/ThemeContext';
import { isCloudBuild } from '@/lib/buildMode';
import { useDemoRouter } from '@/lib/useDemoHref';
import DarkDatabasePage from '@/designs/dark/DatabasePage';
import LightDatabasePage from '@/designs/light/DatabasePage';

export default function DatabaseRoute() {
  const { themeId } = useTheme();
  const router = useDemoRouter();

  useEffect(() => {
    // Database page is not available in cloud mode
    if (isCloudBuild) {
      router.replace('/');
    }
  }, [router]);

  if (isCloudBuild) return null;

  return themeId === 'dark' ? <DarkDatabasePage /> : <LightDatabasePage />;
}
