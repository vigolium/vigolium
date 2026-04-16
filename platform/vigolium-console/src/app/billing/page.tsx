'use client';

import { useEffect } from 'react';
import { useTheme } from '@/contexts/ThemeContext';
import { isStaticBuild } from '@/lib/buildMode';
import { useDemoRouter } from '@/lib/useDemoHref';
import DarkBillingPage from '@/designs/dark/BillingPage';
import LightBillingPage from '@/designs/light/BillingPage';

export default function BillingRoute() {
  const { themeId } = useTheme();
  const router = useDemoRouter();

  useEffect(() => {
    if (isStaticBuild) router.replace('/');
  }, [router]);

  if (isStaticBuild) return null;

  return themeId === 'dark' ? <DarkBillingPage /> : <LightBillingPage />;
}
