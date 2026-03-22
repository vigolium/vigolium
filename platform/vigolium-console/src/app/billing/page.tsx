'use client';

import { useTheme } from '@/contexts/ThemeContext';
import DarkBillingPage from '@/designs/dark/BillingPage';
import LightBillingPage from '@/designs/light/BillingPage';

export default function BillingRoute() {
  const { themeId } = useTheme();
  return themeId === 'dark' ? <DarkBillingPage /> : <LightBillingPage />;
}
