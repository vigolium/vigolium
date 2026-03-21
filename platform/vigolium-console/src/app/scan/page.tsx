'use client';

import { useTheme } from '@/contexts/ThemeContext';
import DarkScanPage from '@/designs/dark/ScanPage';
import LightScanPage from '@/designs/light/ScanPage';

export default function ScanRoute() {
  const { themeId } = useTheme();
  return themeId === 'dark' ? <DarkScanPage /> : <LightScanPage />;
}
