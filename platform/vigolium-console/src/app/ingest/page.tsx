'use client';

import { useTheme } from '@/contexts/ThemeContext';
import DarkIngestPage from '@/designs/dark/IngestPage';
import LightIngestPage from '@/designs/light/IngestPage';

export default function IngestRoute() {
  const { themeId } = useTheme();
  return themeId === 'dark' ? <DarkIngestPage /> : <LightIngestPage />;
}
