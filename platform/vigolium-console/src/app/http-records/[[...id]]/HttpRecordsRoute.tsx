'use client';

import { useParams } from 'next/navigation';
import { useTheme } from '@/contexts/ThemeContext';
import DarkHttpRecordsPage from '@/designs/dark/HttpRecordsPage';
import LightHttpRecordsPage from '@/designs/light/HttpRecordsPage';

export default function HttpRecordsRoute() {
  const { themeId } = useTheme();
  const params = useParams();
  const segments = params?.id as string[] | undefined;
  const initialId = segments?.[0] ?? null;
  return themeId === 'dark'
    ? <DarkHttpRecordsPage initialId={initialId} />
    : <LightHttpRecordsPage initialId={initialId} />;
}
