'use client';

import { useParams } from 'next/navigation';
import { useTheme } from '@/contexts/ThemeContext';
import DarkFindingsPage from '@/designs/dark/FindingsPage';
import LightFindingsPage from '@/designs/light/FindingsPage';

export default function FindingsRoute() {
  const { themeId } = useTheme();
  const params = useParams();
  const segments = params?.id as string[] | undefined;
  const initialId = segments?.[0] ? Number(segments[0]) : null;
  return themeId === 'dark'
    ? <DarkFindingsPage initialId={initialId} />
    : <LightFindingsPage initialId={initialId} />;
}
