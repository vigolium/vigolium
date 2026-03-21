'use client';

import { useParams } from 'next/navigation';
import { useTheme } from '@/contexts/ThemeContext';
import DarkSourceReposPage from '@/designs/dark/SourceReposPage';
import LightSourceReposPage from '@/designs/light/SourceReposPage';

export default function SourceReposRoute() {
  const { themeId } = useTheme();
  const params = useParams();
  const segments = params?.id as string[] | undefined;
  const initialId = segments?.[0] ? Number(segments[0]) : null;
  return themeId === 'dark'
    ? <DarkSourceReposPage initialId={initialId} />
    : <LightSourceReposPage initialId={initialId} />;
}
