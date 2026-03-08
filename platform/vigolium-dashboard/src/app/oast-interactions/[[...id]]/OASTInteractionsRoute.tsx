'use client';

import { useParams } from 'next/navigation';
import { useTheme } from '@/contexts/ThemeContext';
import DarkOASTInteractionsPage from '@/designs/dark/OASTInteractionsPage';
import LightOASTInteractionsPage from '@/designs/light/OASTInteractionsPage';

export default function OASTInteractionsRoute() {
  const { themeId } = useTheme();
  const params = useParams();
  const segments = params?.id as string[] | undefined;
  const initialId = segments?.[0] ? Number(segments[0]) : null;
  return themeId === 'dark'
    ? <DarkOASTInteractionsPage initialId={initialId} />
    : <LightOASTInteractionsPage initialId={initialId} />;
}
