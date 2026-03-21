'use client';

import { use } from 'react';
import { useTheme } from '@/contexts/ThemeContext';
import DarkSettingsPage from '@/designs/dark/SettingsPage';
import LightSettingsPage from '@/designs/light/SettingsPage';

const VALID_TABS = ['config', 'projects', 'theme', 'about'] as const;
type SettingsTab = (typeof VALID_TABS)[number];

export default function SettingsRoute({ params }: { params: Promise<{ tab?: string[] }> }) {
  const { tab } = use(params);
  const { themeId } = useTheme();

  const initialTab: SettingsTab =
    tab?.[0] && VALID_TABS.includes(tab[0] as SettingsTab)
      ? (tab[0] as SettingsTab)
      : 'config';

  const Page = themeId === 'dark' ? DarkSettingsPage : LightSettingsPage;
  return <Page initialTab={initialTab} />;
}
