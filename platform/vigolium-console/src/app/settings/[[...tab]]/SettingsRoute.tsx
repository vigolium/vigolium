'use client';

import { use } from 'react';
import { useTheme } from '@/contexts/ThemeContext';
import { isStaticBuild } from '@/lib/buildMode';
import DarkSettingsPage from '@/designs/dark/SettingsPage';
import LightSettingsPage from '@/designs/light/SettingsPage';

const STATIC_TABS = ['config', 'projects', 'theme', 'about'];
const CLOUD_TABS = ['profile', 'team', 'console', 'theme'];

export default function SettingsRoute({ params }: { params: Promise<{ tab?: string[] }> }) {
  const { tab } = use(params);
  const { themeId } = useTheme();

  const validTabs = isStaticBuild ? STATIC_TABS : CLOUD_TABS;
  const defaultTab = isStaticBuild ? 'config' : 'profile';
  const initialTab = tab?.[0] && validTabs.includes(tab[0]) ? tab[0] : defaultTab;

  const Page = themeId === 'dark' ? DarkSettingsPage : LightSettingsPage;
  return <Page initialTab={initialTab} />;
}
