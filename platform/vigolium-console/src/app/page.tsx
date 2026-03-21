'use client';

import { useTheme } from '@/contexts/ThemeContext';
import DarkDashboard from '@/designs/dark/DashboardPage';
import LightDashboard from '@/designs/light/DashboardPage';

export default function HomePage() {
  const { themeId } = useTheme();
  return themeId === 'dark' ? <DarkDashboard /> : <LightDashboard />;
}
