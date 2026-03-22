'use client';

import { useTheme } from '@/contexts/ThemeContext';
import DarkAuthGate from '@/designs/dark/AuthGatePage';
import LightAuthGate from '@/designs/light/AuthGatePage';

export default function LoginPage() {
  const { themeId } = useTheme();
  return themeId === 'dark' ? <DarkAuthGate /> : <LightAuthGate />;
}
