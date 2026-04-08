'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useTheme } from '@/contexts/ThemeContext';
import { isStaticBuild } from '@/lib/buildMode';
import DarkAuthGate from '@/designs/dark/AuthGatePage';
import LightAuthGate from '@/designs/light/AuthGatePage';
import ConfigError from '@/components/shared/ConfigError';

interface ConfigIssue {
  key: string;
  severity: 'error' | 'warning';
  message: string;
}

export default function LoginPage() {
  const { themeId } = useTheme();
  const router = useRouter();
  const [configIssues, setConfigIssues] = useState<ConfigIssue[] | null>(null);
  const [configOk, setConfigOk] = useState<boolean | null>(null);
  const [ssoDisabled, setSsoDisabled] = useState(false);

  useEffect(() => {
    // Static mode uses AuthGate in layout, not a separate login page
    if (isStaticBuild) {
      router.replace('/');
      return;
    }

    // Check server config on mount
    fetch('/api/config-check')
      .then((res) => res.json())
      .then((data) => {
        setConfigOk(data.ok);
        setConfigIssues(data.issues || []);
        setSsoDisabled(data.ssoDisabled ?? false);
      })
      .catch(() => {
        // If config-check itself fails, assume config is broken
        setConfigOk(false);
        setConfigIssues([{ key: 'SERVER', severity: 'error', message: 'Could not reach the config-check endpoint. The server may be misconfigured.' }]);
      });
  }, [router]);

  if (isStaticBuild) return null;

  // Show config error page if there are critical issues
  if (configOk === false && configIssues) {
    return <ConfigError issues={configIssues} />;
  }

  // Still loading config check — show nothing briefly
  if (configOk === null) return null;

  return themeId === 'dark' ? <DarkAuthGate ssoDisabled={ssoDisabled} /> : <LightAuthGate ssoDisabled={ssoDisabled} />;
}
