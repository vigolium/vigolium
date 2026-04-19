'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useTheme } from '@/contexts/ThemeContext';
import { isStaticBuild } from '@/lib/buildMode';
import DarkAuthGate from '@/designs/dark/AuthGatePage';
import LightAuthGate from '@/designs/light/AuthGatePage';
import ConfigError from '@/components/shared/ConfigError';
import DemoUnlockPage from '@/components/shared/DemoUnlockPage';

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
  const [showcasesEnabled, setShowcasesEnabled] = useState(false);
  const [demoFeatureEnabled, setDemoFeatureEnabled] = useState<boolean | null>(null);
  const [demoSkipAuth, setDemoSkipAuth] = useState(false);

  useEffect(() => {
    // Static mode uses AuthGate in layout, not a separate login page
    if (isStaticBuild) {
      router.replace('/');
      return;
    }

    // Check server config + demo status in parallel
    Promise.all([
      fetch('/api/config-check').then((res) => res.json()).catch(() => null),
      fetch('/api/demo/status').then((res) => res.json()).catch(() => null),
    ])
      .then(([cfg, demo]) => {
        if (cfg) {
          setConfigOk(cfg.ok);
          setConfigIssues(cfg.issues || []);
          setSsoDisabled(cfg.ssoDisabled ?? false);
          setShowcasesEnabled(cfg.showcasesEnabled ?? false);
        } else {
          setConfigOk(false);
          setConfigIssues([{ key: 'SERVER', severity: 'error', message: 'Could not reach the config-check endpoint. The server may be misconfigured.' }]);
        }
        setDemoFeatureEnabled(demo?.feature_enabled === true);
        setDemoSkipAuth(demo?.skip_auth === true);
      });
  }, [router]);

  if (isStaticBuild) return null;

  // Still loading — show nothing briefly
  if (configOk === null || demoFeatureEnabled === null) return null;

  // Demo-only mode takes over the login screen with a read-only unlock UI
  if (demoFeatureEnabled) {
    return <DemoUnlockPage showcasesEnabled={showcasesEnabled} skipAuth={demoSkipAuth} />;
  }

  // Show config error page if there are critical issues
  if (configOk === false && configIssues) {
    return <ConfigError issues={configIssues} />;
  }

  return themeId === 'dark'
    ? <DarkAuthGate ssoDisabled={ssoDisabled} showcasesEnabled={showcasesEnabled} />
    : <LightAuthGate ssoDisabled={ssoDisabled} showcasesEnabled={showcasesEnabled} />;
}
