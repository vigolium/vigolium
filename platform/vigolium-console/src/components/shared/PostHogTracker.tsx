'use client';

import { useEffect } from 'react';
import { usePathname } from 'next/navigation';

const KEY = process.env.NEXT_PUBLIC_POSTHOG_KEY;
const HOST = process.env.NEXT_PUBLIC_POSTHOG_HOST || 'https://us.i.posthog.com';

export default function PostHogTracker() {
  const pathname = usePathname();

  useEffect(() => {
    if (!KEY) return;

    let cancelled = false;
    import('posthog-js').then(({ default: posthog }) => {
      if (cancelled) return;
      if (!posthog.__loaded) {
        posthog.init(KEY, {
          api_host: HOST,
          capture_pageview: false,
          autocapture: false,
          capture_pageleave: false,
        });
      }
      if (pathname === '/') posthog.capture('$pageview');
    });

    return () => { cancelled = true; };
  }, [pathname]);

  return null;
}
