'use client';

import { useEffect } from 'react';
import { useDemoRouter } from '@/lib/useDemoHref';

export default function TeamRedirect() {
  const router = useDemoRouter();
  useEffect(() => {
    router.replace('/settings/team');
  }, [router]);
  return null;
}
