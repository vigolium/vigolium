'use client';

import { useEffect } from 'react';
import { useDemoRouter } from '@/lib/useDemoHref';

export default function ConfigRoute() {
  const router = useDemoRouter();
  useEffect(() => {
    router.replace('/settings');
  }, [router]);
  return null;
}
