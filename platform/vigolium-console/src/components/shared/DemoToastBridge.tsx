'use client';

import { useEffect } from 'react';
import { onDemoBlocked } from '@/api/client';
import { useToast } from '@/contexts/ToastContext';

export default function DemoToastBridge() {
  const { toast } = useToast();

  useEffect(() => {
    return onDemoBlocked(() => {
      toast('This action is disabled in demo mode', 'info');
    });
  }, [toast]);

  return null;
}
