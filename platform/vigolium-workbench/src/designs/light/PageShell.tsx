'use client';

import type { ReactNode } from 'react';
import { useServerInfo } from '@/api/hooks';
import Layout from './Layout';
import Header from './Header';
import Navigation from './Navigation';

export default function PageShell({ children }: { children: ReactNode }) {
  const { data: serverInfo, isSuccess: isConnected } = useServerInfo();

  return (
    <Layout>
      <Header serverInfo={serverInfo} isConnected={isConnected} />
      <Navigation />
      <main className="px-0 pt-0 pb-0">
        {children}
      </main>
    </Layout>
  );
}
