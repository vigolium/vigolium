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
      <footer className="px-4 py-2 flex items-center justify-center gap-3 text-[10px] border-t" style={{ borderColor: 'var(--v-border)', color: 'var(--v-text-muted)' }}>
        <a href="https://www.vigolium.com/" target="_blank" rel="noopener noreferrer" className="hover:underline" style={{ color: 'var(--v-accent)' }}>vigolium.com</a>
        <span>·</span>
        <a href="https://docs.vigolium.com/" target="_blank" rel="noopener noreferrer" className="hover:underline" style={{ color: 'var(--v-accent)' }}>docs</a>
      </footer>
    </Layout>
  );
}
