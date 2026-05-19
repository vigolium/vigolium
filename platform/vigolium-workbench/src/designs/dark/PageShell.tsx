'use client';

import type { ReactNode } from 'react';
import { Cloud } from 'lucide-react';
import { usePathname } from 'next/navigation';
import { useServerInfo } from '@/api/hooks';
import Layout from './Layout';
import Header from './Header';
import Navigation from './Navigation';

export default function PageShell({ children }: { children: ReactNode }) {
  const { data: serverInfo, isSuccess: isConnected } = useServerInfo();
  const pathname = usePathname();

  return (
    <Layout>
      <Header serverInfo={serverInfo} isConnected={isConnected} />
      <Navigation />
      <main key={pathname} className="v-page-enter px-0 pt-0 pb-0 flex-1 flex flex-col min-h-0">
        {children}
      </main>
      <footer className="px-4 py-2 flex items-center justify-center gap-3 text-[10px] border-t" style={{ borderColor: 'var(--v-border)', color: 'var(--v-text-muted)' }}>
        <a href="https://console.vigolium.com/" target="_blank" rel="noopener noreferrer" className="hover:underline flex items-center gap-1" style={{ color: 'var(--v-accent)' }}><Cloud className="w-3 h-3" />vigolium cloud</a>
        <span>·</span>
        <a href="https://www.vigolium.com/" target="_blank" rel="noopener noreferrer" className="hover:underline" style={{ color: 'var(--v-accent)' }}>website</a>
        <span>·</span>
        <a href="https://docs.vigolium.com/" target="_blank" rel="noopener noreferrer" className="hover:underline" style={{ color: 'var(--v-accent)' }}>docs</a>
        <span>·</span>
        <a href="mailto:contact@vigolium.com" className="hover:underline" style={{ color: 'var(--v-accent)' }}>contact us</a>
      </footer>
    </Layout>
  );
}
