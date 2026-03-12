import type { ReactNode } from 'react';

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <div
      className="min-h-screen"
      style={{
        backgroundColor: 'var(--v-bg, #f6edda)',
        color: 'var(--v-text, #005661)',
        fontFamily: '"IBM Plex Mono", "JetBrains Mono", monospace',
      }}
    >
      {children}
    </div>
  );
}
