import type { ReactNode } from 'react';

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <div
      className="min-h-screen flex flex-col"
      style={{
        backgroundColor: 'var(--v-bg, #1c1b19)',
        color: 'var(--v-text, #fce8c3)',
        fontFamily: '"JetBrains Mono", "Fira Code", monospace',
      }}
    >
      {children}
    </div>
  );
}
