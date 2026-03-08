import type { ReactNode } from 'react';

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <div
      className="min-h-screen bg-[#1c1b19] text-[#fce8c3]"
      style={{ fontFamily: '"JetBrains Mono", "Fira Code", monospace' }}
    >
      {children}
    </div>
  );
}
