import type { ReactNode } from 'react';

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <div
      className="min-h-screen bg-[#f6edda] text-[#005661]"
      style={{ fontFamily: '"IBM Plex Mono", "JetBrains Mono", monospace' }}
    >
      {children}
    </div>
  );
}
