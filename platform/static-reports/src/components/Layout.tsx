import type { ReactNode } from "react";

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen bg-cream paper-texture relative">
      <div className="relative z-10">{children}</div>
    </div>
  );
}
