import type { ReactNode } from "react";

export default function Layout({ children }: { children: ReactNode }) {
  return <div className="relative min-h-screen">{children}</div>;
}
