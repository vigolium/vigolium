import type { ReactNode } from "react";

interface Props {
  children: ReactNode;
}

export default function SectionTitle({ children }: Props) {
  return (
    <h2 className="font-serif text-2xl font-bold text-charcoal mb-6 tracking-tight">
      {children}
    </h2>
  );
}
