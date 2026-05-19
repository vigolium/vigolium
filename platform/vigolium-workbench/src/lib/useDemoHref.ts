'use client';

import { useRouter } from 'next/navigation';

/**
 * Workbench has no demo mode. These exports are kept as no-op shims so the
 * codebase that originated from the unified console keeps compiling.
 */
export function useDemoKey(): string | null {
  return null;
}

export function useDemoHref(href: string): string {
  return href;
}

export function useDemoRouter() {
  return useRouter();
}
