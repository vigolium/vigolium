'use client';

import { useEffect, useState } from 'react';

/**
 * Drop-in alternative to `useSearchParams()` from `next/navigation` that does NOT
 * trigger the static-prerender CSR bailout (and the dev-mode hydration mismatch
 * that comes with it).
 *
 * Returns an empty `URLSearchParams` on the server and on the very first client
 * render — so SSR HTML matches the initial client render. The actual values are
 * populated after mount via a `useEffect` reading `window.location.search`.
 *
 * Listens to `popstate` so back/forward updates are reflected. Programmatic
 * pushes via the Next router don't fire `popstate`, but they remount the
 * consuming component anyway when navigating between pages, so the stale-link
 * window is small and inherent to client-only routing reads.
 */
export function useSearchParamsClient(): URLSearchParams {
  const [params, setParams] = useState<URLSearchParams>(() => new URLSearchParams());
  useEffect(() => {
    const update = () => setParams(new URLSearchParams(window.location.search));
    update();
    window.addEventListener('popstate', update);
    return () => window.removeEventListener('popstate', update);
  }, []);
  return params;
}
