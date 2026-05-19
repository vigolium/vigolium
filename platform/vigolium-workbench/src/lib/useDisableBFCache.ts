'use client';

import { useEffect } from 'react';

/**
 * Disqualifies the current page from the browser's back/forward cache.
 *
 * Why: any page that (a) drives readiness with `useEffect` + `setReady(true)`,
 * or (b) leaves via `window.location` to an external/server-rendered URL, is at
 * risk of being restored from a frozen BFCache snapshot when the user clicks
 * back. The snapshot replays in-flight fetches as aborted, so `loading=true`
 * sticks forever and the page renders blank or half-rendered.
 *
 * How: a no-op `beforeunload` listener disqualifies the page from BFCache in
 * all major browsers (no dialog appears unless `preventDefault` is called).
 * The `pageshow.persisted` handler is a safety net — if any browser still
 * serves a snapshot, we cache-bust the URL and force a fresh load.
 *
 * Apply on every client page that hits at least one of these patterns:
 *   - Mounts and immediately fetches state needed to render (`/welcome`,
 *     `/billing`, `/login` — the demo/config-check race).
 *   - Issues `window.location.href = ...` to a non-Next.js URL (Polar, WorkOS).
 *   - Hosts an interactive flow that BFCache can freeze mid-state.
 */
export function useDisableBFCache() {
  useEffect(() => {
    const blockBfcache = () => {};
    const onPageShow = (e: PageTransitionEvent) => {
      if (e.persisted) {
        const url = new URL(window.location.href);
        url.searchParams.set('_t', String(Date.now()));
        window.location.replace(url.toString());
      }
    };
    window.addEventListener('beforeunload', blockBfcache);
    window.addEventListener('pageshow', onPageShow);
    return () => {
      window.removeEventListener('beforeunload', blockBfcache);
      window.removeEventListener('pageshow', onPageShow);
    };
  }, []);
}
