'use client';

import { useCallback, useMemo } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';

/** Append `demo_key=<key>` to a path string unless it already has one. */
export function appendDemoKey(href: string, key: string | null): string {
  if (!key) return href;

  // External URLs or hash-only links are left alone
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(href) || href.startsWith('//') || href.startsWith('#')) {
    return href;
  }

  const [pathAndQuery, fragment] = href.split('#');
  const [path, query = ''] = pathAndQuery.split('?');
  const params = new URLSearchParams(query);
  if (!params.has('demo_key')) {
    params.set('demo_key', key);
  }
  const qs = params.toString();
  const rebuilt = qs ? `${path}?${qs}` : path;
  return fragment ? `${rebuilt}#${fragment}` : rebuilt;
}

/** Returns the current request's `demo_key` (if any) so it can be preserved across navigation. */
export function useDemoKey(): string | null {
  const searchParams = useSearchParams();
  return searchParams?.get('demo_key') ?? null;
}

/**
 * Rewrite an href so it carries the current `demo_key` query param.
 * Use for `<Link href=…>` and similar.
 */
export function useDemoHref(href: string): string {
  const demoKey = useDemoKey();
  return useMemo(() => appendDemoKey(href, demoKey), [href, demoKey]);
}

type PushOptions = Parameters<ReturnType<typeof useRouter>['push']>[1];

/** `useRouter()` whose push/replace automatically carry the current demo_key. */
export function useDemoRouter() {
  const router = useRouter();
  const demoKey = useDemoKey();

  const push = useCallback(
    (href: string, options?: PushOptions) => router.push(appendDemoKey(href, demoKey), options),
    [router, demoKey],
  );
  const replace = useCallback(
    (href: string, options?: PushOptions) => router.replace(appendDemoKey(href, demoKey), options),
    [router, demoKey],
  );
  const prefetch = useCallback(
    (href: string, options?: Parameters<ReturnType<typeof useRouter>['prefetch']>[1]) =>
      router.prefetch(appendDemoKey(href, demoKey), options),
    [router, demoKey],
  );

  return useMemo(
    () => ({
      ...router,
      push,
      replace,
      prefetch,
    }),
    [router, push, replace, prefetch],
  );
}
