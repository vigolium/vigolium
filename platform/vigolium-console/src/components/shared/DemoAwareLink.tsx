'use client';

import NextLink, { type LinkProps } from 'next/link';
import type { ComponentPropsWithoutRef, ReactNode } from 'react';
import { useDemoHref } from '@/lib/useDemoHref';

type AnchorProps = Omit<ComponentPropsWithoutRef<'a'>, keyof LinkProps>;

interface DemoAwareLinkProps extends AnchorProps, Omit<LinkProps, 'href'> {
  href: string;
  children?: ReactNode;
}

/**
 * Drop-in replacement for `next/link` `<Link>` that preserves the current URL's
 * `demo_key` query param across navigation. String-only hrefs by design — the
 * UrlObject form isn't used in this codebase.
 */
export default function DemoAwareLink({ href, children, ...rest }: DemoAwareLinkProps) {
  const resolved = useDemoHref(href);
  return (
    <NextLink href={resolved} {...rest}>
      {children}
    </NextLink>
  );
}
