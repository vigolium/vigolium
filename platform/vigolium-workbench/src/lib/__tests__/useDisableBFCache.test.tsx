import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook } from '@testing-library/react';
import { useDisableBFCache } from '../useDisableBFCache';

describe('useDisableBFCache', () => {
  let addSpy: ReturnType<typeof vi.spyOn>;
  let removeSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    addSpy = vi.spyOn(window, 'addEventListener');
    removeSpy = vi.spyOn(window, 'removeEventListener');
  });

  afterEach(() => {
    addSpy.mockRestore();
    removeSpy.mockRestore();
  });

  it('attaches beforeunload + pageshow listeners on mount', () => {
    renderHook(() => useDisableBFCache());

    const events = addSpy.mock.calls.map((c: unknown[]) => c[0]);
    expect(events).toContain('beforeunload');
    expect(events).toContain('pageshow');
  });

  it('removes listeners on unmount', () => {
    const { unmount } = renderHook(() => useDisableBFCache());
    unmount();

    const events = removeSpy.mock.calls.map((c: unknown[]) => c[0]);
    expect(events).toContain('beforeunload');
    expect(events).toContain('pageshow');
  });

  it('cache-busts and reloads when restored from BFCache', () => {
    const replaceSpy = vi.fn();
    const originalLocation = window.location;
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: {
        ...originalLocation,
        href: 'http://localhost/welcome?foo=bar',
        replace: replaceSpy,
      },
    });

    let pageShowHandler: ((e: PageTransitionEvent) => void) | null = null;
    addSpy.mockImplementation((event: string, handler: EventListenerOrEventListenerObject) => {
      if (event === 'pageshow') pageShowHandler = handler as (e: PageTransitionEvent) => void;
    });

    renderHook(() => useDisableBFCache());

    expect(pageShowHandler).not.toBeNull();
    pageShowHandler!({ persisted: true } as PageTransitionEvent);

    expect(replaceSpy).toHaveBeenCalledTimes(1);
    const newUrl = replaceSpy.mock.calls[0][0] as string;
    expect(newUrl).toContain('foo=bar');
    expect(newUrl).toMatch(/_t=\d+/);

    Object.defineProperty(window, 'location', {
      configurable: true,
      value: originalLocation,
    });
  });

  it('does NOT reload on a regular pageshow (not from BFCache)', () => {
    const replaceSpy = vi.fn();
    const originalLocation = window.location;
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...originalLocation, href: 'http://localhost/welcome', replace: replaceSpy },
    });

    let pageShowHandler: ((e: PageTransitionEvent) => void) | null = null;
    addSpy.mockImplementation((event: string, handler: EventListenerOrEventListenerObject) => {
      if (event === 'pageshow') pageShowHandler = handler as (e: PageTransitionEvent) => void;
    });

    renderHook(() => useDisableBFCache());
    pageShowHandler!({ persisted: false } as PageTransitionEvent);

    expect(replaceSpy).not.toHaveBeenCalled();

    Object.defineProperty(window, 'location', {
      configurable: true,
      value: originalLocation,
    });
  });
});
