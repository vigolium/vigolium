type PostHogLike = {
  __loaded?: boolean;
  capture: (event: string, props?: Record<string, unknown>) => void;
};

export function trackEvent(name: string, props?: Record<string, unknown>): void {
  if (typeof window === 'undefined') return;
  const posthog = (window as unknown as { posthog?: PostHogLike }).posthog;
  if (!posthog || !posthog.__loaded) return;
  posthog.capture(name, props);
}
