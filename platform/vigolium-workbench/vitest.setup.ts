import '@testing-library/jest-dom/vitest';
import { afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';

// Node 25 ships an experimental built-in `localStorage` global that's a plain
// `{}` with no getItem/setItem/clear. It shadows the DOM env's Storage on
// `globalThis` (which jsdom and happy-dom both alias to `window`). Replace it
// with a minimal in-memory Storage implementation.
function makeStorage(): Storage {
  const data = new Map<string, string>();
  return {
    get length() {
      return data.size;
    },
    clear() {
      data.clear();
    },
    getItem(key: string) {
      return data.has(key) ? (data.get(key) as string) : null;
    },
    key(index: number) {
      return Array.from(data.keys())[index] ?? null;
    },
    removeItem(key: string) {
      data.delete(key);
    },
    setItem(key: string, value: string) {
      data.set(key, String(value));
    },
  };
}

function installStorage(name: 'localStorage' | 'sessionStorage') {
  const store = makeStorage();
  Object.defineProperty(globalThis, name, {
    configurable: true,
    writable: true,
    value: store,
  });
  if (typeof window !== 'undefined' && globalThis !== window) {
    Object.defineProperty(window, name, {
      configurable: true,
      writable: true,
      value: store,
    });
  }
}

installStorage('localStorage');
installStorage('sessionStorage');

afterEach(() => {
  cleanup();
  globalThis.localStorage.clear();
  globalThis.sessionStorage.clear();
});

if (typeof window !== 'undefined') {
  if (!window.matchMedia) {
    window.matchMedia = (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    });
  }
  if (!window.ResizeObserver) {
    window.ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    };
  }
}

export { beforeAll, afterAll };
