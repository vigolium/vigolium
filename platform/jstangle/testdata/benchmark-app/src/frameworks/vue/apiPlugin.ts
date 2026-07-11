/**
 * Vue API Plugin
 *
 * Tests Vue plugin patterns:
 * - V3: Vue plugin with $api
 * - Global properties
 * - Provide/Inject patterns
 */

// Simulated Vue types
interface App {
  config: {
    globalProperties: Record<string, unknown>;
  };
  provide: (key: symbol | string, value: unknown) => void;
}

interface ApiPluginOptions {
  baseUrl?: string;
  timeout?: number;
  headers?: Record<string, string>;
}

// Pattern V3: Vue plugin with $api
export const apiPlugin = {
  install(app: App, options: ApiPluginOptions = {}) {
    const baseUrl = options.baseUrl ?? '/api/v1';
    const defaultHeaders = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    const api = {
      get: async <T>(url: string): Promise<T> => {
        const response = await fetch(`${baseUrl}${url}`, {
          method: 'GET',
          headers: defaultHeaders,
        });
        return response.json() as Promise<T>;
      },

      post: async <T>(url: string, data: unknown): Promise<T> => {
        const response = await fetch(`${baseUrl}${url}`, {
          method: 'POST',
          headers: defaultHeaders,
          body: JSON.stringify(data),
        });
        return response.json() as Promise<T>;
      },

      put: async <T>(url: string, data: unknown): Promise<T> => {
        const response = await fetch(`${baseUrl}${url}`, {
          method: 'PUT',
          headers: defaultHeaders,
          body: JSON.stringify(data),
        });
        return response.json() as Promise<T>;
      },

      delete: async <T>(url: string): Promise<T> => {
        const response = await fetch(`${baseUrl}${url}`, {
          method: 'DELETE',
          headers: defaultHeaders,
        });
        return response.json() as Promise<T>;
      },

      patch: async <T>(url: string, data: unknown): Promise<T> => {
        const response = await fetch(`${baseUrl}${url}`, {
          method: 'PATCH',
          headers: defaultHeaders,
          body: JSON.stringify(data),
        });
        return response.json() as Promise<T>;
      },
    };

    // Add to global properties
    app.config.globalProperties.$api = api;

    // Also provide for Composition API
    app.provide('api', api);
  },
};

// Pattern V4: Auth plugin
export const authPlugin = {
  install(app: App) {
    const auth = {
      token: null as string | null,

      async login(credentials: { username: string; password: string }): Promise<boolean> {
        try {
          const response = await fetch('/api/v1/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(credentials),
          });

          if (!response.ok) return false;

          const data = await response.json() as { token: string };
          this.token = data.token;
          localStorage.setItem('auth_token', data.token);
          return true;
        } catch {
          return false;
        }
      },

      async logout(): Promise<void> {
        await fetch('/api/v1/auth/logout', {
          method: 'POST',
          headers: this.token ? { Authorization: `Bearer ${this.token}` } : {},
        });
        this.token = null;
        localStorage.removeItem('auth_token');
      },

      async register(userData: {
        email: string;
        password: string;
        name: string;
      }): Promise<boolean> {
        try {
          const response = await fetch('/api/v1/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(userData),
          });
          return response.ok;
        } catch {
          return false;
        }
      },

      async refreshToken(): Promise<boolean> {
        const refreshToken = localStorage.getItem('refresh_token');
        if (!refreshToken) return false;

        try {
          const response = await fetch('/api/v1/auth/refresh', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refresh_token: refreshToken }),
          });

          if (!response.ok) return false;

          const data = await response.json() as { token: string };
          this.token = data.token;
          localStorage.setItem('auth_token', data.token);
          return true;
        } catch {
          return false;
        }
      },

      isAuthenticated(): boolean {
        return !!this.token || !!localStorage.getItem('auth_token');
      },
    };

    app.config.globalProperties.$auth = auth;
    app.provide('auth', auth);
  },
};

// Pattern V5: Analytics plugin
export const analyticsPlugin = {
  install(app: App, options: { endpoint?: string } = {}) {
    const endpoint = options.endpoint ?? '/api/v1/analytics';

    const analytics = {
      async track(event: string, properties?: Record<string, unknown>): Promise<void> {
        await fetch(`${endpoint}/track`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            event,
            properties,
            timestamp: Date.now(),
            page: window.location.pathname,
          }),
        });
      },

      async pageView(page?: string): Promise<void> {
        await fetch(`${endpoint}/pageview`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            page: page ?? window.location.pathname,
            referrer: document.referrer,
            timestamp: Date.now(),
          }),
        });
      },

      async identify(userId: string, traits?: Record<string, unknown>): Promise<void> {
        await fetch(`${endpoint}/identify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ user_id: userId, traits }),
        });
      },
    };

    app.config.globalProperties.$analytics = analytics;
    app.provide('analytics', analytics);
  },
};

// Pattern V6: Notification plugin
export const notificationPlugin = {
  install(app: App) {
    const notifications = {
      async fetch(): Promise<unknown[]> {
        const response = await fetch('/api/v1/notifications');
        const data = await response.json() as { notifications: unknown[] };
        return data.notifications;
      },

      async markAsRead(notificationId: string): Promise<void> {
        await fetch(`/api/v1/notifications/${notificationId}/read`, {
          method: 'POST',
        });
      },

      async markAllAsRead(): Promise<void> {
        await fetch('/api/v1/notifications/read-all', {
          method: 'POST',
        });
      },

      async getUnreadCount(): Promise<number> {
        const response = await fetch('/api/v1/notifications/unread-count');
        const data = await response.json() as { count: number };
        return data.count;
      },

      async updateSettings(settings: Record<string, boolean>): Promise<void> {
        await fetch('/api/v1/notifications/settings', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(settings),
        });
      },
    };

    app.config.globalProperties.$notifications = notifications;
    app.provide('notifications', notifications);
  },
};

// Pattern V7: Storage plugin with API sync
export const storagePlugin = {
  install(app: App) {
    const storage = {
      async get<T>(key: string): Promise<T | null> {
        // Try local first
        const local = localStorage.getItem(key);
        if (local) {
          return JSON.parse(local) as T;
        }

        // Fetch from API
        try {
          const response = await fetch(`/api/v1/storage/${key}`);
          if (!response.ok) return null;
          const data = await response.json() as { value: T };
          localStorage.setItem(key, JSON.stringify(data.value));
          return data.value;
        } catch {
          return null;
        }
      },

      async set<T>(key: string, value: T): Promise<void> {
        localStorage.setItem(key, JSON.stringify(value));

        // Sync to API
        await fetch(`/api/v1/storage/${key}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ value }),
        });
      },

      async remove(key: string): Promise<void> {
        localStorage.removeItem(key);
        await fetch(`/api/v1/storage/${key}`, { method: 'DELETE' });
      },

      async sync(): Promise<void> {
        const response = await fetch('/api/v1/storage/sync');
        const data = await response.json() as Record<string, unknown>;

        Object.entries(data).forEach(([key, value]) => {
          localStorage.setItem(key, JSON.stringify(value));
        });
      },
    };

    app.config.globalProperties.$storage = storage;
    app.provide('storage', storage);
  },
};
