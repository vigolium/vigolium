/**
 * Main Entry Point
 *
 * Consolidates all services and tests entry-point specific patterns:
 * - Object property access (routes.dashboard)
 * - Arrow function parameters
 * - Loop with dynamic URL
 * - Multiple initialization patterns
 */

// Import all services
import { authService } from './services/authService';
import { userService } from './services/userService';
import { productService } from './services/productService';
import { analyticsService, analyticsServiceFunctional } from './services/analyticsService';
import { apiClient } from './utils/apiClient';
import { endpoints, routes, globalConfig, environment } from './config/endpoints';

// Import framework modules (they export functions/classes that may contain API calls)
import { useApi, useUser, useMutation } from './frameworks/react/useApi';
import { ApiService, ProductService, AuthService } from './frameworks/angular/api.service';
import { useAuth, useCrud, useSearch } from './frameworks/vue/useApi';
import { apiPlugin, authPlugin, analyticsPlugin } from './frameworks/vue/apiPlugin';

// Re-export for external use
export {
  authService,
  userService,
  productService,
  analyticsService,
  analyticsServiceFunctional,
  apiClient,
  endpoints,
  routes,
  globalConfig,
  environment,
  // React
  useApi,
  useUser,
  useMutation,
  // Angular
  ApiService,
  ProductService,
  AuthService,
  // Vue
  useAuth,
  useCrud,
  useSearch,
  apiPlugin,
  authPlugin,
  analyticsPlugin,
};

// Application class
class App {
  private initialized = false;

  // Pattern 1: Object property access for routes
  async init() {
    if (this.initialized) return;

    console.log('Initializing app...');

    // Pattern 2: Direct fetch in init
    const config = await fetch('/api/v1/app/config').then((r) => r.json());
    console.log('App config loaded:', config);

    // Pattern 3: Using routes object
    await apiClient.get(routes.dashboard);
    await apiClient.get(routes.settings);
    await apiClient.get(routes.notifications);

    // Pattern 4: Check auth status
    const isLoggedIn = await authService.checkSession();
    if (!isLoggedIn) {
      console.log('Not logged in, redirecting...');
      return;
    }

    // Pattern 5: Load user profile
    const profile = await userService.getProfile();
    console.log('User profile:', profile);

    // Pattern 6: Track app init
    analyticsService.trackEvent({
      name: 'app_initialized',
      properties: { version: '2.0' },
    });

    this.initialized = true;
  }

  // Pattern 7: Login flow
  async login(phone: string, password: string) {
    try {
      const result = await authService.login({ phone, password });
      console.log('Login successful');

      // Track login
      await analyticsServiceFunctional.track('user_login', {
        method: 'phone',
      });

      return result;
    } catch (error) {
      console.error('Login failed:', error);
      throw error;
    }
  }

  // Pattern 8: Load products with pagination
  async loadProducts(page = 1) {
    const products = await productService.listProducts(page, 20);

    // Pattern 9: Loop with dynamic URL (fetch each product detail)
    for (const product of products.products.slice(0, 3)) {
      await productService.getProduct(product.id);
    }

    return products;
  }

  // Pattern 10: Conditional API call based on user role
  async loadDashboard(isAdmin: boolean) {
    const dashboardUrl = isAdmin
      ? '/api/v1/admin/dashboard'
      : '/api/v1/user/dashboard';

    const dashboard = await apiClient.get(dashboardUrl);
    return dashboard;
  }

  // Pattern 11: Arrow function passed to map
  async loadMultipleUsers(userIds: string[]) {
    const fetchUser = (id: string) => fetch(`/api/v1/users/${id}`).then((r) => r.json());
    const users = await Promise.all(userIds.map(fetchUser));
    return users;
  }

  // Pattern 12: Complex data submission
  async submitOrder(items: Array<{ productId: string; quantity: number }>) {
    const orderData = {
      items: items.map((item) => ({
        product_id: item.productId,
        quantity: item.quantity,
      })),
      metadata: {
        source: 'web',
        timestamp: Date.now(),
        session_id: Math.random().toString(36),
      },
    };

    const result = await apiClient.post('/api/v1/orders/create', orderData);
    return result;
  }

  // Pattern 13: Health check endpoints
  async checkHealth() {
    const endpoints = [
      '/api/health',
      '/api/v1/health/db',
      '/api/v1/health/cache',
      '/api/v1/health/queue',
    ];

    const results = await Promise.all(
      endpoints.map((url) =>
        fetch(url)
          .then((r) => ({ url, status: r.status, ok: r.ok }))
          .catch(() => ({ url, status: 0, ok: false }))
      )
    );

    return results;
  }

  // Pattern 14: Upload with FormData
  async uploadFile(file: File, type: 'avatar' | 'document') {
    const uploadUrls = {
      avatar: '/api/v1/uploads/avatar',
      document: '/api/v1/uploads/document',
    };

    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch(uploadUrls[type], {
      method: 'POST',
      body: formData,
    });

    return response.json();
  }

  // Pattern 15: WebSocket connection
  connectRealtime(roomId: string) {
    const wsUrl = `${globalConfig.SOCKET_URL}/rooms/${roomId}`;
    const ws = new WebSocket(wsUrl);

    ws.onmessage = (event) => {
      console.log('Received:', event.data);
    };

    return ws;
  }

  // Pattern 16: Batch operations
  async batchUpdate(updates: Array<{ id: string; data: Record<string, unknown> }>) {
    await apiClient.post('/api/v1/batch/update', {
      operations: updates.map((u) => ({
        resource_id: u.id,
        update_data: u.data,
      })),
    });
  }

  // Pattern 17: Environment-based URL
  async getFeatureFlags() {
    const env = environment;
    const url = `${env.api.baseUrl}/feature-flags`;
    const response = await fetch(url);
    return response.json();
  }

  // Pattern 18: Retry logic with different endpoints
  async fetchWithFallback<T>(primaryUrl: string, fallbackUrl: string): Promise<T> {
    try {
      const response = await fetch(primaryUrl);
      if (!response.ok) throw new Error('Primary failed');
      return response.json() as Promise<T>;
    } catch {
      const response = await fetch(fallbackUrl);
      return response.json() as Promise<T>;
    }
  }
}

// Export app instance
export const app = new App();

// Auto-init on load (if in browser)
if (typeof window !== 'undefined') {
  window.addEventListener('DOMContentLoaded', () => {
    app.init().catch(console.error);
  });
}

// Default export
export default app;
