/**
 * API Endpoint Constants
 *
 * This module exports all API endpoints as constants.
 * Used to test cross-module import resolution in webpack bundles.
 */

// AUTH endpoints (4)
export const endpoints = {
  AUTH_LOGIN: '/api/v1/auth/login',
  AUTH_LOGOUT: '/api/v1/auth/logout',
  AUTH_REFRESH: '/api/v1/auth/refresh',
  AUTH_REGISTER: '/api/v1/auth/register',

  // USER endpoints (5)
  USER_PROFILE: '/api/v1/users/profile',
  USER_BY_ID: '/api/v1/users',
  USER_UPDATE: '/api/v1/users/update',
  USER_DELETE: '/api/v1/users/delete',
  USER_AVATAR: '/api/v1/users/avatar',

  // PRODUCT endpoints (6)
  PRODUCT_LIST: '/api/v1/products',
  PRODUCT_BY_ID: '/api/v1/products',
  PRODUCT_CREATE: '/api/v1/products/create',
  PRODUCT_UPDATE: '/api/v1/products/update',
  PRODUCT_DELETE: '/api/v1/products/delete',
  PRODUCT_SEARCH: '/api/v1/products/search',

  // ANALYTICS endpoints (3)
  ANALYTICS_TRACK: '/api/v1/analytics/track',
  ANALYTICS_EVENTS: '/api/v1/analytics/events',
  ANALYTICS_REPORT: '/api/v1/analytics/report',

  // ORDER endpoints (4)
  ORDER_CREATE: '/api/v1/orders/create',
  ORDER_LIST: '/api/v1/orders',
  ORDER_BY_ID: '/api/v1/orders',
  ORDER_CANCEL: '/api/v1/orders/cancel',

  // NOTIFICATION endpoints (3)
  NOTIFICATION_LIST: '/api/v1/notifications',
  NOTIFICATION_READ: '/api/v1/notifications/read',
  NOTIFICATION_SETTINGS: '/api/v1/notifications/settings',
};

// Nested environment config - tests deep object resolution
export const environment = {
  api: {
    baseUrl: 'https://api.example.com',
    version: 'v1',
    timeout: 30000,
  },
  cdn: {
    baseUrl: 'https://cdn.example.com',
    imagePath: '/images',
  },
  features: {
    analytics: true,
    darkMode: false,
    newDashboard: true,
  },
};

// Global config pattern - tests this.API_URL resolution
export const globalConfig = {
  API_URL: '/site-api',
  BOB_URL: '/bob-service',
  SOCKET_URL: 'wss://ws.example.com',
  ADMIN_API: '/admin-api/v2',
};

// Routes object - tests object property access patterns
export const routes = {
  dashboard: '/api/v1/dashboard',
  settings: '/api/v1/settings',
  notifications: '/api/v1/notifications/all',
  profile: '/api/v1/me/profile',
  preferences: '/api/v1/me/preferences',
};

// URL builder function - tests function return value detection
export function buildUrl(path: string): string {
  return `${environment.api.baseUrl}${path}`;
}

// Search URL builder - tests complex URL construction
export function buildSearchUrl(query: string, filters?: Record<string, string>): string {
  const base = '/api/v1/search';
  const params = new URLSearchParams({ q: query, ...filters });
  return `${base}?${params.toString()}`;
}
