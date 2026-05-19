/**
 * User Service
 *
 * Tests various URL patterns for user CRUD operations:
 * - Import + concatenation (endpoints.USER_BY_ID + "/" + userId)
 * - Template with import
 * - Local variable URL
 * - Nested object access (environment.api.baseUrl)
 * - Direct fetch() call
 */

import { apiClient, httpService } from '../utils/apiClient';
import { endpoints, environment, buildUrl } from '../config/endpoints';

interface User {
  id: string;
  name: string;
  email: string;
  phone: string;
  avatar?: string;
  createdAt: string;
}

interface UserUpdate {
  name?: string;
  email?: string;
  phone?: string;
}

interface PaginatedUsers {
  users: User[];
  total: number;
  page: number;
  pageSize: number;
}

export const userService = {
  // Pattern 1: Direct import reference
  getProfile: async (): Promise<User> => {
    const response = await apiClient.get<User>(endpoints.USER_PROFILE);
    return response.data;
  },

  // Pattern 2: Import + concatenation with parameter
  getUserById: async (userId: string): Promise<User> => {
    const response = await apiClient.get<User>(endpoints.USER_BY_ID + '/' + userId);
    return response.data;
  },

  // Pattern 3: Template literal with imported base
  updateUser: async (userId: string, data: UserUpdate): Promise<User> => {
    const response = await apiClient.put<User>(`${endpoints.USER_UPDATE}/${userId}`, data);
    return response.data;
  },

  // Pattern 4: Local variable + concatenation
  deleteUser: async (userId: string): Promise<void> => {
    const deleteEndpoint = endpoints.USER_DELETE;
    await apiClient.delete(deleteEndpoint + '/' + userId);
  },

  // Pattern 5: Direct fetch() with template literal
  uploadAvatar: async (userId: string, file: File): Promise<string> => {
    const formData = new FormData();
    formData.append('avatar', file);

    const response = await fetch(`${endpoints.USER_AVATAR}/${userId}`, {
      method: 'POST',
      body: formData,
    });

    const result = await response.json() as { avatarUrl: string };
    return result.avatarUrl;
  },

  // Pattern 6: Nested object access from environment
  getApiVersion: async (): Promise<string> => {
    const env = environment;
    const response = await apiClient.get<{ version: string }>(
      env.api.baseUrl + '/version'
    );
    return response.data.version;
  },

  // Pattern 7: Function-returned URL (very hard to detect)
  searchUsers: async (query: string): Promise<User[]> => {
    const url = buildSearchUrl(query);
    const response = await apiClient.get<{ users: User[] }>(url);
    return response.data.users;
  },

  // Pattern 8: Paginated endpoint with query params
  listUsers: async (page: number, pageSize: number): Promise<PaginatedUsers> => {
    const response = await apiClient.get<PaginatedUsers>(endpoints.USER_BY_ID, {
      params: { page, page_size: pageSize },
    });
    return response.data;
  },

  // Pattern 9: Using buildUrl helper function
  getUserPreferences: async (userId: string): Promise<Record<string, unknown>> => {
    const url = buildUrl(`/users/${userId}/preferences`);
    const response = await apiClient.get<Record<string, unknown>>(url);
    return response.data;
  },

  // Pattern 10: httpService alternative client
  getUserStats: async (userId: string): Promise<Record<string, number>> => {
    const response = await httpService.fetchJson<Record<string, number>>(
      `/api/v1/users/${userId}/stats`
    );
    return response;
  },

  // Pattern 11: Complex body with nested objects and arrays
  updateUserSettings: async (
    userId: string,
    settings: {
      notifications: { email: boolean; push: boolean; sms: boolean };
      privacy: { profileVisible: boolean; showEmail: boolean };
      preferences: string[];
    }
  ): Promise<void> => {
    await apiClient.put(`/api/v1/users/${userId}/settings`, {
      notification_settings: {
        email_enabled: settings.notifications.email,
        push_enabled: settings.notifications.push,
        sms_enabled: settings.notifications.sms,
      },
      privacy_settings: {
        profile_visible: settings.privacy.profileVisible,
        show_email: settings.privacy.showEmail,
      },
      user_preferences: settings.preferences,
    });
  },

  // Pattern 12: Direct hard-coded URL
  healthCheck: async (): Promise<boolean> => {
    const response = await fetch('/api/health');
    return response.ok;
  },

  // Pattern 13: URL from array access
  getUserByIndex: async (index: number): Promise<User> => {
    const userEndpoints = [
      '/api/v1/users/admin',
      '/api/v1/users/moderator',
      '/api/v1/users/regular',
    ];
    const url = userEndpoints[index] ?? userEndpoints[2];
    const response = await apiClient.get<User>(url);
    return response.data;
  },
};

// Helper function within module (tests local function resolution)
function buildSearchUrl(query: string): string {
  return '/api/v1/users/search?q=' + encodeURIComponent(query);
}
