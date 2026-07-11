/**
 * Auth Service
 *
 * Tests various URL patterns for authentication endpoints:
 * - P1: Import reference (endpoints.AUTH_LOGIN)
 * - P2: Template literal with parameter
 * - P3: String concatenation
 * - P4: Complex body objects
 * - P5: Local variable URL
 */

import { apiClient } from '../utils/apiClient';
import { endpoints, globalConfig } from '../config/endpoints';

interface LoginCredentials {
  phone: string;
  password: string;
  rememberMe?: boolean;
}

interface RegisterData {
  phone: string;
  email: string;
  name: string;
  password: string;
  acceptTerms: boolean;
}

interface TokenResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

interface User {
  id: string;
  name: string;
  email: string;
  phone: string;
}

export const authService = {
  // Pattern 1: Direct import reference - a.O.AUTH_LOGIN becomes endpoints.AUTH_LOGIN
  login: async (credentials: LoginCredentials): Promise<TokenResponse> => {
    const response = await apiClient.post<TokenResponse>(endpoints.AUTH_LOGIN, {
      phone_number: credentials.phone,
      password: credentials.password,
      remember_me: credentials.rememberMe ?? false,
    });
    return response.data;
  },

  // Pattern 2: Direct import reference
  logout: async (): Promise<void> => {
    await apiClient.post(endpoints.AUTH_LOGOUT, {});
  },

  // Pattern 3: Direct import reference with body
  refresh: async (token: string): Promise<TokenResponse> => {
    const response = await apiClient.post<TokenResponse>(endpoints.AUTH_REFRESH, {
      refresh_token: token,
    });
    return response.data;
  },

  // Pattern 4: Import reference with complex nested body
  register: async (userData: RegisterData): Promise<User> => {
    const response = await apiClient.post<User>(endpoints.AUTH_REGISTER, {
      phone_number: userData.phone,
      email: userData.email,
      full_name: userData.name,
      password: userData.password,
      terms_accepted: userData.acceptTerms,
      metadata: {
        source: 'web',
        version: '2.0',
        timestamp: Date.now(),
      },
    });
    return response.data;
  },

  // Pattern 5: Template literal URL with parameter (hard to detect)
  verifyOtp: async (phone: string, otp: string): Promise<boolean> => {
    const response = await apiClient.post<{ verified: boolean }>(
      `/api/v1/auth/verify/${phone}`,
      { otp }
    );
    return response.data.verified;
  },

  // Pattern 6: String concatenation
  resetPassword: async (token: string, newPassword: string): Promise<void> => {
    const baseUrl = '/api/v1/auth';
    await apiClient.post(baseUrl + '/reset-password', {
      reset_token: token,
      new_password: newPassword,
    });
  },

  // Pattern 7: Local variable then use
  forgotPassword: async (email: string): Promise<void> => {
    const forgotPasswordUrl = '/api/v1/auth/forgot-password';
    await apiClient.post(forgotPasswordUrl, { email });
  },

  // Pattern 8: Global config variable
  checkSession: async (): Promise<boolean> => {
    const response = await apiClient.get<{ valid: boolean }>(
      globalConfig.API_URL + '/auth/session'
    );
    return response.data.valid;
  },

  // Pattern 9: Template literal with imported config
  validateToken: async (token: string): Promise<boolean> => {
    const response = await apiClient.post<{ valid: boolean }>(
      `${globalConfig.API_URL}/auth/validate`,
      { token }
    );
    return response.data.valid;
  },

  // Pattern 10: Direct fetch() call instead of apiClient
  ping: async (): Promise<boolean> => {
    const response = await fetch('/api/v1/auth/ping', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    return response.ok;
  },

  // Pattern 11: Conditional URL based on flag
  ssoLogin: async (provider: string, isProd: boolean): Promise<string> => {
    const url = isProd
      ? '/api/v1/auth/sso/prod'
      : '/api/v1/auth/sso/staging';
    const response = await apiClient.post<{ redirectUrl: string }>(url, { provider });
    return response.data.redirectUrl;
  },

  // Pattern 12: Multiple concatenations
  mfaSetup: async (userId: string, method: string): Promise<{ secret: string }> => {
    const basePath = '/api/v1';
    const authPath = '/auth/mfa';
    const fullUrl = basePath + authPath + '/setup/' + method;
    const response = await apiClient.post<{ secret: string }>(fullUrl, { user_id: userId });
    return response.data;
  },
};
