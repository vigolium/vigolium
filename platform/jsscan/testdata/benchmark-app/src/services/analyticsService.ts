/**
 * Analytics Service
 *
 * Tests global config variable patterns:
 * - globalConfig.API_URL usage
 * - this.API_URL pattern
 * - Hard-coded string literal
 * - Conditional URL based on flags
 */

import { apiClient } from '../utils/apiClient';
import { endpoints, globalConfig } from '../config/endpoints';

interface EventData {
  name: string;
  properties?: Record<string, unknown>;
  timestamp?: number;
}

interface PageView {
  page: string;
  referrer?: string;
  duration?: number;
}

interface AnalyticsReport {
  period: string;
  metrics: Record<string, number>;
  breakdown: Array<{ label: string; value: number }>;
}

// Class-based service to test this.property patterns
class AnalyticsServiceClass {
  private API_URL = globalConfig.API_URL;
  private BOB_URL = globalConfig.BOB_URL;
  private ADMIN_API = globalConfig.ADMIN_API;

  // Pattern 1: Using this.API_URL
  async trackEvent(eventData: EventData): Promise<void> {
    await apiClient.post(this.API_URL + '/track', {
      event: eventData.name,
      properties: eventData.properties ?? {},
      timestamp: eventData.timestamp ?? Date.now(),
    });
  }

  // Pattern 2: Direct config access
  async getEvents(userId: string, startDate: string, endDate: string): Promise<EventData[]> {
    const response = await apiClient.get<{ events: EventData[] }>(
      globalConfig.API_URL + '/events',
      {
        params: {
          user_id: userId,
          start: startDate,
          end: endDate,
        },
      }
    );
    return response.data.events;
  }

  // Pattern 3: Template literal with config
  async generateReport(reportType: string): Promise<AnalyticsReport> {
    const response = await apiClient.post<AnalyticsReport>(
      `${this.BOB_URL}/report/${reportType}`,
      {
        format: 'pdf',
        include_charts: true,
      }
    );
    return response.data;
  }

  // Pattern 4: Hard-coded string (should always detect)
  async healthCheck(): Promise<boolean> {
    const response = await apiClient.get('/api/health');
    return response.status === 200;
  }

  // Pattern 5: Using imported endpoint directly
  async sendAnalytics(data: Record<string, unknown>): Promise<void> {
    await apiClient.post(endpoints.ANALYTICS_TRACK, data);
  }

  // Pattern 6: Admin API with this reference
  async getAdminDashboard(): Promise<Record<string, unknown>> {
    const response = await apiClient.get<Record<string, unknown>>(
      this.ADMIN_API + '/dashboard'
    );
    return response.data;
  }

  // Pattern 7: Conditional URL based on environment
  async trackPageView(pageView: PageView, isProd: boolean): Promise<void> {
    const url = isProd
      ? '/api/v1/analytics/pageview/prod'
      : '/api/v1/analytics/pageview/staging';

    await apiClient.post(url, {
      page: pageView.page,
      referrer: pageView.referrer ?? document.referrer,
      duration: pageView.duration ?? 0,
      metadata: {
        viewport: `${window.innerWidth}x${window.innerHeight}`,
        userAgent: navigator.userAgent,
      },
    });
  }

  // Pattern 8: Multiple URLs in object
  async batchTrack(events: EventData[]): Promise<void> {
    const endpoints = {
      primary: '/api/v1/analytics/batch',
      fallback: '/api/v1/analytics/batch-fallback',
      legacy: '/api/legacy/analytics',
    };

    try {
      await apiClient.post(endpoints.primary, { events });
    } catch {
      await apiClient.post(endpoints.fallback, { events });
    }
  }
}

// Export instance
export const analyticsService = new AnalyticsServiceClass();

// Also export functional version
export const analyticsServiceFunctional = {
  // Pattern 9: Immediate config access
  track: async (event: string, properties?: Record<string, unknown>): Promise<void> => {
    await apiClient.post(globalConfig.API_URL + '/analytics/track', {
      event,
      properties,
      timestamp: Date.now(),
    });
  },

  // Pattern 10: Nested template with config
  getReport: async (type: string, period: string): Promise<AnalyticsReport> => {
    const response = await apiClient.get<AnalyticsReport>(
      `${globalConfig.BOB_URL}/reports/${type}/${period}`
    );
    return response.data;
  },

  // Pattern 11: Import + concatenation
  listEvents: async (): Promise<unknown[]> => {
    const response = await apiClient.get<{ data: unknown[] }>(
      endpoints.ANALYTICS_EVENTS + '/list'
    );
    return response.data.data;
  },

  // Pattern 12: Arrow function with immediate fetch
  quickTrack: (eventName: string) =>
    fetch('/api/v1/analytics/quick-track', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event: eventName, ts: Date.now() }),
    }),

  // Pattern 13: Using SOCKET_URL (different protocol)
  connectWebSocket: (): WebSocket => {
    return new WebSocket(globalConfig.SOCKET_URL + '/analytics');
  },
};
