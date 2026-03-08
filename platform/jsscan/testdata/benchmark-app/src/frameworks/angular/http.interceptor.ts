/**
 * Angular HTTP Interceptor
 *
 * Tests Angular interceptor patterns:
 * - A5: HTTP Interceptor with URL modification
 * - Token injection
 * - Error handling
 *
 * Note: This simulates Angular patterns for bundling tests.
 */

// Simulated Angular types
function Injectable() {
  return function <T extends new (...args: unknown[]) => unknown>(constructor: T) {
    return constructor;
  };
}

interface HttpRequest<T> {
  url: string;
  method: string;
  headers: Map<string, string>;
  body: T | null;
  clone(options: {
    url?: string;
    headers?: Map<string, string>;
    setHeaders?: Record<string, string>;
  }): HttpRequest<T>;
}

interface HttpHandler {
  handle(req: HttpRequest<unknown>): Promise<HttpResponse<unknown>>;
}

interface HttpResponse<T> {
  status: number;
  body: T;
}

interface HttpErrorResponse {
  status: number;
  message: string;
}

interface HttpInterceptor {
  intercept(req: HttpRequest<unknown>, next: HttpHandler): Promise<HttpResponse<unknown>>;
}

// Pattern A5: HTTP Interceptor - API URL prefix
@Injectable()
export class ApiPrefixInterceptor implements HttpInterceptor {
  private apiPrefix = '/api/v1';

  async intercept(
    req: HttpRequest<unknown>,
    next: HttpHandler
  ): Promise<HttpResponse<unknown>> {
    // Only add prefix to relative URLs that don't already have /api
    if (!req.url.startsWith('http') && !req.url.startsWith('/api')) {
      const apiReq = req.clone({
        url: `${this.apiPrefix}${req.url}`,
      });
      return next.handle(apiReq);
    }
    return next.handle(req);
  }
}

// Pattern A6: Auth token interceptor
@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  private authEndpoints = [
    '/api/v1/auth/login',
    '/api/v1/auth/register',
    '/api/v1/auth/forgot-password',
  ];

  async intercept(
    req: HttpRequest<unknown>,
    next: HttpHandler
  ): Promise<HttpResponse<unknown>> {
    // Skip auth endpoints
    if (this.authEndpoints.includes(req.url)) {
      return next.handle(req);
    }

    const token = localStorage.getItem('auth_token');
    if (token) {
      const authReq = req.clone({
        setHeaders: {
          Authorization: `Bearer ${token}`,
        },
      });
      return next.handle(authReq);
    }

    return next.handle(req);
  }
}

// Pattern A7: Error handling interceptor
@Injectable()
export class ErrorInterceptor implements HttpInterceptor {
  private errorLogEndpoint = '/api/v1/errors/log';

  async intercept(
    req: HttpRequest<unknown>,
    next: HttpHandler
  ): Promise<HttpResponse<unknown>> {
    try {
      return await next.handle(req);
    } catch (error) {
      const httpError = error as HttpErrorResponse;

      // Log error to backend
      if (httpError.status >= 500) {
        await this.logError({
          url: req.url,
          method: req.method,
          status: httpError.status,
          message: httpError.message,
          timestamp: new Date().toISOString(),
        });
      }

      // Handle 401 - redirect to login
      if (httpError.status === 401) {
        localStorage.removeItem('auth_token');
        window.location.href = '/login';
      }

      throw error;
    }
  }

  private async logError(errorData: Record<string, unknown>): Promise<void> {
    await fetch(this.errorLogEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(errorData),
    });
  }
}

// Pattern A8: Caching interceptor
@Injectable()
export class CacheInterceptor implements HttpInterceptor {
  private cache = new Map<string, { data: unknown; timestamp: number }>();
  private cacheDuration = 5 * 60 * 1000; // 5 minutes

  private cacheableEndpoints = [
    '/api/v1/products',
    '/api/v1/categories',
    '/api/v1/settings/public',
  ];

  async intercept(
    req: HttpRequest<unknown>,
    next: HttpHandler
  ): Promise<HttpResponse<unknown>> {
    // Only cache GET requests
    if (req.method !== 'GET') {
      return next.handle(req);
    }

    // Check if endpoint is cacheable
    const isCacheable = this.cacheableEndpoints.some((ep) =>
      req.url.startsWith(ep)
    );

    if (!isCacheable) {
      return next.handle(req);
    }

    const cacheKey = req.url;
    const cached = this.cache.get(cacheKey);

    if (cached && Date.now() - cached.timestamp < this.cacheDuration) {
      return { status: 200, body: cached.data };
    }

    const response = await next.handle(req);
    this.cache.set(cacheKey, { data: response.body, timestamp: Date.now() });
    return response;
  }
}

// Pattern A9: Retry interceptor
@Injectable()
export class RetryInterceptor implements HttpInterceptor {
  private maxRetries = 3;
  private retryableStatusCodes = [408, 429, 500, 502, 503, 504];

  async intercept(
    req: HttpRequest<unknown>,
    next: HttpHandler
  ): Promise<HttpResponse<unknown>> {
    let lastError: unknown;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        return await next.handle(req);
      } catch (error) {
        lastError = error;
        const httpError = error as HttpErrorResponse;

        if (!this.retryableStatusCodes.includes(httpError.status)) {
          throw error;
        }

        if (attempt < this.maxRetries) {
          // Exponential backoff
          await this.delay(Math.pow(2, attempt) * 1000);
        }
      }
    }

    throw lastError;
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

// Pattern A10: Loading interceptor
@Injectable()
export class LoadingInterceptor implements HttpInterceptor {
  private loadingEndpoint = '/api/v1/ui/loading';
  private activeRequests = 0;

  async intercept(
    req: HttpRequest<unknown>,
    next: HttpHandler
  ): Promise<HttpResponse<unknown>> {
    this.activeRequests++;

    if (this.activeRequests === 1) {
      // Notify loading started
      await fetch(this.loadingEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ loading: true }),
      });
    }

    try {
      return await next.handle(req);
    } finally {
      this.activeRequests--;

      if (this.activeRequests === 0) {
        // Notify loading ended
        await fetch(this.loadingEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ loading: false }),
        });
      }
    }
  }
}

// Pattern A11: Analytics interceptor
@Injectable()
export class AnalyticsInterceptor implements HttpInterceptor {
  async intercept(
    req: HttpRequest<unknown>,
    next: HttpHandler
  ): Promise<HttpResponse<unknown>> {
    const startTime = Date.now();

    try {
      const response = await next.handle(req);
      const duration = Date.now() - startTime;

      // Track successful request
      await fetch('/api/v1/analytics/api-call', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: req.url,
          method: req.method,
          status: response.status,
          duration,
          success: true,
        }),
      });

      return response;
    } catch (error) {
      const duration = Date.now() - startTime;
      const httpError = error as HttpErrorResponse;

      // Track failed request
      await fetch('/api/v1/analytics/api-call', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: req.url,
          method: req.method,
          status: httpError.status,
          duration,
          success: false,
          error: httpError.message,
        }),
      });

      throw error;
    }
  }
}
