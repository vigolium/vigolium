/**
 * API Client Wrapper
 *
 * Axios-style HTTP client to test s.S.post() patterns
 * when minified by webpack.
 */

type RequestConfig = {
  headers?: Record<string, string>;
  params?: Record<string, string | number>;
  timeout?: number;
};

type ResponseData<T = unknown> = {
  data: T;
  status: number;
  headers: Headers;
};

// Simulate axios-style client that will become s.S in minified code
export const apiClient = {
  post: async <T = unknown>(
    url: string,
    data?: unknown,
    config?: RequestConfig
  ): Promise<ResponseData<T>> => {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...config?.headers,
      },
      body: data ? JSON.stringify(data) : undefined,
    });
    return {
      data: (await response.json()) as T,
      status: response.status,
      headers: response.headers,
    };
  },

  get: async <T = unknown>(url: string, config?: RequestConfig): Promise<ResponseData<T>> => {
    let finalUrl = url;
    if (config?.params) {
      const params = new URLSearchParams();
      Object.entries(config.params).forEach(([key, value]) => {
        params.append(key, String(value));
      });
      finalUrl = `${url}?${params.toString()}`;
    }

    const response = await fetch(finalUrl, {
      method: 'GET',
      headers: config?.headers,
    });
    return {
      data: (await response.json()) as T,
      status: response.status,
      headers: response.headers,
    };
  },

  put: async <T = unknown>(
    url: string,
    data?: unknown,
    config?: RequestConfig
  ): Promise<ResponseData<T>> => {
    const response = await fetch(url, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        ...config?.headers,
      },
      body: data ? JSON.stringify(data) : undefined,
    });
    return {
      data: (await response.json()) as T,
      status: response.status,
      headers: response.headers,
    };
  },

  delete: async <T = unknown>(url: string, config?: RequestConfig): Promise<ResponseData<T>> => {
    const response = await fetch(url, {
      method: 'DELETE',
      headers: config?.headers,
    });
    return {
      data: (await response.json()) as T,
      status: response.status,
      headers: response.headers,
    };
  },

  patch: async <T = unknown>(
    url: string,
    data?: unknown,
    config?: RequestConfig
  ): Promise<ResponseData<T>> => {
    const response = await fetch(url, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        ...config?.headers,
      },
      body: data ? JSON.stringify(data) : undefined,
    });
    return {
      data: (await response.json()) as T,
      status: response.status,
      headers: response.headers,
    };
  },

  request: async <T = unknown>(
    method: string,
    url: string,
    data?: unknown,
    config?: RequestConfig
  ): Promise<ResponseData<T>> => {
    const response = await fetch(url, {
      method: method.toUpperCase(),
      headers: {
        'Content-Type': 'application/json',
        ...config?.headers,
      },
      body: data ? JSON.stringify(data) : undefined,
    });
    return {
      data: (await response.json()) as T,
      status: response.status,
      headers: response.headers,
    };
  },
};

// Alternative HTTP client with different naming
export const httpService = {
  send: async (method: string, endpoint: string, payload?: unknown) => {
    return fetch(endpoint, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: payload ? JSON.stringify(payload) : undefined,
    });
  },

  fetchJson: async <T>(url: string): Promise<T> => {
    const response = await fetch(url);
    return response.json() as Promise<T>;
  },
};

// Create instance pattern (like axios.create())
export function createApiClient(baseUrl: string) {
  return {
    get: (path: string) => fetch(`${baseUrl}${path}`),
    post: (path: string, data: unknown) =>
      fetch(`${baseUrl}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      }),
  };
}
