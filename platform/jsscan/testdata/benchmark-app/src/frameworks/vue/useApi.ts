/**
 * Vue Composition API Hooks
 *
 * Tests Vue-specific patterns:
 * - V1: Composition API with fetch
 * - V2: Reactive URL
 * - V3: Computed URLs
 */

// Simulated Vue reactivity (for bundling tests)
function ref<T>(value: T): { value: T } {
  return { value };
}

function computed<T>(getter: () => T): { value: T } {
  return { get value() { return getter(); } };
}

function watch(
  _source: unknown,
  callback: (newVal: unknown, oldVal: unknown) => void
): void {
  // Simulated watch - in real Vue this would be reactive
  callback(undefined, undefined);
}

function watchEffect(effect: () => void): void {
  effect();
}

function onMounted(callback: () => void): void {
  callback();
}

type Ref<T> = { value: T };

// Pattern V1: Basic Composition API with fetch
export function useApi<T>(endpoint: string) {
  const data = ref<T | null>(null);
  const loading = ref(false);
  const error = ref<Error | null>(null);

  const fetchData = async () => {
    loading.value = true;
    error.value = null;

    try {
      const response = await fetch(endpoint);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      data.value = await response.json() as T;
    } catch (e) {
      error.value = e instanceof Error ? e : new Error(String(e));
    } finally {
      loading.value = false;
    }
  };

  onMounted(() => {
    fetchData();
  });

  return { data, loading, error, refetch: fetchData };
}

// Pattern V2: Reactive URL based on parameter
export function useUser(userId: Ref<string>) {
  const user = ref<Record<string, unknown> | null>(null);
  const loading = ref(false);

  const url = computed(() => `/api/v1/users/${userId.value}`);

  watchEffect(async () => {
    if (!userId.value) return;

    loading.value = true;
    try {
      const response = await fetch(url.value);
      user.value = await response.json() as Record<string, unknown>;
    } finally {
      loading.value = false;
    }
  });

  return { user, loading };
}

// Pattern V3: CRUD composable
export function useCrud<T extends { id: string }>(resourceUrl: string) {
  const items = ref<T[]>([]);
  const loading = ref(false);

  const fetchAll = async () => {
    loading.value = true;
    try {
      const response = await fetch(resourceUrl);
      items.value = await response.json() as T[];
    } finally {
      loading.value = false;
    }
  };

  const fetchOne = async (id: string): Promise<T | null> => {
    const response = await fetch(`${resourceUrl}/${id}`);
    return response.json() as Promise<T>;
  };

  const create = async (data: Omit<T, 'id'>): Promise<T> => {
    const response = await fetch(resourceUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    const created = await response.json() as T;
    items.value = [...items.value, created];
    return created;
  };

  const update = async (id: string, data: Partial<T>): Promise<T> => {
    const response = await fetch(`${resourceUrl}/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    const updated = await response.json() as T;
    items.value = items.value.map((item) =>
      item.id === id ? updated : item
    );
    return updated;
  };

  const remove = async (id: string): Promise<void> => {
    await fetch(`${resourceUrl}/${id}`, { method: 'DELETE' });
    items.value = items.value.filter((item) => item.id !== id);
  };

  onMounted(() => {
    fetchAll();
  });

  return { items, loading, fetchAll, fetchOne, create, update, remove };
}

// Pattern V4: Search composable with debounce
export function useSearch<T>(searchEndpoint: string, debounceMs = 300) {
  const query = ref('');
  const results = ref<T[]>([]);
  const loading = ref(false);
  let timeoutId: NodeJS.Timeout | null = null;

  watch(
    () => query.value,
    (newQuery) => {
      if (timeoutId) clearTimeout(timeoutId);

      if (!newQuery) {
        results.value = [];
        return;
      }

      timeoutId = setTimeout(async () => {
        loading.value = true;
        try {
          const response = await fetch(
            `${searchEndpoint}?q=${encodeURIComponent(newQuery as string)}`
          );
          const data = await response.json() as { results: T[] };
          results.value = data.results;
        } finally {
          loading.value = false;
        }
      }, debounceMs);
    }
  );

  return { query, results, loading };
}

// Pattern V5: Pagination composable
export function usePagination<T>(baseUrl: string, pageSize = 20) {
  const items = ref<T[]>([]);
  const page = ref(1);
  const hasMore = ref(true);
  const loading = ref(false);

  const loadPage = async (pageNum: number) => {
    loading.value = true;
    try {
      const response = await fetch(
        `${baseUrl}?page=${pageNum}&page_size=${pageSize}`
      );
      const data = await response.json() as { items: T[]; hasMore: boolean };
      items.value = data.items;
      hasMore.value = data.hasMore;
      page.value = pageNum;
    } finally {
      loading.value = false;
    }
  };

  const nextPage = () => {
    if (hasMore.value) loadPage(page.value + 1);
  };

  const prevPage = () => {
    if (page.value > 1) loadPage(page.value - 1);
  };

  onMounted(() => {
    loadPage(1);
  });

  return { items, page, hasMore, loading, loadPage, nextPage, prevPage };
}

// Pattern V6: Auth composable
export function useAuth() {
  const user = ref<Record<string, unknown> | null>(null);
  const isAuthenticated = computed(() => !!user.value);
  const loading = ref(false);

  const login = async (credentials: { username: string; password: string }) => {
    loading.value = true;
    try {
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials),
      });
      const data = await response.json() as { token: string; user: Record<string, unknown> };
      localStorage.setItem('token', data.token);
      user.value = data.user;
      return true;
    } catch {
      return false;
    } finally {
      loading.value = false;
    }
  };

  const logout = async () => {
    await fetch('/api/v1/auth/logout', { method: 'POST' });
    localStorage.removeItem('token');
    user.value = null;
  };

  const fetchCurrentUser = async () => {
    const token = localStorage.getItem('token');
    if (!token) return;

    try {
      const response = await fetch('/api/v1/auth/me', {
        headers: { Authorization: `Bearer ${token}` },
      });
      user.value = await response.json() as Record<string, unknown>;
    } catch {
      localStorage.removeItem('token');
    }
  };

  onMounted(() => {
    fetchCurrentUser();
  });

  return { user, isAuthenticated, loading, login, logout };
}

// Pattern V7: Form submission composable
export function useForm<T>(submitEndpoint: string) {
  const submitting = ref(false);
  const error = ref<string | null>(null);
  const success = ref(false);

  const submit = async (data: T) => {
    submitting.value = true;
    error.value = null;
    success.value = false;

    try {
      const response = await fetch(submitEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });

      if (!response.ok) {
        const errorData = await response.json() as { message: string };
        throw new Error(errorData.message);
      }

      success.value = true;
      return await response.json();
    } catch (e) {
      error.value = e instanceof Error ? e.message : 'Unknown error';
      return null;
    } finally {
      submitting.value = false;
    }
  };

  return { submitting, error, success, submit };
}

// Pattern V8: Real-time updates composable
export function useRealtime<T>(endpoint: string, wsEndpoint: string) {
  const data = ref<T | null>(null);
  const connected = ref(false);
  let ws: WebSocket | null = null;

  const fetchInitial = async () => {
    const response = await fetch(endpoint);
    data.value = await response.json() as T;
  };

  const connect = () => {
    ws = new WebSocket(wsEndpoint);

    ws.onopen = () => {
      connected.value = true;
    };

    ws.onmessage = (event) => {
      data.value = JSON.parse(event.data) as T;
    };

    ws.onclose = () => {
      connected.value = false;
      // Reconnect after delay
      setTimeout(connect, 5000);
    };
  };

  onMounted(() => {
    fetchInitial();
    connect();
  });

  return { data, connected };
}
