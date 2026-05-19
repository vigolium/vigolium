/**
 * React API Hooks
 *
 * Tests React-specific patterns:
 * - R1: Custom hook with fetch inside useEffect
 * - R2: Generic mutation hook
 * - R3: Async data fetching hook
 */

import { useState, useEffect, useCallback, useRef } from 'react';

interface UseApiOptions {
  immediate?: boolean;
  onSuccess?: (data: unknown) => void;
  onError?: (error: Error) => void;
}

interface UseApiResult<T> {
  data: T | null;
  loading: boolean;
  error: Error | null;
  refetch: () => Promise<void>;
}

// Pattern R1: Custom hook with fetch
export function useApi<T>(endpoint: string, options: UseApiOptions = {}): UseApiResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(endpoint);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      setData(result as T);
      options.onSuccess?.(result);
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      setError(error);
      options.onError?.(error);
    } finally {
      setLoading(false);
    }
  }, [endpoint, options.onSuccess, options.onError]);

  useEffect(() => {
    if (options.immediate !== false) {
      fetchData();
    }
  }, [fetchData, options.immediate]);

  return { data, loading, error, refetch: fetchData };
}

// Pattern R2: Generic mutation hook
export function useMutation<TData = unknown, TVariables = unknown>(
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE'
) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const mutate = useCallback(
    async (url: string, body?: TVariables): Promise<TData | null> => {
      setLoading(true);
      setError(null);
      try {
        const response = await fetch(url, {
          method,
          headers: { 'Content-Type': 'application/json' },
          body: body ? JSON.stringify(body) : undefined,
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return (await response.json()) as TData;
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        setError(error);
        return null;
      } finally {
        setLoading(false);
      }
    },
    [method]
  );

  return { mutate, loading, error };
}

// Pattern R3: Hook with dynamic URL based on parameter
export function useUser(userId: string | null) {
  const [user, setUser] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!userId) return;

    setLoading(true);
    fetch(`/api/v1/users/${userId}`)
      .then((res) => res.json())
      .then((data) => setUser(data as Record<string, unknown>))
      .finally(() => setLoading(false));
  }, [userId]);

  return { user, loading };
}

// Pattern R4: Hook with paginated data
export function usePaginatedData<T>(baseUrl: string, pageSize = 10) {
  const [items, setItems] = useState<T[]>([]);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(true);
  const [loading, setLoading] = useState(false);

  const loadMore = useCallback(async () => {
    if (loading || !hasMore) return;

    setLoading(true);
    try {
      const response = await fetch(
        `${baseUrl}?page=${page}&page_size=${pageSize}`
      );
      const data = (await response.json()) as { items: T[]; hasMore: boolean };
      setItems((prev) => [...prev, ...data.items]);
      setHasMore(data.hasMore);
      setPage((p) => p + 1);
    } finally {
      setLoading(false);
    }
  }, [baseUrl, page, pageSize, loading, hasMore]);

  useEffect(() => {
    loadMore();
  }, []);

  return { items, loading, hasMore, loadMore };
}

// Pattern R5: Resource hook with CRUD
export function useResource<T extends { id: string }>(resourceUrl: string) {
  const [items, setItems] = useState<T[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(resourceUrl)
      .then((res) => res.json())
      .then((data) => setItems(data as T[]))
      .finally(() => setLoading(false));
  }, [resourceUrl]);

  const create = useCallback(
    async (data: Omit<T, 'id'>) => {
      const response = await fetch(resourceUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      const created = (await response.json()) as T;
      setItems((prev) => [...prev, created]);
      return created;
    },
    [resourceUrl]
  );

  const update = useCallback(
    async (id: string, data: Partial<T>) => {
      const response = await fetch(`${resourceUrl}/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      const updated = (await response.json()) as T;
      setItems((prev) => prev.map((item) => (item.id === id ? updated : item)));
      return updated;
    },
    [resourceUrl]
  );

  const remove = useCallback(
    async (id: string) => {
      await fetch(`${resourceUrl}/${id}`, { method: 'DELETE' });
      setItems((prev) => prev.filter((item) => item.id !== id));
    },
    [resourceUrl]
  );

  return { items, loading, create, update, remove };
}

// Pattern R6: Debounced search hook
export function useSearch<T>(searchEndpoint: string, debounceMs = 300) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<T[]>([]);
  const [loading, setLoading] = useState(false);
  const timeoutRef = useRef<NodeJS.Timeout>();

  useEffect(() => {
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
    }

    if (!query.trim()) {
      setResults([]);
      return;
    }

    timeoutRef.current = setTimeout(async () => {
      setLoading(true);
      try {
        const response = await fetch(
          `${searchEndpoint}?q=${encodeURIComponent(query)}`
        );
        const data = (await response.json()) as { results: T[] };
        setResults(data.results);
      } finally {
        setLoading(false);
      }
    }, debounceMs);

    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, [query, searchEndpoint, debounceMs]);

  return { query, setQuery, results, loading };
}
