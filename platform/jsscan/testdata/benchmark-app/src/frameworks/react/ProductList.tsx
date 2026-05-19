/**
 * React Product Components
 *
 * Tests React Query style patterns and complex component patterns
 */

import React, { useState, useEffect, useCallback } from 'react';
import { usePaginatedData, useSearch } from './useApi';

interface Product {
  id: string;
  name: string;
  price: number;
  category: string;
  imageUrl: string;
}

// Simulated React Query-like hook (without actual dependency)
function useQuery<T>(options: {
  queryKey: unknown[];
  queryFn: () => Promise<T>;
  enabled?: boolean;
}) {
  const [data, setData] = useState<T | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    if (options.enabled === false) return;

    setIsLoading(true);
    options
      .queryFn()
      .then((result) => setData(result))
      .catch((err) => setError(err as Error))
      .finally(() => setIsLoading(false));
  }, [JSON.stringify(options.queryKey), options.enabled]);

  return { data, isLoading, error };
}

// Pattern R5: React Query style pattern
export function ProductList() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['products'],
    queryFn: () => fetch('/api/v1/products').then((r) => r.json()) as Promise<{ products: Product[] }>,
  });

  if (isLoading) return <div>Loading products...</div>;
  if (error) return <div>Error loading products</div>;

  return (
    <div className="product-list">
      {data?.products.map((product) => (
        <ProductCard key={product.id} product={product} />
      ))}
    </div>
  );
}

// Pattern R6: Query with dynamic key
export function ProductsByCategory({ category }: { category: string }) {
  const { data } = useQuery({
    queryKey: ['products', category],
    queryFn: () =>
      fetch(`/api/v1/products/category/${category}`).then((r) => r.json()) as Promise<{
        products: Product[];
      }>,
    enabled: !!category,
  });

  return (
    <div>
      {data?.products.map((p) => (
        <div key={p.id}>{p.name}</div>
      ))}
    </div>
  );
}

// Pattern R7: Query with pagination
export function PaginatedProductList() {
  const [page, setPage] = useState(1);

  const { data, isLoading } = useQuery({
    queryKey: ['products', 'paginated', page],
    queryFn: () =>
      fetch(`/api/v1/products?page=${page}&limit=20`).then((r) => r.json()) as Promise<{
        products: Product[];
        hasMore: boolean;
      }>,
  });

  return (
    <div>
      {isLoading ? (
        <div>Loading...</div>
      ) : (
        <>
          {data?.products.map((p) => (
            <div key={p.id}>{p.name}</div>
          ))}
          <button onClick={() => setPage((p) => p + 1)} disabled={!data?.hasMore}>
            Load More
          </button>
        </>
      )}
    </div>
  );
}

// ProductCard with detail fetch on click
function ProductCard({ product }: { product: Product }) {
  const [details, setDetails] = useState<Record<string, unknown> | null>(null);
  const [showDetails, setShowDetails] = useState(false);

  const loadDetails = useCallback(async () => {
    if (details) {
      setShowDetails(true);
      return;
    }

    const response = await fetch(`/api/v1/products/${product.id}/details`);
    const data = await response.json();
    setDetails(data as Record<string, unknown>);
    setShowDetails(true);
  }, [product.id, details]);

  return (
    <div className="product-card">
      <img src={product.imageUrl} alt={product.name} />
      <h3>{product.name}</h3>
      <p>${product.price}</p>
      <button onClick={loadDetails}>View Details</button>
      {showDetails && details && (
        <div className="details">{JSON.stringify(details)}</div>
      )}
    </div>
  );
}

// Pattern R8: Search with debounce
export function ProductSearch() {
  const { query, setQuery, results, loading } = useSearch<Product>(
    '/api/v1/products/search'
  );

  return (
    <div className="product-search">
      <input
        type="text"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Search products..."
      />
      {loading && <div>Searching...</div>}
      <div className="results">
        {results.map((product) => (
          <div key={product.id} className="result-item">
            {product.name} - ${product.price}
          </div>
        ))}
      </div>
    </div>
  );
}

// Pattern R9: Infinite scroll with custom hook
export function InfiniteProductList() {
  const { items, loading, hasMore, loadMore } = usePaginatedData<Product>(
    '/api/v1/products/infinite',
    20
  );

  return (
    <div className="infinite-list">
      {items.map((product) => (
        <div key={product.id} className="product-item">
          {product.name}
        </div>
      ))}
      {loading && <div>Loading more...</div>}
      {hasMore && !loading && (
        <button onClick={loadMore}>Load More</button>
      )}
    </div>
  );
}

// Pattern R10: Product form with create mutation
export function CreateProductForm() {
  const [name, setName] = useState('');
  const [price, setPrice] = useState('');
  const [category, setCategory] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);

    await fetch('/api/v1/products/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name,
        price: parseFloat(price),
        category,
        inventory: {
          stock: 0,
          warehouse: 'default',
        },
      }),
    });

    setSubmitting(false);
    // Reset form
    setName('');
    setPrice('');
    setCategory('');
  };

  return (
    <form onSubmit={handleSubmit}>
      <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Name" />
      <input value={price} onChange={(e) => setPrice(e.target.value)} placeholder="Price" />
      <input value={category} onChange={(e) => setCategory(e.target.value)} placeholder="Category" />
      <button type="submit" disabled={submitting}>
        {submitting ? 'Creating...' : 'Create Product'}
      </button>
    </form>
  );
}

// Pattern R11: Bulk actions
export function ProductBulkActions({ selectedIds }: { selectedIds: string[] }) {
  const handleBulkDelete = async () => {
    await fetch('/api/v1/products/bulk-delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ product_ids: selectedIds }),
    });
  };

  const handleBulkUpdate = async (updates: Record<string, unknown>) => {
    await fetch('/api/v1/products/bulk-update', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        product_ids: selectedIds,
        updates,
      }),
    });
  };

  return (
    <div className="bulk-actions">
      <button onClick={handleBulkDelete}>Delete Selected</button>
      <button onClick={() => handleBulkUpdate({ status: 'archived' })}>
        Archive Selected
      </button>
    </div>
  );
}
