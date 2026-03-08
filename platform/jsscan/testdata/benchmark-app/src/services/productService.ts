/**
 * Product Service
 *
 * Tests body parameter extraction patterns:
 * - Complex nested body objects
 * - Spread operator in body
 * - Local variable for body
 * - Multiple API calls in one function
 */

import { apiClient } from '../utils/apiClient';
import { endpoints } from '../config/endpoints';

interface Product {
  id: string;
  name: string;
  price: number;
  category: string;
  inventory: {
    stock: number;
    warehouse: string;
  };
  createdAt: string;
}

interface ProductCreate {
  name: string;
  price: number;
  category: string;
  stock: number;
  warehouse: string;
  description?: string;
  tags?: string[];
}

interface ProductFilter {
  query?: string;
  category?: string;
  minPrice?: number;
  maxPrice?: number;
  sortBy?: 'price' | 'name' | 'relevance';
  inStock?: boolean;
}

interface PaginatedProducts {
  products: Product[];
  total: number;
  page: number;
  hasMore: boolean;
}

export const productService = {
  // Pattern 1: Simple GET with params
  listProducts: async (page: number, limit: number): Promise<PaginatedProducts> => {
    const response = await apiClient.get<PaginatedProducts>(endpoints.PRODUCT_LIST, {
      params: { page, limit },
    });
    return response.data;
  },

  // Pattern 2: GET with template literal
  getProduct: async (productId: string): Promise<Product> => {
    const response = await apiClient.get<Product>(`${endpoints.PRODUCT_BY_ID}/${productId}`);
    return response.data;
  },

  // Pattern 3: POST with complex body object literal
  createProduct: async (product: ProductCreate): Promise<Product> => {
    const response = await apiClient.post<Product>(endpoints.PRODUCT_CREATE, {
      name: product.name,
      price: product.price,
      category: product.category,
      inventory: {
        stock: product.stock,
        warehouse: product.warehouse,
      },
      metadata: {
        description: product.description ?? '',
        tags: product.tags ?? [],
        created_by: 'system',
        version: 1,
      },
    });
    return response.data;
  },

  // Pattern 4: PUT with spread body (harder to detect full body)
  updateProduct: async (productId: string, changes: Partial<Product>): Promise<Product> => {
    const response = await apiClient.put<Product>(
      endpoints.PRODUCT_UPDATE + '/' + productId,
      changes
    );
    return response.data;
  },

  // Pattern 5: DELETE
  deleteProduct: async (productId: string): Promise<void> => {
    await apiClient.delete(endpoints.PRODUCT_DELETE + '/' + productId);
  },

  // Pattern 6: POST with local variable body
  searchProducts: async (filters: ProductFilter): Promise<Product[]> => {
    const searchBody = {
      query: filters.query,
      category: filters.category,
      min_price: filters.minPrice,
      max_price: filters.maxPrice,
      sort_by: filters.sortBy ?? 'relevance',
      in_stock_only: filters.inStock ?? false,
    };
    const response = await apiClient.post<{ products: Product[] }>(
      endpoints.PRODUCT_SEARCH,
      searchBody
    );
    return response.data.products;
  },

  // Pattern 7: Multiple API calls in sequence
  createAndFetch: async (product: ProductCreate): Promise<Product> => {
    const created = await apiClient.post<Product>(endpoints.PRODUCT_CREATE, {
      name: product.name,
      price: product.price,
      category: product.category,
      inventory: {
        stock: product.stock,
        warehouse: product.warehouse,
      },
    });
    // Second API call using result from first
    const fetched = await apiClient.get<Product>(
      `${endpoints.PRODUCT_BY_ID}/${created.data.id}`
    );
    return fetched.data;
  },

  // Pattern 8: Bulk operations with array body
  bulkCreate: async (products: ProductCreate[]): Promise<Product[]> => {
    const bulkBody = products.map((p) => ({
      name: p.name,
      price: p.price,
      category: p.category,
      stock: p.stock,
    }));
    const response = await apiClient.post<{ created: Product[] }>(
      '/api/v1/products/bulk-create',
      { products: bulkBody }
    );
    return response.data.created;
  },

  // Pattern 9: Conditional body based on input
  updateInventory: async (
    productId: string,
    change: number,
    reason: string
  ): Promise<{ newStock: number }> => {
    const body = change > 0
      ? { action: 'add', quantity: change, reason }
      : { action: 'remove', quantity: Math.abs(change), reason };

    const response = await apiClient.post<{ newStock: number }>(
      `/api/v1/products/${productId}/inventory`,
      body
    );
    return response.data;
  },

  // Pattern 10: Form data style body
  uploadProductImage: async (productId: string, imageUrl: string): Promise<void> => {
    await fetch(`/api/v1/products/${productId}/images`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        image_url: imageUrl,
        is_primary: true,
      }),
    });
  },

  // Pattern 11: URL with multiple dynamic segments
  getProductReview: async (productId: string, reviewId: string): Promise<unknown> => {
    const response = await apiClient.get(
      `/api/v1/products/${productId}/reviews/${reviewId}`
    );
    return response.data;
  },

  // Pattern 12: Using variable for URL parts
  getProductsByCategory: async (category: string, subcategory?: string): Promise<Product[]> => {
    const basePath = '/api/v1/products/category';
    const categoryPath = subcategory
      ? `${basePath}/${category}/${subcategory}`
      : `${basePath}/${category}`;

    const response = await apiClient.get<{ products: Product[] }>(categoryPath);
    return response.data.products;
  },

  // Pattern 13: Object destructuring in body
  quickUpdate: async (
    productId: string,
    { price, stock }: { price?: number; stock?: number }
  ): Promise<void> => {
    await apiClient.patch(`/api/v1/products/${productId}/quick`, {
      price,
      stock,
      updated_at: new Date().toISOString(),
    });
  },
};
