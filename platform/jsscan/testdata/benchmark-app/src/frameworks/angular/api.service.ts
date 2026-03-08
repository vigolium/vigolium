/**
 * Angular API Service
 *
 * Tests Angular-specific patterns:
 * - A1: HttpClient trong service
 * - A2: Generic CRUD methods
 * - A3: POST với body
 * - A4: Parameterized URL
 *
 * Note: This simulates Angular patterns for bundling tests.
 * The decorators are simplified versions.
 */

// Simulated Angular decorators and types
function Injectable(_options?: { providedIn?: string }) {
  return function <T extends new (...args: unknown[]) => unknown>(constructor: T) {
    return constructor;
  };
}

// Simulated HttpClient (mimics Angular's HttpClient interface)
class HttpClient {
  private async request<T>(method: string, url: string, options?: {
    body?: unknown;
    headers?: Record<string, string>;
    params?: Record<string, string>;
  }): Promise<T> {
    let finalUrl = url;
    if (options?.params) {
      const params = new URLSearchParams(options.params);
      finalUrl = `${url}?${params.toString()}`;
    }

    const response = await fetch(finalUrl, {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
      body: options?.body ? JSON.stringify(options.body) : undefined,
    });

    return response.json() as Promise<T>;
  }

  get<T>(url: string, options?: { params?: Record<string, string> }) {
    return this.request<T>('GET', url, options);
  }

  post<T>(url: string, body: unknown, options?: { headers?: Record<string, string> }) {
    return this.request<T>('POST', url, { body, ...options });
  }

  put<T>(url: string, body: unknown) {
    return this.request<T>('PUT', url, { body });
  }

  patch<T>(url: string, body: unknown) {
    return this.request<T>('PATCH', url, { body });
  }

  delete<T>(url: string) {
    return this.request<T>('DELETE', url);
  }
}

// Types
interface User {
  id: string;
  name: string;
  email: string;
}

interface Product {
  id: string;
  name: string;
  price: number;
}

interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}

// Pattern A1: HttpClient service with Injectable decorator
@Injectable({ providedIn: 'root' })
export class ApiService {
  private baseUrl = '/api/v1';
  private http: HttpClient;

  constructor() {
    this.http = new HttpClient();
  }

  // Pattern A2: Generic CRUD - GET list
  getUsers(): Promise<User[]> {
    return this.http.get<User[]>(`${this.baseUrl}/users`);
  }

  // Pattern A3: POST với body
  createUser(user: Omit<User, 'id'>): Promise<User> {
    return this.http.post<User>(`${this.baseUrl}/users`, user);
  }

  // Pattern A4: Parameterized URL
  getUserById(id: string): Promise<User> {
    return this.http.get<User>(`${this.baseUrl}/users/${id}`);
  }

  // Pattern A5: PUT update
  updateUser(id: string, user: Partial<User>): Promise<User> {
    return this.http.put<User>(`${this.baseUrl}/users/${id}`, user);
  }

  // Pattern A6: DELETE
  deleteUser(id: string): Promise<void> {
    return this.http.delete<void>(`${this.baseUrl}/users/${id}`);
  }

  // Pattern A7: GET with query params
  searchUsers(query: string, page = 1, pageSize = 20): Promise<PaginatedResponse<User>> {
    return this.http.get<PaginatedResponse<User>>(`${this.baseUrl}/users/search`, {
      params: {
        q: query,
        page: String(page),
        page_size: String(pageSize),
      },
    });
  }
}

// Pattern A8: Separate service for products
@Injectable({ providedIn: 'root' })
export class ProductService {
  private readonly apiUrl = '/api/v1/products';
  private http: HttpClient;

  constructor() {
    this.http = new HttpClient();
  }

  getAll(): Promise<Product[]> {
    return this.http.get<Product[]>(this.apiUrl);
  }

  getById(id: string): Promise<Product> {
    return this.http.get<Product>(`${this.apiUrl}/${id}`);
  }

  create(product: Omit<Product, 'id'>): Promise<Product> {
    return this.http.post<Product>(this.apiUrl, product);
  }

  update(id: string, product: Partial<Product>): Promise<Product> {
    return this.http.put<Product>(`${this.apiUrl}/${id}`, product);
  }

  delete(id: string): Promise<void> {
    return this.http.delete<void>(`${this.apiUrl}/${id}`);
  }

  // Pattern A9: Complex query with multiple params
  search(filters: {
    category?: string;
    minPrice?: number;
    maxPrice?: number;
    sortBy?: string;
  }): Promise<Product[]> {
    const params: Record<string, string> = {};
    if (filters.category) params['category'] = filters.category;
    if (filters.minPrice !== undefined) params['min_price'] = String(filters.minPrice);
    if (filters.maxPrice !== undefined) params['max_price'] = String(filters.maxPrice);
    if (filters.sortBy) params['sort_by'] = filters.sortBy;

    return this.http.get<Product[]>(`${this.apiUrl}/search`, { params });
  }
}

// Pattern A10: Auth service
@Injectable({ providedIn: 'root' })
export class AuthService {
  private http: HttpClient;

  constructor() {
    this.http = new HttpClient();
  }

  login(credentials: { username: string; password: string }): Promise<{ token: string }> {
    return this.http.post<{ token: string }>('/api/v1/auth/login', credentials);
  }

  logout(): Promise<void> {
    return this.http.post<void>('/api/v1/auth/logout', {});
  }

  refresh(refreshToken: string): Promise<{ token: string }> {
    return this.http.post<{ token: string }>('/api/v1/auth/refresh', {
      refresh_token: refreshToken,
    });
  }

  getCurrentUser(): Promise<User> {
    return this.http.get<User>('/api/v1/auth/me');
  }
}

// Pattern A11: Generic CRUD service base class (without decorator for TS compatibility)
export class BaseCrudService<T extends { id: string }> {
  protected http: HttpClient;

  constructor(protected resourceUrl: string) {
    this.http = new HttpClient();
  }

  getAll(): Promise<T[]> {
    return this.http.get<T[]>(this.resourceUrl);
  }

  getById(id: string): Promise<T> {
    return this.http.get<T>(`${this.resourceUrl}/${id}`);
  }

  create(entity: Omit<T, 'id'>): Promise<T> {
    return this.http.post<T>(this.resourceUrl, entity);
  }

  update(id: string, entity: Partial<T>): Promise<T> {
    return this.http.put<T>(`${this.resourceUrl}/${id}`, entity);
  }

  delete(id: string): Promise<void> {
    return this.http.delete<void>(`${this.resourceUrl}/${id}`);
  }
}

// Pattern A12: Order service (concrete implementation)
@Injectable({ providedIn: 'root' })
export class OrderService {
  private http: HttpClient;
  private resourceUrl = '/api/v1/orders';

  constructor() {
    this.http = new HttpClient();
  }

  getAll() {
    return this.http.get<unknown[]>(this.resourceUrl);
  }

  getById(id: string) {
    return this.http.get<unknown>(`${this.resourceUrl}/${id}`);
  }

  create(entity: unknown) {
    return this.http.post<unknown>(this.resourceUrl, entity);
  }

  getByUser(userId: string) {
    return this.http.get<unknown[]>(`${this.resourceUrl}/user/${userId}`);
  }

  cancel(orderId: string) {
    return this.http.post<void>(`${this.resourceUrl}/${orderId}/cancel`, {});
  }
}
