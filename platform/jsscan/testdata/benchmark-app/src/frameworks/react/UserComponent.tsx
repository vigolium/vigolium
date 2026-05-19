/**
 * React User Components
 *
 * Tests React component patterns:
 * - R3: useEffect with API call
 * - R4: Event handler with API
 * - Form submission patterns
 */

import React, { useState, useEffect, FormEvent, useCallback } from 'react';
import { useApi, useMutation } from './useApi';

interface User {
  id: string;
  name: string;
  email: string;
  avatar?: string;
}

interface UserProfileProps {
  userId: string;
}

// Pattern R3: useEffect with API call
export function UserProfile({ userId }: UserProfileProps) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);

    fetch(`/api/v1/users/${userId}`)
      .then((res) => {
        if (!res.ok) throw new Error('Failed to fetch user');
        return res.json();
      })
      .then((data) => setUser(data as User))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [userId]);

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;
  if (!user) return <div>User not found</div>;

  return (
    <div className="user-profile">
      <img src={user.avatar} alt={user.name} />
      <h2>{user.name}</h2>
      <p>{user.email}</p>
    </div>
  );
}

// Pattern R4: Event handler with API
export function LoginForm() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      if (!response.ok) {
        throw new Error('Login failed');
      }

      const data = await response.json();
      localStorage.setItem('token', (data as { token: string }).token);
      window.location.href = '/dashboard';
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        placeholder="Username"
      />
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Password"
      />
      {error && <div className="error">{error}</div>}
      <button type="submit" disabled={loading}>
        {loading ? 'Logging in...' : 'Login'}
      </button>
    </form>
  );
}

// Pattern R5: Registration form with complex body
export function RegistrationForm() {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    phone: '',
    password: '',
    confirmPassword: '',
    acceptTerms: false,
  });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);

    await fetch('/api/v1/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        full_name: formData.name,
        email: formData.email,
        phone_number: formData.phone,
        password: formData.password,
        terms_accepted: formData.acceptTerms,
        registration_source: 'web',
        metadata: {
          browser: navigator.userAgent,
          locale: navigator.language,
        },
      }),
    });

    setLoading(false);
  };

  return (
    <form onSubmit={handleSubmit}>
      {/* Form fields */}
      <button type="submit" disabled={loading}>Register</button>
    </form>
  );
}

// Pattern R6: Using custom hook with hardcoded endpoint
export function UserSettings() {
  const { data: settings, loading, refetch } = useApi<Record<string, unknown>>(
    '/api/v1/users/me/settings'
  );
  const { mutate: updateSettings, loading: updating } = useMutation<void, Record<string, unknown>>('PUT');

  const handleSave = useCallback(async () => {
    if (!settings) return;
    await updateSettings('/api/v1/users/me/settings', settings);
    refetch();
  }, [settings, updateSettings, refetch]);

  if (loading) return <div>Loading settings...</div>;

  return (
    <div>
      <pre>{JSON.stringify(settings, null, 2)}</pre>
      <button onClick={handleSave} disabled={updating}>Save</button>
    </div>
  );
}

// Pattern R7: Component with multiple API calls
export function Dashboard() {
  const [stats, setStats] = useState<Record<string, number> | null>(null);
  const [notifications, setNotifications] = useState<unknown[]>([]);
  const [recentActivity, setRecentActivity] = useState<unknown[]>([]);

  useEffect(() => {
    // Multiple parallel API calls
    Promise.all([
      fetch('/api/v1/dashboard/stats').then((r) => r.json()),
      fetch('/api/v1/notifications/unread').then((r) => r.json()),
      fetch('/api/v1/activity/recent').then((r) => r.json()),
    ]).then(([statsData, notifData, activityData]) => {
      setStats(statsData as Record<string, number>);
      setNotifications((notifData as { items: unknown[] }).items);
      setRecentActivity((activityData as { items: unknown[] }).items);
    });
  }, []);

  return (
    <div className="dashboard">
      <div className="stats">{JSON.stringify(stats)}</div>
      <div className="notifications">{notifications.length} unread</div>
      <div className="activity">{recentActivity.length} recent</div>
    </div>
  );
}

// Pattern R8: Inline arrow function in JSX
export function QuickActions() {
  return (
    <div>
      <button
        onClick={() => fetch('/api/v1/actions/refresh', { method: 'POST' })}
      >
        Refresh
      </button>
      <button
        onClick={async () => {
          await fetch('/api/v1/actions/sync', { method: 'POST' });
          alert('Synced!');
        }}
      >
        Sync
      </button>
    </div>
  );
}
