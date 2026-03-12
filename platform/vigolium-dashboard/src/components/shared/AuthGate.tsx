'use client';

import { useState, useEffect, useCallback, type ReactNode } from 'react';
import { getToken, setToken, clearAuth, checkServerInfo, getBaseUrl, onAuthRequired, login, fetchUserInfo } from '@/api/client';
import { getScheme, applySchemeVars, DEFAULT_DARK_SCHEME } from '@/lib/colorSchemes';

interface AuthGateProps {
  children: ReactNode;
}

export default function AuthGate({ children }: AuthGateProps) {
  const [state, setState] = useState<'loading' | 'auth' | 'ready'>('loading');
  const [usernameInput, setUsernameInput] = useState('');
  const [accessCodeInput, setAccessCodeInput] = useState('');
  const [error, setError] = useState('');
  const [showAccessCode, setShowAccessCode] = useState(false);
  const [loading, setLoading] = useState(false);

  // Apply default dark theme vars immediately so the login page has proper colors
  // (ThemeProvider is a child of AuthGate and hasn't mounted yet)
  useEffect(() => {
    if (state !== 'ready') {
      applySchemeVars(getScheme(DEFAULT_DARK_SCHEME).colors);
    }
  }, [state]);

  const tryConnect = useCallback(async () => {
    // Check if backend is accessible without auth
    const { ok, noAuth } = await checkServerInfo();
    if (noAuth) {
      await fetchUserInfo();
      setState('ready');
      return;
    }

    // Check if we have a stored token
    const token = getToken();
    if (token) {
      try {
        const base = getBaseUrl();
        const res = await fetch(new URL('/server-info', base).toString(), {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.ok) {
          await fetchUserInfo();
          setState('ready');
          return;
        }
      } catch {
        // fall through to auth
      }
    }

    setState('auth');
  }, []);

  useEffect(() => {
    tryConnect();
    return onAuthRequired(() => setState('auth'));
  }, [tryConnect]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    const username = usernameInput.trim();
    const accessCode = accessCodeInput.trim();

    if (!username || !accessCode) {
      setError('username and access_code are required');
      return;
    }

    setLoading(true);
    try {
      const result = await login(username, accessCode);
      setToken(result.token);
      await fetchUserInfo();
      setState('ready');
    } catch (err) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('cannot connect to server');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    clearAuth();
    setState('auth');
    setUsernameInput('');
    setAccessCodeInput('');
  };

  if (state === 'loading') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[var(--v-bg)] font-mono">
        <div className="flex items-center gap-2 text-[var(--v-text-muted)] text-sm">
          <span className="text-[var(--v-accent)] animate-pulse">&#9608;</span>
          <span>connecting...</span>
        </div>
      </div>
    );
  }

  if (state === 'auth') {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-[var(--v-bg)] p-4 font-mono">
        {/* Logo above login box */}
        <img src="/vigolium-logo-minimal.png" alt="" className="h-32 w-32 mb-4 rounded-lg border border-[var(--v-accent)]/50 animate-logo-glow" />
        <style jsx>{`
          @keyframes logo-glow {
            0%, 100% { box-shadow: 0 0 12px color-mix(in srgb, var(--v-accent) 25%, transparent); }
            50% { box-shadow: 0 0 28px color-mix(in srgb, var(--v-accent) 55%, transparent), 0 0 48px color-mix(in srgb, var(--v-accent) 20%, transparent); }
          }
          .animate-logo-glow { animation: logo-glow 3s ease-in-out infinite; }
        `}</style>
        <p className="text-[var(--v-text-muted)] text-xs text-center max-w-md mb-4"><a href="https://github.com/vigolium" target="_blank" rel="noopener noreferrer" className="text-[var(--v-accent)] hover:underline">Vigolium</a> - High-fidelity web vulnerability scanner that combines speed, modularity, precision, and AI-powered analysis.</p>

        <div className="w-full max-w-md border border-[var(--v-border)] bg-[var(--v-bg)]">
          {/* Header */}
          <div className="px-4 py-2 border-b border-[var(--v-border)] flex items-center gap-2">
            <span className="text-[var(--v-accent)] text-sm font-bold">AUTHENTICATE GATE</span>
          </div>

          <div className="p-4">
            <form onSubmit={handleSubmit} className="space-y-4">
              {/* Username */}
              <div>
                <label className="block text-[var(--v-text-muted)] text-xs mb-1">username:</label>
                <div className="relative flex items-center">
                  <span className="absolute left-2 text-[var(--v-border)] text-xs">&gt;</span>
                  <input
                    type="text"
                    value={usernameInput}
                    onChange={(e) => setUsernameInput(e.target.value)}
                    placeholder="username"
                    autoComplete="username"
                    className="w-full bg-[var(--v-surface)] border border-[var(--v-border)] text-[var(--v-text)] text-sm pl-6 pr-3 py-1.5 focus:outline-none focus:border-[var(--v-accent)]/50 placeholder-[var(--v-text-muted)]"
                  />
                </div>
              </div>

              {/* Access Code */}
              <div>
                <label className="block text-[var(--v-text-muted)] text-xs mb-1">access_code:</label>
                <div className="relative flex items-center">
                  <span className="absolute left-2 text-[var(--v-border)] text-xs">&gt;</span>
                  <input
                    type={showAccessCode ? 'text' : 'password'}
                    value={accessCodeInput}
                    onChange={(e) => setAccessCodeInput(e.target.value)}
                    placeholder="vgl_..."
                    autoComplete="current-password"
                    className="w-full bg-[var(--v-surface)] border border-[var(--v-border)] text-[var(--v-text)] text-sm pl-6 pr-14 py-1.5 focus:outline-none focus:border-[var(--v-accent)]/50 placeholder-[var(--v-text-muted)]"
                  />
                  <button
                    type="button"
                    onClick={() => setShowAccessCode(!showAccessCode)}
                    className="absolute right-2 text-[var(--v-text-muted)] hover:text-[var(--v-text)] text-xs"
                  >
                    [{showAccessCode ? 'hide' : 'show'}]
                  </button>
                </div>
              </div>

              {/* Error */}
              {error && (
                <div className="text-[var(--v-error)] text-xs">
                  <span className="text-[var(--v-error)]">err:</span> {error}
                </div>
              )}

              {/* Submit */}
              <button
                type="submit"
                disabled={loading}
                className="w-full border border-[var(--v-border)] bg-[var(--v-surface)] text-[var(--v-accent)] text-sm py-1.5 hover:bg-[var(--v-accent)]/10 hover:border-[var(--v-accent)]/30 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? '[authenticating...]' : '[login]'}
              </button>
            </form>
          </div>
        </div>

        <p className="text-[var(--v-text-muted)] text-xs text-center mt-4">
          Crafted with <span className="text-[var(--v-error)]">&lt;3</span> by{' '}
          <a href="https://twitter.com/j3ssie" target="_blank" rel="noopener noreferrer" className="text-[var(--v-accent)] hover:underline">@j3ssie</a>
          {' & '}
          <a href="https://github.com/theblackturtle" target="_blank" rel="noopener noreferrer" className="text-[var(--v-accent)] hover:underline">@theblackturtle</a>
        </p>
      </div>
    );
  }

  return (
    <>
      {children}
      {/* Expose logout function globally */}
      <button
        onClick={handleLogout}
        className="hidden"
        id="vigolium-logout"
        aria-hidden
      />
    </>
  );
}
