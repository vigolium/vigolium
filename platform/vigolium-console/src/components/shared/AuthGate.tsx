'use client';

import { useState, useEffect, useCallback, type ReactNode } from 'react';
import { getToken, setToken, clearAuth, checkServerInfo, getBaseUrl, onAuthRequired, login, fetchUserInfo } from '@/api/client';
import { getScheme, applySchemeVars, DEFAULT_DARK_SCHEME } from '@/lib/colorSchemes';
import { trackEvent } from '@/lib/posthogClient';

interface AuthGateProps {
  children: ReactNode;
}

export default function AuthGate({ children }: AuthGateProps) {
  const [state, setState] = useState<'loading' | 'auth' | 'ready'>('loading');
  const [authTab, setAuthTab] = useState<'api_key' | 'credentials'>('api_key');
  const [usernameInput, setUsernameInput] = useState('');
  const [accessCodeInput, setAccessCodeInput] = useState('');
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [error, setError] = useState('');
  const [showAccessCode, setShowAccessCode] = useState(false);
  const [showApiKey, setShowApiKey] = useState(false);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  // Apply default dark theme vars immediately so the login page has proper colors
  // (ThemeProvider is a child of AuthGate and hasn't mounted yet)
  useEffect(() => {
    if (state !== 'ready') {
      applySchemeVars(getScheme(DEFAULT_DARK_SCHEME).colors);
    }
  }, [state]);

  const tryConnect = useCallback(async () => {
    // Check if backend is accessible without auth
    const { noAuth } = await checkServerInfo();
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

    if (authTab === 'api_key') {
      const apiKey = apiKeyInput.trim();
      if (!apiKey) {
        setError('api_key is required');
        return;
      }

      setLoading(true);
      try {
        const base = getBaseUrl();
        const res = await fetch(new URL('/server-info', base).toString(), {
          headers: { Authorization: `Bearer ${apiKey}` },
        });
        if (!res.ok) {
          setError('invalid api key');
          return;
        }
        setToken(apiKey);
        await fetchUserInfo();
        setState('ready');
      } catch {
        setError('cannot connect to server');
      } finally {
        setLoading(false);
      }
    } else {
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
    }
  };

  const handleLogout = () => {
    clearAuth();
    setState('auth');
    setUsernameInput('');
    setAccessCodeInput('');
    setApiKeyInput('');
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
        <img src="/vigolium-logo-minimal.png" alt="" className="h-28 w-28 mb-5 rounded-lg border border-sky-400/50 animate-logo-glow" />
        <style jsx>{`
          @keyframes logo-glow {
            0%, 100% { box-shadow: 0 0 12px rgba(56, 189, 248, 0.25); }
            50% { box-shadow: 0 0 28px rgba(56, 189, 248, 0.55), 0 0 48px rgba(56, 189, 248, 0.20); }
          }
          .animate-logo-glow { animation: logo-glow 3s ease-in-out infinite; }
        `}</style>
        <h1 className="text-sky-400 text-xl font-bold mb-1">Vigolium Workbench</h1>
        <p className="text-[var(--v-text-muted)] text-sm text-center max-w-lg mb-5">High-fidelity vulnerability scanner fusing agentic AI with native speed, modularity, and precision</p>

        <div className="w-full max-w-lg border border-[var(--v-border)] bg-[var(--v-bg)]">
          {/* Tabs */}
          <div className="flex border-b border-[var(--v-border)]">
            <button
              type="button"
              onClick={() => { setAuthTab('api_key'); setError(''); }}
              className={`flex-1 px-4 py-3 text-sm font-bold transition-colors ${authTab === 'api_key' ? 'text-[var(--v-accent)] border-b border-[var(--v-accent)]' : 'text-[var(--v-text-muted)] hover:text-[var(--v-text)]'}`}
            >
              API KEY
            </button>
            <button
              type="button"
              onClick={() => { setAuthTab('credentials'); setError(''); }}
              className={`flex-1 px-4 py-3 text-sm font-bold transition-colors ${authTab === 'credentials' ? 'text-[var(--v-accent)] border-b border-[var(--v-accent)]' : 'text-[var(--v-text-muted)] hover:text-[var(--v-text)]'}`}
            >
              CREDENTIALS
            </button>
          </div>

          <div className="p-5">
            <form onSubmit={handleSubmit} className="space-y-5">
              {authTab === 'api_key' ? (
                /* API Key */
                <>
                  <div>
                    <label className="block text-[var(--v-text-muted)] text-sm mb-1.5">auth_api_key:</label>
                    <div className="relative flex items-center">
                      <span className="absolute left-3 text-[var(--v-border)] text-sm">&gt;</span>
                      <input
                        type={showApiKey ? 'text' : 'password'}
                        value={apiKeyInput}
                        onChange={(e) => setApiKeyInput(e.target.value)}
                        placeholder="vgl_..."
                        autoComplete="off"
                        className="w-full bg-[var(--v-surface)] border border-[var(--v-border)] text-[var(--v-text)] text-base pl-7 pr-16 py-2 focus:outline-none focus:border-[var(--v-accent)]/50 placeholder-[var(--v-text-muted)]"
                      />
                      <button
                        type="button"
                        onClick={() => setShowApiKey(!showApiKey)}
                        className="absolute right-3 text-[var(--v-text-muted)] hover:text-[var(--v-text)] text-sm"
                      >
                        [{showApiKey ? 'hide' : 'show'}]
                      </button>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => { navigator.clipboard.writeText('vigolium config view server.auth_api_key --force'); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
                    className="w-full text-left bg-[var(--v-surface)] border border-[var(--v-border)] px-3 py-2 hover:border-[var(--v-accent)]/30 transition-colors cursor-pointer"
                  >
                    <span className="flex items-center justify-between text-[var(--v-text-muted)] text-xs">
                      <span>run this to view your api key:</span>
                      <span>{copied ? 'copied!' : 'click to copy'}</span>
                    </span>
                    <code className="block text-[var(--v-accent)] text-sm mt-1">$ vigolium config view server.auth_api_key --force</code>
                  </button>
                </>
              ) : (
                /* Username + Access Code */
                <>
                  <div>
                    <label className="block text-[var(--v-text-muted)] text-sm mb-1.5">username:</label>
                    <div className="relative flex items-center">
                      <span className="absolute left-3 text-[var(--v-border)] text-sm">&gt;</span>
                      <input
                        type="text"
                        value={usernameInput}
                        onChange={(e) => setUsernameInput(e.target.value)}
                        placeholder="username"
                        autoComplete="username"
                        className="w-full bg-[var(--v-surface)] border border-[var(--v-border)] text-[var(--v-text)] text-base pl-7 pr-3 py-2 focus:outline-none focus:border-[var(--v-accent)]/50 placeholder-[var(--v-text-muted)]"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-[var(--v-text-muted)] text-sm mb-1.5">access_code:</label>
                    <div className="relative flex items-center">
                      <span className="absolute left-3 text-[var(--v-border)] text-sm">&gt;</span>
                      <input
                        type={showAccessCode ? 'text' : 'password'}
                        value={accessCodeInput}
                        onChange={(e) => setAccessCodeInput(e.target.value)}
                        placeholder="vgl_..."
                        autoComplete="current-password"
                        className="w-full bg-[var(--v-surface)] border border-[var(--v-border)] text-[var(--v-text)] text-base pl-7 pr-16 py-2 focus:outline-none focus:border-[var(--v-accent)]/50 placeholder-[var(--v-text-muted)]"
                      />
                      <button
                        type="button"
                        onClick={() => setShowAccessCode(!showAccessCode)}
                        className="absolute right-3 text-[var(--v-text-muted)] hover:text-[var(--v-text)] text-sm"
                      >
                        [{showAccessCode ? 'hide' : 'show'}]
                      </button>
                    </div>
                  </div>
                </>
              )}

              {/* Error */}
              {error && (
                <div className="text-[var(--v-error)] text-sm">
                  <span className="text-[var(--v-error)]">err:</span> {error}
                </div>
              )}

              {/* Submit */}
              <button
                type="submit"
                disabled={loading}
                className="w-full border border-[var(--v-border)] bg-[var(--v-surface)] text-[var(--v-accent)] text-base py-2 hover:bg-[var(--v-accent)]/10 hover:border-[var(--v-accent)]/30 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? '[authenticating...]' : '[login]'}
              </button>
            </form>
          </div>
        </div>

        <div className="flex items-center gap-3 mt-5 text-sm">
          <a href="https://www.vigolium.com/" target="_blank" rel="noopener noreferrer" className="text-[var(--v-accent)] hover:underline">[website]</a>
          <span className="text-[var(--v-text-muted)]">·</span>
          <a href="https://docs.vigolium.com/" target="_blank" rel="noopener noreferrer" className="text-[var(--v-accent)] hover:underline">[docs]</a>
          <span className="text-[var(--v-text-muted)]">·</span>
          <a href="/showcases" onClick={() => trackEvent('showcases_link_clicked', { location: 'authgate_shared' })} className="text-[var(--v-accent)] hover:underline">[showcases]</a>
        </div>
        <p className="text-[var(--v-text-muted)] text-sm text-center mt-2">
          Crafted with <span className="text-[var(--v-error)]">&lt;3</span> by{' '}
          <a href="https://twitter.com/j3ssie" target="_blank" rel="noopener noreferrer" className="text-[var(--v-accent)] hover:underline">@j3ssie</a>
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
