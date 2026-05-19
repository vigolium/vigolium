'use client';

import { useState, useEffect, useCallback, type ReactNode } from 'react';
import { KeyRound, User, LogIn, Loader2 } from 'lucide-react';
import { getToken, setToken, clearAuth, checkServerInfo, getBaseUrl, onAuthRequired, login, fetchUserInfo } from '@/api/client';
import { getScheme, applySchemeVars, DEFAULT_DARK_SCHEME } from '@/lib/colorSchemes';
import KrakenOrb from '@/components/shared/KrakenOrb';

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

    // Enforce a minimum spinner duration so the auth animation is actually
    // visible even when the backend responds instantly (e.g. localhost).
    const MIN_SPIN_MS = 650;
    const startedAt = Date.now();
    const settle = async () => {
      const elapsed = Date.now() - startedAt;
      if (elapsed < MIN_SPIN_MS) {
        await new Promise((r) => setTimeout(r, MIN_SPIN_MS - elapsed));
      }
    };

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
          await settle();
          setError('invalid api key');
          return;
        }
        setToken(apiKey);
        await fetchUserInfo();
        await settle();
        setState('ready');
      } catch {
        await settle();
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
        await settle();
        setState('ready');
      } catch (err) {
        await settle();
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
      <div className="min-h-screen flex flex-col items-center justify-center bg-[var(--v-bg)] px-4 py-10 font-mono">
        <style>{`
          @keyframes login-shell-fade-in {
            from { opacity: 0; transform: translateY(2px); }
            to { opacity: 1; transform: translateY(0); }
          }
          .login-shell-fade-in { animation: login-shell-fade-in 280ms ease-out both; }

          @keyframes login-card-swap {
            from { opacity: 0; transform: translateY(4px); }
            to { opacity: 1; transform: translateY(0); }
          }
          .login-card-swap { animation: login-card-swap 220ms ease-out both; }

          .auth-btn-glow-muted { transition: box-shadow 0.4s ease, opacity 0.2s ease; }
          .auth-btn-glow-muted:hover { box-shadow: 0 0 12px color-mix(in srgb, var(--v-text) 50%, transparent), 0 0 28px color-mix(in srgb, var(--v-text) 28%, transparent), 0 0 56px color-mix(in srgb, var(--v-text) 14%, transparent); }
          .auth-link-glow { transition: text-shadow 0.2s ease, color 0.2s ease; }
          .auth-link-glow:hover { color: #fb923c; text-shadow: 0 0 8px color-mix(in srgb, #fb923c 70%, transparent), 0 0 18px color-mix(in srgb, #fb923c 35%, transparent); }
          .auth-cmd-glow { transition: box-shadow 0.3s ease, border-color 0.2s ease, background-color 0.2s ease; }
          .auth-cmd-glow:hover { border-color: color-mix(in srgb, var(--v-accent) 35%, transparent); background-color: color-mix(in srgb, var(--v-accent) 6%, transparent); box-shadow: 0 0 8px color-mix(in srgb, var(--v-accent) 18%, transparent), 0 0 18px color-mix(in srgb, var(--v-accent) 8%, transparent); }
          @media (prefers-reduced-motion: reduce) {
            .login-shell-fade-in, .login-card-swap, .auth-btn-glow-muted, .auth-link-glow, .auth-cmd-glow { animation: none; transition: none; }
          }
        `}</style>
        <div className="login-shell-fade-in flex flex-col items-center w-full">
          {/* Animated Kraken Orb logo */}
          <KrakenOrb size={300} className="mb-6" />
          <h1 className="text-sky-400 text-xl font-bold mb-3 text-center">Vigolium Workbench</h1>
          <p className="text-sm leading-relaxed mb-6 text-center max-w-xl" style={{ color: 'var(--v-text-muted)' }}>High-fidelity vulnerability scanner fusing agentic AI with native speed, modularity, and precision.</p>

          <div
            className="w-full max-w-md border text-center"
            style={{ backgroundColor: 'var(--v-surface)', borderColor: 'var(--v-border)' }}
          >
            {/* Tabs */}
            <div className="flex border-b" style={{ borderColor: 'var(--v-border)' }}>
              <button
                type="button"
                onClick={() => { setAuthTab('api_key'); setError(''); }}
                className={`flex-1 px-4 py-2.5 text-xs font-semibold transition-colors ${authTab === 'api_key' ? 'border-b' : ''}`}
                style={authTab === 'api_key'
                  ? { color: 'var(--v-accent)', borderBottomColor: 'var(--v-accent)' }
                  : { color: 'var(--v-text-muted)' }}
              >
                API KEY
              </button>
              <button
                type="button"
                onClick={() => { setAuthTab('credentials'); setError(''); }}
                className={`flex-1 px-4 py-2.5 text-xs font-semibold transition-colors ${authTab === 'credentials' ? 'border-b' : ''}`}
                style={authTab === 'credentials'
                  ? { color: 'var(--v-accent)', borderBottomColor: 'var(--v-accent)' }
                  : { color: 'var(--v-text-muted)' }}
              >
                CREDENTIALS
              </button>
            </div>

            <div key={authTab} className="login-card-swap p-5 text-left">
              <form onSubmit={handleSubmit} className="space-y-2">
                {authTab === 'api_key' ? (
                  <>
                    <p className="text-xs mb-3 text-center" style={{ color: 'var(--v-text-muted)' }}>Authenticate with your Vigolium API key</p>
                    <div className="relative">
                      <KeyRound className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--v-text-muted)' }} />
                      <input
                        type={showApiKey ? 'text' : 'password'}
                        value={apiKeyInput}
                        onChange={(e) => setApiKeyInput(e.target.value)}
                        placeholder="vgl_..."
                        autoComplete="off"
                        className="w-full border text-xs pl-8 pr-14 py-2.5 focus:outline-none bg-transparent"
                        style={{ borderColor: 'var(--v-border)', color: 'var(--v-text)' }}
                      />
                      <button
                        type="button"
                        onClick={() => setShowApiKey(!showApiKey)}
                        className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px]"
                        style={{ color: 'var(--v-text-muted)' }}
                      >
                        [{showApiKey ? 'hide' : 'show'}]
                      </button>
                    </div>
                    <button
                      type="button"
                      onClick={() => { navigator.clipboard.writeText('vigolium config view server.auth_api_key --force'); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
                      className="auth-cmd-glow w-full text-left border px-3 py-2 cursor-pointer"
                      style={{
                        borderColor: 'color-mix(in srgb, var(--v-accent) 18%, transparent)',
                        backgroundColor: 'color-mix(in srgb, var(--v-accent) 3%, transparent)',
                      }}
                    >
                      <span className="flex items-center justify-between text-[10px]" style={{ color: 'var(--v-text-muted)' }}>
                        <span>run this to view your api key:</span>
                        <span style={{ color: copied ? 'var(--v-accent)' : 'var(--v-text-muted)' }}>{copied ? 'copied!' : 'click to copy'}</span>
                      </span>
                      <code className="block text-xs mt-1 font-semibold" style={{ color: 'var(--v-accent)' }}>$ vigolium config view server.auth_api_key --force</code>
                    </button>
                  </>
                ) : (
                  <>
                    <p className="text-xs mb-3 text-center" style={{ color: 'var(--v-text-muted)' }}>Sign in with your username and access code</p>
                    <div className="relative">
                      <User className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--v-text-muted)' }} />
                      <input
                        type="text"
                        value={usernameInput}
                        onChange={(e) => setUsernameInput(e.target.value)}
                        placeholder="username"
                        autoComplete="username"
                        className="w-full border text-xs pl-8 pr-3 py-2.5 focus:outline-none bg-transparent"
                        style={{ borderColor: 'var(--v-border)', color: 'var(--v-text)' }}
                      />
                    </div>
                    <div className="relative">
                      <KeyRound className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--v-text-muted)' }} />
                      <input
                        type={showAccessCode ? 'text' : 'password'}
                        value={accessCodeInput}
                        onChange={(e) => setAccessCodeInput(e.target.value)}
                        placeholder="access code"
                        autoComplete="current-password"
                        className="w-full border text-xs pl-8 pr-14 py-2.5 focus:outline-none bg-transparent"
                        style={{ borderColor: 'var(--v-border)', color: 'var(--v-text)' }}
                      />
                      <button
                        type="button"
                        onClick={() => setShowAccessCode(!showAccessCode)}
                        className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px]"
                        style={{ color: 'var(--v-text-muted)' }}
                      >
                        [{showAccessCode ? 'hide' : 'show'}]
                      </button>
                    </div>
                  </>
                )}

                <button
                  type="submit"
                  disabled={loading}
                  className="flex items-center justify-center gap-2 w-full px-4 py-2 text-xs font-semibold transition-all duration-150 auth-btn-glow-muted disabled:opacity-50 disabled:cursor-not-allowed"
                  style={{ backgroundColor: 'var(--v-text)', color: 'var(--v-bg)' }}
                >
                  {loading ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      <span>authenticating...</span>
                    </>
                  ) : (
                    <>
                      <LogIn className="w-3.5 h-3.5" />
                      <span>Sign in</span>
                    </>
                  )}
                </button>

                {error && (
                  <p className="text-[10px] mt-2" style={{ color: 'var(--v-error)' }}>{error}</p>
                )}
              </form>
            </div>
          </div>

          <div className="flex items-center justify-center gap-4 mt-6 text-xs" style={{ color: 'var(--v-text-muted)' }}>
            <a href="https://www.vigolium.com/" target="_blank" rel="noopener noreferrer" className="text-[var(--v-accent)] auth-link-glow no-underline hover:no-underline">[website]</a>
            <span>·</span>
            <a href="https://console.vigolium.com/" target="_blank" rel="noopener noreferrer" className="text-[var(--v-accent)] auth-link-glow no-underline hover:no-underline">[vigolium cloud]</a>
            <span>·</span>
            <a href="https://docs.vigolium.com/" target="_blank" rel="noopener noreferrer" className="text-[var(--v-accent)] auth-link-glow no-underline hover:no-underline">[docs]</a>
          </div>
          <p className="text-xs text-center mt-2" style={{ color: 'var(--v-text-muted)' }}>
            Crafted with <span className="text-[var(--v-error)]">&lt;3</span> by{' '}
            <a href="https://twitter.com/j3ssie" target="_blank" rel="noopener noreferrer" className="text-[var(--v-accent)] auth-link-glow no-underline hover:no-underline">@j3ssie</a>
          </p>
        </div>
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
