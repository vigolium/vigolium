'use client';

import { useState, useEffect, useCallback, type ReactNode } from 'react';
import { getToken, setToken, setBaseUrl, getBaseUrl, clearAuth, checkServerInfo, onAuthRequired } from '@/api/client';

interface AuthGateProps {
  children: ReactNode;
}

export default function AuthGate({ children }: AuthGateProps) {
  const [state, setState] = useState<'loading' | 'auth' | 'ready'>('loading');
  const [tokenInput, setTokenInput] = useState('');
  const [urlInput, setUrlInput] = useState('');
  const [error, setError] = useState('');
  const [showToken, setShowToken] = useState(false);
  const [showUrl, setShowUrl] = useState(false);
  const [copied, setCopied] = useState(false);

  const tryConnect = useCallback(async () => {
    // Check if backend is accessible without auth
    const { ok, noAuth } = await checkServerInfo();
    if (noAuth) {
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

    if (urlInput.trim()) {
      setBaseUrl(urlInput.trim());
    }
    if (tokenInput.trim()) {
      setToken(tokenInput.trim());
    }

    try {
      const base = getBaseUrl();
      const headers: Record<string, string> = {};
      const token = tokenInput.trim();
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      const res = await fetch(new URL('/server-info', base).toString(), { headers });
      if (res.ok) {
        setState('ready');
      } else if (res.status === 401) {
        setError('invalid api token');
      } else {
        setError(`server returned ${res.status}`);
      }
    } catch {
      setError('cannot connect to server');
    }
  };

  const handleLogout = () => {
    clearAuth();
    setState('auth');
    setTokenInput('');
  };

  if (state === 'loading') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#1c1b19] font-mono">
        <div className="flex items-center gap-2 text-[#918175] text-sm">
          <span className="text-[#7fd962] animate-pulse">&#9608;</span>
          <span>connecting...</span>
        </div>
      </div>
    );
  }

  if (state === 'auth') {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-[#1c1b19] p-4 font-mono">
        {/* Logo above login box */}
        <img src="/vigolium-logo-minimal.png" alt="" className="h-20 w-20 mb-4 rounded-lg border border-[#7fd962]/50 shadow-[0_0_16px_rgba(127,217,98,0.35)]" />

        <div className="w-full max-w-md border border-[#2e2b26] bg-[#1c1b19]">
          {/* Header */}
          <div className="px-4 py-2 border-b border-[#2e2b26] flex items-center gap-2">
            <span className="text-[#7fd962] text-sm font-bold">VIGOLIUM</span>
            <span className="text-[#403d38]">|</span>
            <span className="text-[#918175] text-xs">api login</span>
          </div>

          <div className="p-4">
            <form onSubmit={handleSubmit} className="space-y-4">
              {/* API Token */}
              <div>
                <label className="block text-[#918175] text-xs mb-1">api_token:</label>
                <div className="relative flex items-center">
                  <span className="absolute left-2 text-[#403d38] text-xs">&gt;</span>
                  <input
                    type={showToken ? 'text' : 'password'}
                    value={tokenInput}
                    onChange={(e) => setTokenInput(e.target.value)}
                    placeholder="bearer token..."
                    className="w-full bg-[#141310] border border-[#2e2b26] text-[#fce8c3] text-sm pl-6 pr-14 py-1.5 focus:outline-none focus:border-[#7fd962]/50 placeholder-[#403d38]"
                  />
                  <button
                    type="button"
                    onClick={() => setShowToken(!showToken)}
                    className="absolute right-2 text-[#918175] hover:text-[#fce8c3] text-xs"
                  >
                    [{showToken ? 'hide' : 'show'}]
                  </button>
                </div>
              </div>

              {/* API URL toggle */}
              <div>
                <button
                  type="button"
                  onClick={() => setShowUrl(!showUrl)}
                  className="text-[#918175] hover:text-[#fce8c3] text-xs"
                >
                  [{showUrl ? '-' : '+'}] api_url
                </button>
                {showUrl && (
                  <div className="relative flex items-center mt-1">
                    <span className="absolute left-2 text-[#403d38] text-xs">&gt;</span>
                    <input
                      type="url"
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      placeholder={getBaseUrl()}
                      className="w-full bg-[#141310] border border-[#2e2b26] text-[#fce8c3] text-sm pl-6 pr-3 py-1.5 focus:outline-none focus:border-[#7fd962]/50 placeholder-[#403d38]"
                    />
                  </div>
                )}
              </div>

              {/* Error */}
              {error && (
                <div className="text-[#ef2f27] text-xs">
                  <span className="text-[#f75341]">err:</span> {error}
                </div>
              )}

              {/* Submit */}
              <button
                type="submit"
                className="w-full border border-[#2e2b26] bg-[#141310] text-[#7fd962] text-sm py-1.5 hover:bg-[#7fd962]/10 hover:border-[#7fd962]/30 transition-colors"
              >
                [connect]
              </button>
            </form>

            {/* Credential hint */}
            <div className="mt-4 pt-3 border-t border-[#2e2b26]">
              <p className="text-[#918175] text-xs leading-relaxed">
                get your credentials:
              </p>
              <pre
                onClick={() => {
                  navigator.clipboard.writeText('vigolium config view server.auth_api_key --force');
                  setCopied(true);
                  setTimeout(() => setCopied(false), 2000);
                }}
                className="mt-1 bg-[#141310] border border-[#2e2b26] px-2 py-1.5 text-[#fce8c3] text-xs overflow-x-auto cursor-pointer hover:border-[#7fd962]/50 transition-colors group relative"
                title="click to copy"
              >
                <span className="text-[#7fd962]">$</span> vigolium config view server.auth_api_key --force
                <span className="absolute right-2 top-1/2 -translate-y-1/2 text-[#7fd962] text-xs">
                  {copied ? 'copied!' : <span className="opacity-0 group-hover:opacity-100 text-[#918175] transition-opacity">[copy]</span>}
                </span>
              </pre>
            </div>
          </div>
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
