'use client';

import { useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { Mail, Github, KeyRound, ShieldOff } from 'lucide-react';
import Layout from './Layout';

function GoogleIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor">
      <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" />
      <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
      <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
      <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
    </svg>
  );
}

interface AuthGatePageProps {
  ssoDisabled?: boolean;
}

type AuthTab = 'sso' | 'access-code';

export default function AuthGatePage({ ssoDisabled = false }: AuthGatePageProps) {
  const searchParams = useSearchParams();
  const returnTo = searchParams.get('return_to') || '/select-project';
  const signInUrl = `/api/auth/signin?return_to=${encodeURIComponent(returnTo)}`;

  const [activeTab, setActiveTab] = useState<AuthTab>(ssoDisabled ? 'access-code' : 'sso');
  const [accessCode, setAccessCode] = useState('');
  const [accessEmail, setAccessEmail] = useState('');
  const [accessError, setAccessError] = useState('');
  const [accessLoading, setAccessLoading] = useState(false);
  const [showAccessCode, setShowAccessCode] = useState(false);

  const handleAccessCodeSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAccessError('');

    const code = accessCode.trim();
    const email = accessEmail.trim();
    if (!code) {
      setAccessError('Access code is required');
      return;
    }
    if (!email) {
      setAccessError('Email is required');
      return;
    }

    setAccessLoading(true);
    try {
      const res = await fetch('/api/auth/access-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, email }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setAccessError(data.error || 'Invalid access code or email');
        return;
      }
      window.location.href = returnTo;
    } catch {
      setAccessError('Could not reach server');
    } finally {
      setAccessLoading(false);
    }
  };

  return (
    <Layout>
      <style>{`
        @keyframes logo-glow {
          0%, 100% { filter: drop-shadow(0 0 6px var(--v-accent)) drop-shadow(0 0 18px color-mix(in srgb, var(--v-accent) 30%, transparent)); }
          50% { filter: drop-shadow(0 0 10px var(--v-accent)) drop-shadow(0 0 28px color-mix(in srgb, var(--v-accent) 45%, transparent)); }
        }
      `}</style>
      <div className="min-h-screen flex flex-col items-center justify-center px-4">
        <div className="w-full max-w-sm">
          {/* Logo & Title */}
          <div className="text-center mb-10">
            <img
              src="/vigolium-logo-minimal.png"
              alt="Vigolium"
              className="w-28 h-28 mx-auto mb-6"
              style={{ animation: 'logo-glow 3s ease-in-out infinite' }}
            />
            <h1 className="text-xl font-bold tracking-widest" style={{ color: 'var(--v-accent)' }}>
              Vigolium Cloud Console
            </h1>
            <p className="text-xs mt-3 leading-relaxed max-w-xs mx-auto" style={{ color: 'var(--v-text-muted)' }}>
              High-fidelity vulnerability scanner fusing agentic AI with native speed, modularity, and precision
            </p>
          </div>

          {/* Auth Card */}
          <div
            className="border rounded overflow-hidden"
            style={{ backgroundColor: 'var(--v-surface)', borderColor: 'var(--v-border)' }}
          >
            {/* Tabs */}
            <div className="flex" style={{ borderBottom: '1px solid var(--v-border)' }}>
              <button
                onClick={() => { setActiveTab('sso'); setAccessError(''); }}
                className="flex-1 px-4 py-3 text-xs font-medium transition-all duration-200"
                style={{
                  color: activeTab === 'sso' ? 'var(--v-accent)' : 'var(--v-text-muted)',
                  borderBottom: activeTab === 'sso' ? '2px solid var(--v-accent)' : '2px solid transparent',
                  backgroundColor: activeTab === 'sso' ? 'rgba(46, 139, 87, 0.04)' : 'transparent',
                }}
              >
                SSO
              </button>
              <button
                onClick={() => { setActiveTab('access-code'); setAccessError(''); }}
                className="flex-1 px-4 py-3 text-xs font-medium transition-all duration-200"
                style={{
                  color: activeTab === 'access-code' ? 'var(--v-accent)' : 'var(--v-text-muted)',
                  borderBottom: activeTab === 'access-code' ? '2px solid var(--v-accent)' : '2px solid transparent',
                  backgroundColor: activeTab === 'access-code' ? 'rgba(46, 139, 87, 0.04)' : 'transparent',
                }}
              >
                Access Code
              </button>
            </div>

            <div className="p-6">
              {activeTab === 'sso' ? (
                ssoDisabled ? (
                  <div className="flex flex-col items-center gap-3 py-4 text-center">
                    <ShieldOff className="w-6 h-6" style={{ color: 'var(--v-text-muted)' }} />
                    <p className="text-xs leading-relaxed" style={{ color: 'var(--v-text-muted)' }}>
                      SSO login has been disabled by the administrator.<br />
                      Use the <button type="button" onClick={() => setActiveTab('access-code')} className="hover:underline" style={{ color: 'var(--v-accent)' }}>access code</button> tab to sign in.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    <p className="text-xs text-center mb-4" style={{ color: 'var(--v-secondary)' }}>
                      Select a provider to continue
                    </p>

                    <a
                      href={signInUrl}
                      className="flex items-center gap-3 w-full px-4 py-2.5 border rounded text-xs font-medium transition-all duration-200"
                      style={{
                        backgroundColor: 'rgba(46, 139, 87, 0.06)',
                        borderColor: 'rgba(46, 139, 87, 0.3)',
                        color: '#2e8b57',
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.backgroundColor = 'rgba(46, 139, 87, 0.12)';
                        e.currentTarget.style.borderColor = '#2e8b57';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.backgroundColor = 'rgba(46, 139, 87, 0.06)';
                        e.currentTarget.style.borderColor = 'rgba(46, 139, 87, 0.3)';
                      }}
                    >
                      <Mail className="w-4 h-4 flex-shrink-0" />
                      <span>Sign in with Email</span>
                    </a>

                    <a
                      href={signInUrl}
                      className="flex items-center gap-3 w-full px-4 py-2.5 border rounded text-xs font-medium transition-all duration-200"
                      style={{
                        backgroundColor: 'rgba(66, 133, 244, 0.06)',
                        borderColor: 'rgba(66, 133, 244, 0.3)',
                        color: '#4285f4',
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.backgroundColor = 'rgba(66, 133, 244, 0.12)';
                        e.currentTarget.style.borderColor = '#4285f4';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.backgroundColor = 'rgba(66, 133, 244, 0.06)';
                        e.currentTarget.style.borderColor = 'rgba(66, 133, 244, 0.3)';
                      }}
                    >
                      <GoogleIcon className="w-4 h-4 flex-shrink-0" />
                      <span>Sign in with Google</span>
                    </a>

                    <a
                      href={signInUrl}
                      className="flex items-center gap-3 w-full px-4 py-2.5 border rounded text-xs font-medium transition-all duration-200"
                      style={{
                        backgroundColor: 'rgba(36, 41, 46, 0.06)',
                        borderColor: 'rgba(36, 41, 46, 0.25)',
                        color: '#24292e',
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.backgroundColor = 'rgba(36, 41, 46, 0.12)';
                        e.currentTarget.style.borderColor = '#24292e';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.backgroundColor = 'rgba(36, 41, 46, 0.06)';
                        e.currentTarget.style.borderColor = 'rgba(36, 41, 46, 0.25)';
                      }}
                    >
                      <Github className="w-4 h-4 flex-shrink-0" />
                      <span>Sign in with GitHub</span>
                    </a>
                  </div>
                )
              ) : (
                <form onSubmit={handleAccessCodeSubmit}>
                  <p className="text-xs mb-4" style={{ color: 'var(--v-text-muted)' }}>
                    Enter your access code and email
                  </p>
                  <div className="space-y-2">
                    <div className="relative">
                      <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--v-text-muted)' }} />
                      <input
                        type={showAccessCode ? 'text' : 'password'}
                        value={accessCode}
                        onChange={(e) => setAccessCode(e.target.value)}
                        placeholder="Access code"
                        autoComplete="off"
                        className="w-full border rounded text-xs pl-9 pr-14 py-2.5 focus:outline-none transition-colors"
                        style={{
                          backgroundColor: 'var(--v-surface)',
                          borderColor: 'var(--v-border)',
                          color: 'var(--v-text)',
                        }}
                        onFocus={(e) => e.currentTarget.style.borderColor = 'var(--v-accent)'}
                        onBlur={(e) => e.currentTarget.style.borderColor = 'var(--v-border)'}
                      />
                      <button
                        type="button"
                        onClick={() => setShowAccessCode(!showAccessCode)}
                        className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[10px]"
                        style={{ color: 'var(--v-text-muted)' }}
                      >
                        {showAccessCode ? 'hide' : 'show'}
                      </button>
                    </div>
                    <div className="relative">
                      <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--v-text-muted)' }} />
                      <input
                        type="email"
                        value={accessEmail}
                        onChange={(e) => setAccessEmail(e.target.value)}
                        placeholder="you@company.com"
                        autoComplete="email"
                        className="w-full border rounded text-xs pl-9 pr-3 py-2.5 focus:outline-none transition-colors"
                        style={{
                          backgroundColor: 'var(--v-surface)',
                          borderColor: 'var(--v-border)',
                          color: 'var(--v-text)',
                        }}
                        onFocus={(e) => e.currentTarget.style.borderColor = 'var(--v-accent)'}
                        onBlur={(e) => e.currentTarget.style.borderColor = 'var(--v-border)'}
                      />
                    </div>
                    <button
                      type="submit"
                      disabled={accessLoading}
                      className="w-full px-4 py-2.5 border rounded text-xs font-medium transition-all duration-200 disabled:opacity-50"
                      style={{
                        backgroundColor: 'rgba(46, 139, 87, 0.06)',
                        borderColor: 'rgba(46, 139, 87, 0.3)',
                        color: '#2e8b57',
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.backgroundColor = 'rgba(46, 139, 87, 0.12)';
                        e.currentTarget.style.borderColor = '#2e8b57';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.backgroundColor = 'rgba(46, 139, 87, 0.06)';
                        e.currentTarget.style.borderColor = 'rgba(46, 139, 87, 0.3)';
                      }}
                    >
                      {accessLoading ? '...' : 'Sign In'}
                    </button>
                  </div>
                  {accessError && (
                    <p className="text-xs mt-2" style={{ color: '#dc3545' }}>{accessError}</p>
                  )}
                </form>
              )}
            </div>
          </div>

          {/* Footer */}
          <div className="text-center mt-8">
            <div className="flex items-center justify-center gap-3 text-xs" style={{ color: 'var(--v-text-muted)' }}>
              <a href="https://vigolium.com" target="_blank" rel="noopener noreferrer" className="hover:underline transition-colors" style={{ color: 'var(--v-text-muted)' }} onMouseEnter={(e) => e.currentTarget.style.color = 'var(--v-accent)'} onMouseLeave={(e) => e.currentTarget.style.color = 'var(--v-text-muted)'}>[website]</a>
              <span>·</span>
              <a href="https://docs.vigolium.com" target="_blank" rel="noopener noreferrer" className="hover:underline transition-colors" style={{ color: 'var(--v-text-muted)' }} onMouseEnter={(e) => e.currentTarget.style.color = 'var(--v-accent)'} onMouseLeave={(e) => e.currentTarget.style.color = 'var(--v-text-muted)'}>[docs]</a>
              <span>·</span>
              <a href="/showcases" className="hover:underline transition-colors" style={{ color: 'var(--v-text-muted)' }} onMouseEnter={(e) => e.currentTarget.style.color = 'var(--v-accent)'} onMouseLeave={(e) => e.currentTarget.style.color = 'var(--v-text-muted)'}>[showcases]</a>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}
