'use client';

import { useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { Mail, Github, KeyRound, ShieldOff, ShieldCheck, Lock, LogIn } from 'lucide-react';
import { trackEvent } from '@/lib/posthogClient';

function GoogleIcon({ className, style }: { className?: string; style?: React.CSSProperties }) {
  return (
    <svg className={className} style={style} viewBox="0 0 24 24" fill="currentColor">
      <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" />
      <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
      <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
      <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
    </svg>
  );
}

interface AuthGatePageProps {
  ssoDisabled?: boolean;
  showcasesEnabled?: boolean;
}

type AuthTab = 'sso' | 'access-code';

export default function AuthGatePage({ ssoDisabled = false, showcasesEnabled = false }: AuthGatePageProps) {
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
    <div
      className="min-h-screen flex items-center justify-center px-4"
      style={{
        backgroundColor: 'var(--v-bg)',
        color: 'var(--v-text)',
        fontFamily: '"JetBrains Mono", "Fira Code", monospace',
      }}
    >
      <style>{`
        @keyframes auth-logo-glow {
          0%, 100% { filter: drop-shadow(0 0 6px var(--v-accent)) drop-shadow(0 0 18px color-mix(in srgb, var(--v-accent) 30%, transparent)); }
          50% { filter: drop-shadow(0 0 10px var(--v-accent)) drop-shadow(0 0 28px color-mix(in srgb, var(--v-accent) 45%, transparent)); }
        }
        .auth-logo-glow { animation: auth-logo-glow 3s ease-in-out infinite; }
        .auth-btn-glow { transition: box-shadow 0.2s ease; }
        .auth-btn-glow:hover { box-shadow: 0 0 14px color-mix(in srgb, var(--v-accent) 40%, transparent), 0 0 28px color-mix(in srgb, var(--v-accent) 15%, transparent); }
        .auth-btn-glow-muted { transition: box-shadow 0.2s ease; }
        .auth-btn-glow-muted:hover { box-shadow: 0 0 12px color-mix(in srgb, var(--v-text) 15%, transparent), 0 0 24px color-mix(in srgb, var(--v-text) 6%, transparent); }
      `}</style>

      <div
        className="w-full max-w-xl border p-10 text-center rounded"
        style={{ backgroundColor: 'var(--v-surface)', borderColor: 'var(--v-border)' }}
      >
        <img
          src="/vigolium-logo-minimal.png"
          alt="Vigolium"
          className="w-24 h-24 mx-auto mb-5 auth-logo-glow"
        />

        <h1 className="text-xl font-bold mb-3">Vigolium Cloud Console</h1>

        <p className="text-sm leading-relaxed mb-6" style={{ color: 'var(--v-text-muted)' }}>
          High-fidelity vulnerability scanner fusing agentic AI with native speed, modularity, and precision.
        </p>

        <div className="max-w-sm mx-auto border mb-6" style={{ borderColor: 'var(--v-border)' }}>
        {/* Tabs */}
        <div className="flex">
          <button
            onClick={() => { setActiveTab('sso'); setAccessError(''); }}
            className="flex-1 px-4 py-3 text-[10px] font-bold tracking-widest transition-all duration-200 border-b-2"
            style={{
              color: activeTab === 'sso' ? 'var(--v-accent)' : 'var(--v-text-muted)',
              borderBottomColor: activeTab === 'sso' ? 'var(--v-accent)' : 'var(--v-border)',
              backgroundColor: activeTab === 'sso' ? 'color-mix(in srgb, var(--v-accent) 8%, transparent)' : 'transparent',
            }}
          >
            <span className="inline-flex items-center gap-1.5"><ShieldCheck className="w-3.5 h-3.5" /> SSO</span>
          </button>
          <button
            onClick={() => { setActiveTab('access-code'); setAccessError(''); }}
            className="flex-1 px-4 py-3 text-[10px] font-bold tracking-widest transition-all duration-200 border-b-2"
            style={{
              color: activeTab === 'access-code' ? 'var(--v-accent)' : 'var(--v-text-muted)',
              borderBottomColor: activeTab === 'access-code' ? 'var(--v-accent)' : 'var(--v-border)',
              backgroundColor: activeTab === 'access-code' ? 'color-mix(in srgb, var(--v-accent) 8%, transparent)' : 'transparent',
            }}
          >
            <span className="inline-flex items-center gap-1.5"><Lock className="w-3.5 h-3.5" /> Access Code</span>
          </button>
        </div>

        {/* Tab Content */}
        <div className="p-5 flex flex-col justify-center" style={{ minHeight: '240px' }}>
          {activeTab === 'sso' ? (
            ssoDisabled ? (
              <div className="flex flex-col items-center gap-3 py-4 text-center">
                <ShieldOff className="w-6 h-6" style={{ color: 'var(--v-text-muted)' }} />
                <p className="text-xs leading-relaxed" style={{ color: 'var(--v-text-muted)' }}>
                  SSO login has been disabled on this instance.<br />
                  Only authorized access via <button type="button" onClick={() => setActiveTab('access-code')} className="hover:underline" style={{ color: 'var(--v-accent)' }}>access code</button> can be used.
                </p>
              </div>
            ) : (
              <>
                <p className="text-xs mb-4 text-center" style={{ color: 'var(--v-text-muted)' }}>Select a provider to continue</p>
                <div className="space-y-2">
                  <a
                    href={signInUrl}
                    className="flex items-center gap-3 w-full px-4 py-2.5 border text-xs font-medium transition-all duration-200 auth-btn-glow"
                    style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-bg)', color: 'var(--v-text-muted)' }}
                  >
                    <Mail className="w-4 h-4 flex-shrink-0" style={{ color: 'var(--v-accent)' }} />
                    <span>Sign in with Email</span>
                  </a>
                  <a
                    href={signInUrl}
                    className="flex items-center gap-3 w-full px-4 py-2.5 border text-xs font-medium transition-all duration-200 auth-btn-glow-muted"
                    style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-bg)', color: 'var(--v-text-muted)' }}
                  >
                    <GoogleIcon className="w-4 h-4 flex-shrink-0" style={{ color: '#f4a742' }} />
                    <span>Sign in with Google</span>
                  </a>
                  <a
                    href={signInUrl}
                    className="flex items-center gap-3 w-full px-4 py-2.5 border text-xs font-medium transition-all duration-200 auth-btn-glow-muted"
                    style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-bg)', color: 'var(--v-text-muted)' }}
                  >
                    <Github className="w-4 h-4 flex-shrink-0" style={{ color: '#24292e' }} />
                    <span>Sign in with GitHub</span>
                  </a>
                </div>
                <p className="text-xs mt-4 text-center" style={{ color: 'var(--v-text-muted)' }}>
                  Only authorized email domains can access this console.
                </p>
              </>
            )
          ) : (
            <form onSubmit={handleAccessCodeSubmit}>
              <p className="text-xs mb-4 text-center" style={{ color: 'var(--v-text-muted)' }}>Enter your access code and email</p>
              <div className="space-y-2">
                <div className="relative">
                  <KeyRound className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--v-text-muted)' }} />
                  <input
                    type={showAccessCode ? 'text' : 'password'}
                    value={accessCode}
                    onChange={(e) => setAccessCode(e.target.value)}
                    placeholder="Access code"
                    autoComplete="off"
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
                <div className="relative">
                  <Mail className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--v-text-muted)' }} />
                  <input
                    type="email"
                    value={accessEmail}
                    onChange={(e) => setAccessEmail(e.target.value)}
                    placeholder="you@company.com"
                    autoComplete="email"
                    className="w-full border text-xs pl-8 pr-3 py-2.5 focus:outline-none bg-transparent"
                    style={{ borderColor: 'var(--v-border)', color: 'var(--v-text)' }}
                  />
                </div>
                <button
                  type="submit"
                  disabled={accessLoading}
                  className="w-full px-4 py-2.5 border text-xs font-semibold transition-opacity disabled:opacity-50 auth-btn-glow-muted"
                  style={{ backgroundColor: 'var(--v-text)', color: 'var(--v-bg)', borderColor: 'var(--v-border)' }}
                >
                  <span className="inline-flex items-center gap-1.5">{accessLoading ? '...' : <><LogIn className="w-3 h-3" /> Sign In</>}</span>
                </button>
              </div>
              {accessError && (
                <p className="text-[10px] mt-2" style={{ color: 'var(--v-error)' }}>{accessError}</p>
              )}
            </form>
          )}
        </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-center gap-4 text-xs mt-6" style={{ color: 'var(--v-text-muted)' }}>
          <a href="https://vigolium.com" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--v-accent)' }} className="hover:underline">[website]</a>
          <span>·</span>
          <a href="https://docs.vigolium.com" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--v-accent)' }} className="hover:underline">[docs]</a>
          {showcasesEnabled ? (
            <>
              <span>·</span>
              <a href="/showcases" onClick={() => trackEvent('showcases_link_clicked', { location: 'authgate_light' })} style={{ color: 'var(--v-accent)' }} className="hover:underline">[audit showcases]</a>
            </>
          ) : (
            <>
              <span>·</span>
              <a href="mailto:contact@vigolium.com" style={{ color: 'var(--v-accent)' }} className="hover:underline">[contact us]</a>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
