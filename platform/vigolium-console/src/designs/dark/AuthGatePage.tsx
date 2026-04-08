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
      setAccessError('access code is required');
      return;
    }
    if (!email) {
      setAccessError('email is required');
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
        setAccessError(data.error || 'invalid access code or email');
        return;
      }
      // Cookie set — redirect
      window.location.href = returnTo;
    } catch {
      setAccessError('could not reach server');
    } finally {
      setAccessLoading(false);
    }
  };

  return (
    <Layout>
      <style>{`
        @keyframes logo-glow {
          0%, 100% { box-shadow: 0 0 12px color-mix(in srgb, var(--v-accent) 25%, transparent); }
          50% { box-shadow: 0 0 28px color-mix(in srgb, var(--v-accent) 55%, transparent), 0 0 48px color-mix(in srgb, var(--v-accent) 20%, transparent); }
        }
        .animate-logo-glow { animation: logo-glow 3s ease-in-out infinite; }
      `}</style>
      <div className="min-h-screen flex flex-col items-center justify-center px-4 bg-[var(--v-bg)]">
        <div className="w-full max-w-md">
          {/* Logo & Title */}
          <div className="text-center mb-10">
            <img
              src="/vigolium-logo-minimal.png"
              alt="Vigolium"
              className="w-28 h-28 mx-auto mb-6 rounded-lg border border-[var(--v-accent)]/50 animate-logo-glow"
            />
            <h1 className="text-xl font-bold tracking-widest text-[var(--v-accent)]">
              Vigolium Cloud Console
            </h1>
            <p className="text-sm mt-3 leading-relaxed max-w-sm mx-auto text-[var(--v-text-muted)]">
              High-fidelity vulnerability scanner fusing agentic AI with native speed, modularity, and precision
            </p>
          </div>

          {/* Auth Card */}
          <div className="border border-[var(--v-border)] bg-[var(--v-bg)]">
            {/* Tabs */}
            <div className="flex border-b border-[var(--v-border)]">
              <button
                onClick={() => { setActiveTab('sso'); setAccessError(''); }}
                className={`flex-1 px-4 py-3 text-[10px] font-bold tracking-wider transition-all duration-150 ${
                  activeTab === 'sso'
                    ? 'text-[var(--v-accent)] border-b-2 border-[var(--v-accent)] bg-[var(--v-accent)]/5'
                    : 'text-[var(--v-text-muted)] hover:text-[var(--v-text)] hover:bg-[var(--v-surface)]'
                }`}
              >
                SSO
              </button>
              <button
                onClick={() => { setActiveTab('access-code'); setAccessError(''); }}
                className={`flex-1 px-4 py-3 text-[10px] font-bold tracking-wider transition-all duration-150 ${
                  activeTab === 'access-code'
                    ? 'text-[var(--v-accent)] border-b-2 border-[var(--v-accent)] bg-[var(--v-accent)]/5'
                    : 'text-[var(--v-text-muted)] hover:text-[var(--v-text)] hover:bg-[var(--v-surface)]'
                }`}
              >
                ACCESS CODE
              </button>
            </div>

            <div className="p-5">
              {activeTab === 'sso' ? (
                ssoDisabled ? (
                  <div className="flex flex-col items-center gap-3 py-4 text-center">
                    <ShieldOff className="w-6 h-6 text-[var(--v-text-muted)]" />
                    <p className="text-[var(--v-text-muted)] text-xs leading-relaxed">
                      SSO login has been disabled by the administrator.<br />
                      Use the <button type="button" onClick={() => setActiveTab('access-code')} className="text-[var(--v-accent)] hover:underline">access code</button> tab to sign in.
                    </p>
                  </div>
                ) : (
                  <>
                    <p className="text-[var(--v-text-muted)] text-xs mb-4">select a provider to continue</p>
                    <div className="flex gap-2">
                      <a
                        href={signInUrl}
                        className="flex-1 flex flex-col items-center gap-2 px-3 py-3 border border-[var(--v-border)] bg-[var(--v-surface)] text-[10px] text-[var(--v-text-muted)] transition-all duration-150 hover:border-[var(--v-accent)]/50 hover:bg-[var(--v-accent)]/5 hover:text-[var(--v-text)]"
                      >
                        <Mail className="w-4 h-4 text-[var(--v-accent)]" />
                        <span>Email</span>
                      </a>

                      <a
                        href={signInUrl}
                        className="flex-1 flex flex-col items-center gap-2 px-3 py-3 border border-[var(--v-border)] bg-[var(--v-surface)] text-[10px] text-[var(--v-text-muted)] transition-all duration-150 hover:border-[var(--v-secondary)]/50 hover:bg-[var(--v-secondary)]/5 hover:text-[var(--v-text)]"
                      >
                        <GoogleIcon className="w-4 h-4 text-[var(--v-secondary)]" />
                        <span>Google</span>
                      </a>

                      <a
                        href={signInUrl}
                        className="flex-1 flex flex-col items-center gap-2 px-3 py-3 border border-[var(--v-border)] bg-[var(--v-surface)] text-[10px] text-[var(--v-text-muted)] transition-all duration-150 hover:border-[var(--v-tertiary)]/50 hover:bg-[var(--v-tertiary)]/5 hover:text-[var(--v-text)]"
                      >
                        <Github className="w-4 h-4 text-[var(--v-tertiary)]" />
                        <span>GitHub</span>
                      </a>
                    </div>
                  </>
                )
              ) : (
                <form onSubmit={handleAccessCodeSubmit}>
                  <p className="text-[var(--v-text-muted)] text-xs mb-4">enter your access code and email</p>
                  <div className="space-y-2">
                    <div className="relative">
                      <KeyRound className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--v-text-muted)]" />
                      <input
                        type={showAccessCode ? 'text' : 'password'}
                        value={accessCode}
                        onChange={(e) => setAccessCode(e.target.value)}
                        placeholder="access code"
                        autoComplete="off"
                        className="w-full bg-[var(--v-surface)] border border-[var(--v-border)] text-[var(--v-text)] text-xs pl-8 pr-14 py-2.5 focus:outline-none focus:border-[var(--v-accent)]/50 placeholder-[var(--v-text-muted)]/60"
                      />
                      <button
                        type="button"
                        onClick={() => setShowAccessCode(!showAccessCode)}
                        className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] text-[var(--v-text-muted)] hover:text-[var(--v-text)]"
                      >
                        [{showAccessCode ? 'hide' : 'show'}]
                      </button>
                    </div>
                    <div className="relative">
                      <Mail className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--v-text-muted)]" />
                      <input
                        type="email"
                        value={accessEmail}
                        onChange={(e) => setAccessEmail(e.target.value)}
                        placeholder="you@company.com"
                        autoComplete="email"
                        className="w-full bg-[var(--v-surface)] border border-[var(--v-border)] text-[var(--v-text)] text-xs pl-8 pr-3 py-2.5 focus:outline-none focus:border-[var(--v-accent)]/50 placeholder-[var(--v-text-muted)]/60"
                      />
                    </div>
                    <button
                      type="submit"
                      disabled={accessLoading}
                      className="w-full px-4 py-2.5 border border-[var(--v-border)] bg-[var(--v-surface)] text-[10px] text-[var(--v-text-muted)] transition-all duration-150 hover:border-[var(--v-accent)]/50 hover:bg-[var(--v-accent)]/5 hover:text-[var(--v-text)] disabled:opacity-50"
                    >
                      {accessLoading ? '...' : 'sign in'}
                    </button>
                  </div>
                  {accessError && (
                    <p className="text-[var(--v-error)] text-[10px] mt-2">{accessError}</p>
                  )}
                </form>
              )}
            </div>
          </div>

          {/* Footer */}
          <div className="text-center mt-6">
            <div className="flex items-center justify-center gap-3 text-xs text-[var(--v-text-muted)]">
              <a href="https://vigolium.com" target="_blank" rel="noopener noreferrer" className="text-[var(--v-accent)] hover:underline">[website]</a>
              <span>·</span>
              <a href="https://docs.vigolium.com" target="_blank" rel="noopener noreferrer" className="text-[var(--v-accent)] hover:underline">[docs]</a>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}
