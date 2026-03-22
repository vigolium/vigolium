'use client';

import { useSearchParams } from 'next/navigation';
import { Mail, Github, Moon } from 'lucide-react';
import { useTheme } from '@/contexts/ThemeContext';
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

export default function AuthGatePage() {
  const searchParams = useSearchParams();
  const { toggleTheme } = useTheme();
  const returnTo = searchParams.get('return_to') || '/';
  const signInUrl = `/api/auth/signin?return_to=${encodeURIComponent(returnTo)}`;

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
              Vigolium Console
            </h1>
            <p className="text-xs mt-3 leading-relaxed max-w-xs mx-auto" style={{ color: 'var(--v-text-muted)' }}>
              High-fidelity vulnerability scanner fusing agentic AI with native speed, modularity, and precision
            </p>
          </div>

          {/* Auth Card */}
          <div
            className="border rounded p-6 space-y-3"
            style={{ backgroundColor: 'var(--v-surface)', borderColor: 'var(--v-border)' }}
          >
            <p className="text-xs text-center mb-4" style={{ color: 'var(--v-secondary)' }}>
              Sign in to continue
            </p>

            <a
              href={signInUrl}
              className="flex items-center gap-3 w-full px-4 py-2.5 border rounded text-xs transition-colors"
              style={{
                backgroundColor: 'var(--v-bg)',
                borderColor: 'var(--v-border)',
                color: 'var(--v-text)',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = 'var(--v-accent)';
                e.currentTarget.style.color = 'var(--v-accent)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'var(--v-border)';
                e.currentTarget.style.color = 'var(--v-text)';
              }}
            >
              <Mail className="w-4 h-4 flex-shrink-0" />
              <span>Sign in with Email</span>
            </a>

            <a
              href={signInUrl}
              className="flex items-center gap-3 w-full px-4 py-2.5 border rounded text-xs transition-colors"
              style={{
                backgroundColor: 'var(--v-bg)',
                borderColor: 'var(--v-border)',
                color: 'var(--v-text)',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = 'var(--v-accent)';
                e.currentTarget.style.color = 'var(--v-accent)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'var(--v-border)';
                e.currentTarget.style.color = 'var(--v-text)';
              }}
            >
              <GoogleIcon className="w-4 h-4 flex-shrink-0" />
              <span>Sign in with Google</span>
            </a>

            <a
              href={signInUrl}
              className="flex items-center gap-3 w-full px-4 py-2.5 border rounded text-xs transition-colors"
              style={{
                backgroundColor: 'var(--v-bg)',
                borderColor: 'var(--v-border)',
                color: 'var(--v-text)',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = 'var(--v-accent)';
                e.currentTarget.style.color = 'var(--v-accent)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'var(--v-border)';
                e.currentTarget.style.color = 'var(--v-text)';
              }}
            >
              <Github className="w-4 h-4 flex-shrink-0" />
              <span>Sign in with GitHub</span>
            </a>
          </div>

          {/* Footer */}
          <div className="text-center mt-6 flex items-center justify-center gap-4">
            <span className="text-xs" style={{ color: 'var(--v-text-muted)' }}>
              Powered by WorkOS
            </span>
            <button
              onClick={toggleTheme}
              className="text-xs transition-colors"
              style={{ color: 'var(--v-text-muted)' }}
              title="Toggle theme"
            >
              <Moon className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </Layout>
  );
}
