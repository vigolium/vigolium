'use client';

import { useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { Calendar, Mail, Lock, Loader2, Activity } from 'lucide-react';
import { trackEvent } from '@/lib/posthogClient';

interface DemoUnlockPageProps {
  showcasesEnabled?: boolean;
  skipAuth?: boolean;
}

type Phase = 'idle' | 'submitting' | 'success';

const MIN_SPIN_MS = 700;
const SUCCESS_HOLD_MS = 350;

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export default function DemoUnlockPage({ showcasesEnabled = false, skipAuth = false }: DemoUnlockPageProps) {
  const searchParams = useSearchParams();
  const router = useRouter();
  const returnTo = searchParams.get('return_to') || '/';

  const [phase, setPhase] = useState<Phase>('idle');
  const [errorCode, setErrorCode] = useState<string | null>(searchParams.get('demo_error'));

  const errorMessage =
    errorCode === 'expired'
      ? 'That demo_key has expired.'
      : errorCode === 'invalid'
        ? "That demo_key didn't match (or wasn't there at all)."
        : errorCode === 'network'
          ? 'Could not reach the server — please try again.'
          : null;

  const busy = phase !== 'idle';

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const demoKey = String(formData.get('demo_key') || '').trim();
    const rt = String(formData.get('return_to') || '/');
    if (!demoKey) return;

    setErrorCode(null);
    setPhase('submitting');
    const startedAt = Date.now();
    try {
      const url = new URL('/api/demo/login', window.location.origin);
      url.searchParams.set('demo_key', demoKey);
      url.searchParams.set('return_to', rt);
      const res = await fetch(url.toString(), { credentials: 'same-origin' });
      // Ensure the spinner is visible for a minimum time so it doesn't blink on fast responses
      const elapsed = Date.now() - startedAt;
      if (elapsed < MIN_SPIN_MS) await delay(MIN_SPIN_MS - elapsed);

      // fetch auto-follows redirects — response.url is the final landing URL
      const finalUrl = new URL(res.url);
      const err = finalUrl.searchParams.get('demo_error');
      if (finalUrl.pathname === '/login' && err) {
        setErrorCode(err);
        setPhase('idle');
        return;
      }

      // Show a brief "unlocked" hold so the transition into the app feels deliberate
      setPhase('success');
      await delay(SUCCESS_HOLD_MS);
      router.replace(finalUrl.pathname + finalUrl.search);
    } catch {
      const elapsed = Date.now() - startedAt;
      if (elapsed < MIN_SPIN_MS) await delay(MIN_SPIN_MS - elapsed);
      setErrorCode('network');
      setPhase('idle');
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
        @keyframes demo-logo-glow {
          0%, 100% { box-shadow: 0 0 12px color-mix(in srgb, var(--v-accent) 25%, transparent); }
          50% { box-shadow: 0 0 28px color-mix(in srgb, var(--v-accent) 55%, transparent), 0 0 48px color-mix(in srgb, var(--v-accent) 20%, transparent); }
        }
        .demo-logo-glow { animation: demo-logo-glow 3s ease-in-out infinite; }
        @keyframes demo-fade-in {
          from { opacity: 0; transform: translateY(-4px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .demo-fade-in { animation: demo-fade-in 220ms ease-out both; }
        .demo-btn-glow { transition: box-shadow 0.2s ease; }
        .demo-btn-glow:hover { box-shadow: 0 0 14px color-mix(in srgb, var(--v-accent) 40%, transparent), 0 0 28px color-mix(in srgb, var(--v-accent) 15%, transparent); }
        .demo-btn-glow-muted { transition: box-shadow 0.2s ease; }
        .demo-btn-glow-muted:hover { box-shadow: 0 0 12px color-mix(in srgb, var(--v-text) 20%, transparent), 0 0 24px color-mix(in srgb, var(--v-text) 8%, transparent); }
      `}</style>

      <div
        className="w-full max-w-xl border p-10 text-center"
        style={{ backgroundColor: 'var(--v-surface)', borderColor: 'var(--v-border)' }}
      >
        <img
          src="/vigolium-logo-minimal.png"
          alt="Vigolium"
          className="w-24 h-24 mx-auto mb-5 rounded-lg border demo-logo-glow"
          style={{ borderColor: 'color-mix(in srgb, var(--v-accent) 40%, transparent)' }}
        />

        <div
          className="inline-block text-[11px] tracking-widest uppercase px-3 py-1 mb-4 border"
          style={{ color: 'var(--v-accent)', borderColor: 'var(--v-accent)' }}
        >
          {skipAuth ? 'Demo · Open Access' : 'Demo · Locked'}
        </div>

        <h1 className="text-xl font-bold mb-3">This console is in demo mode</h1>

        <p className="text-sm leading-relaxed mb-6" style={{ color: 'var(--v-text-muted)' }}>
          {skipAuth
            ? 'Browse the console in read-only mode with limited pre-loaded scan data. Book a demo to see how we scan your application.'
            : <>Paste a <code style={{ color: 'var(--v-accent)' }}>demo_key</code> for a read-only preview — or book a walkthrough below.</>}
        </p>

        {!skipAuth && errorMessage && (
          <div
            key={errorCode}
            className="text-xs px-3 py-2 mb-5 border demo-fade-in"
            style={{ color: 'var(--v-error)', borderColor: 'var(--v-error)', backgroundColor: 'color-mix(in srgb, var(--v-error) 8%, transparent)' }}
          >
            {errorMessage}
          </div>
        )}

        <div className="flex gap-3 justify-center flex-wrap mb-6">
          <a
            href="https://www.vigolium.com/request-demo"
            target="_blank"
            rel="noopener noreferrer"
            onClick={() => trackEvent('request_demo_clicked', { source: 'demo_unlock' })}
            className="inline-flex items-center gap-2 text-xs px-4 py-2 border font-semibold transition-colors demo-btn-glow"
            style={{
              backgroundColor: 'var(--v-accent)',
              borderColor: 'var(--v-accent)',
              color: 'var(--v-bg)',
            }}
          >
            <Calendar className="w-3.5 h-3.5" />
            Request a Demo
          </a>
          <a
            href="mailto:contact@vigolium.com"
            className="inline-flex items-center gap-2 text-xs px-4 py-2 border transition-colors demo-btn-glow-muted"
            style={{ borderColor: 'var(--v-text-muted)', color: 'var(--v-text)', backgroundColor: 'color-mix(in srgb, var(--v-text) 8%, transparent)' }}
          >
            <Mail className="w-3.5 h-3.5" />
            Contact Us
          </a>
        </div>

        {skipAuth ? (
          <button
            disabled={busy}
            onClick={async () => {
              setPhase('submitting');
              document.cookie = 'vigolium-demo-entered=1; path=/; max-age=86400; samesite=lax';
              trackEvent('demo_enter_clicked', { source: 'demo_unlock' });
              await delay(MIN_SPIN_MS);
              setPhase('success');
              await delay(SUCCESS_HOLD_MS);
              router.replace(returnTo);
            }}
            className="flex items-center justify-center gap-2 text-xs px-4 py-2.5 border font-semibold transition-opacity disabled:opacity-85 disabled:cursor-wait mx-auto demo-btn-glow-muted"
            style={{ width: '70%', maxWidth: '28rem', backgroundColor: 'var(--v-text)', color: 'var(--v-bg)', borderColor: 'var(--v-border)' }}
          >
            {phase === 'submitting' ? (
              <>
                <Loader2 className="w-3 h-3 animate-spin" />
                Loading…
              </>
            ) : phase === 'success' ? (
              <>
                <Loader2 className="w-3 h-3 animate-spin" />
                Entering console…
              </>
            ) : (
              <>
                <Activity className="w-3 h-3" />
                Enter Console
              </>
            )}
          </button>
        ) : (
          <>
            <form
              onSubmit={handleSubmit}
              className="flex items-stretch border max-w-md mx-auto"
              style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-bg)' }}
            >
              <input type="hidden" name="return_to" value={returnTo} />
              <input
                type="text"
                name="demo_key"
                placeholder="Paste your demo_key"
                autoComplete="off"
                spellCheck={false}
                required
                disabled={busy}
                className="flex-1 min-w-0 text-xs px-3 py-2.5 focus:outline-none bg-transparent disabled:opacity-60"
                style={{ color: 'var(--v-text)' }}
              />
              <button
                type="submit"
                disabled={busy}
                className="inline-flex items-center gap-2 text-xs px-4 py-2.5 font-semibold transition-opacity disabled:opacity-85 disabled:cursor-wait demo-btn-glow-muted"
                style={{ backgroundColor: 'var(--v-text)', color: 'var(--v-bg)' }}
              >
                {phase === 'submitting' ? (
                  <>
                    <Loader2 className="w-3 h-3 animate-spin" />
                    Unlocking…
                  </>
                ) : phase === 'success' ? (
                  <>
                    <Loader2 className="w-3 h-3 animate-spin" />
                    Loading console…
                  </>
                ) : (
                  <>
                    <Lock className="w-3 h-3" />
                    Unlock
                  </>
                )}
              </button>
            </form>

            <p className="text-[11px] mt-4" style={{ color: 'var(--v-text-muted)' }}>
              Or append <code style={{ color: 'var(--v-accent)' }}>?demo_key=YOUR_KEY</code> to the URL
            </p>
          </>
        )}

        <div className="flex items-center justify-center gap-4 text-xs mt-6" style={{ color: 'var(--v-text-muted)' }}>
          <a href="https://vigolium.com" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--v-accent)' }} className="hover:underline">[website]</a>
          <span>·</span>
          <a href="https://docs.vigolium.com" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--v-accent)' }} className="hover:underline">[docs]</a>
          {showcasesEnabled && (
            <>
              <span>·</span>
              <a
                href="/showcases"
                onClick={() => trackEvent('showcases_link_clicked', { location: 'demo_unlock' })}
                style={{ color: 'var(--v-accent)' }}
                className="hover:underline"
              >
                [audit showcases]
              </a>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
