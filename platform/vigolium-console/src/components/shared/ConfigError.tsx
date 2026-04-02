'use client';

import { AlertTriangle, Terminal, Copy, Check } from 'lucide-react';
import { useState } from 'react';

interface ConfigIssue {
  key: string;
  severity: 'error' | 'warning';
  message: string;
}

export default function ConfigError({ issues }: { issues: ConfigIssue[] }) {
  const [copied, setCopied] = useState(false);
  const errors = issues.filter((i) => i.severity === 'error');
  const warnings = issues.filter((i) => i.severity === 'warning');

  const envTemplate = issues
    .filter((i) => i.severity === 'error')
    .map((i) => `${i.key}=`)
    .join('\n');

  function copyEnv() {
    navigator.clipboard.writeText(envTemplate).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <div
      className="min-h-screen flex flex-col items-center justify-center px-4"
      style={{ backgroundColor: '#0a0a0a', color: '#e0e0e0' }}
    >
      <div className="w-full max-w-lg">
        {/* Header */}
        <div className="text-center mb-8">
          <div
            className="inline-flex items-center justify-center w-16 h-16 rounded-full mb-4"
            style={{ backgroundColor: 'rgba(234, 179, 8, 0.1)', border: '1px solid rgba(234, 179, 8, 0.3)' }}
          >
            <AlertTriangle className="w-8 h-8" style={{ color: '#eab308' }} />
          </div>
          <h1 className="text-lg font-bold tracking-wide" style={{ color: '#eab308' }}>
            Configuration Required
          </h1>
          <p className="text-xs mt-2" style={{ color: '#888' }}>
            Vigolium Cloud Console is missing required environment variables.
          </p>
        </div>

        {/* Errors */}
        {errors.length > 0 && (
          <div
            className="border p-4 mb-4"
            style={{ backgroundColor: 'rgba(239, 68, 68, 0.05)', borderColor: 'rgba(239, 68, 68, 0.3)' }}
          >
            <h2 className="text-xs font-semibold mb-3" style={{ color: '#ef4444' }}>
              Missing Required Secrets
            </h2>
            <div className="space-y-2">
              {errors.map((issue) => (
                <div key={issue.key} className="flex items-start gap-2 text-xs">
                  <span className="font-mono px-1.5 py-0.5 flex-shrink-0" style={{ backgroundColor: 'rgba(239, 68, 68, 0.1)', color: '#f87171' }}>
                    {issue.key}
                  </span>
                  <span style={{ color: '#aaa' }}>{issue.message}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Warnings */}
        {warnings.length > 0 && (
          <div
            className="border p-4 mb-4"
            style={{ backgroundColor: 'rgba(234, 179, 8, 0.03)', borderColor: 'rgba(234, 179, 8, 0.2)' }}
          >
            <h2 className="text-xs font-semibold mb-3" style={{ color: '#eab308' }}>
              Optional Configuration
            </h2>
            <div className="space-y-2">
              {warnings.map((issue) => (
                <div key={issue.key} className="flex items-start gap-2 text-xs">
                  <span className="font-mono px-1.5 py-0.5 flex-shrink-0" style={{ backgroundColor: 'rgba(234, 179, 8, 0.1)', color: '#facc15' }}>
                    {issue.key}
                  </span>
                  <span style={{ color: '#888' }}>{issue.message}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Fix instructions */}
        <div className="border p-4 mb-4" style={{ backgroundColor: 'rgba(255,255,255,0.02)', borderColor: '#333' }}>
          <h2 className="text-xs font-semibold mb-3" style={{ color: '#ccc' }}>
            How to Fix
          </h2>
          <ol className="text-xs space-y-2" style={{ color: '#999' }}>
            <li>
              <span className="font-mono" style={{ color: '#ccc' }}>1.</span> Copy{' '}
              <span className="font-mono px-1 py-0.5" style={{ backgroundColor: 'rgba(255,255,255,0.05)', color: '#ccc' }}>.env.example</span>{' '}
              to{' '}
              <span className="font-mono px-1 py-0.5" style={{ backgroundColor: 'rgba(255,255,255,0.05)', color: '#ccc' }}>.env</span>{' '}
              and fill in the values.
            </li>
            <li>
              <span className="font-mono" style={{ color: '#ccc' }}>2.</span> Restart the dev server.
            </li>
          </ol>

          {envTemplate && (
            <div className="mt-3 relative">
              <pre
                className="text-xs p-3 font-mono overflow-x-auto"
                style={{ backgroundColor: '#111', color: '#888', border: '1px solid #333' }}
              >
                {envTemplate}
              </pre>
              <button
                onClick={copyEnv}
                className="absolute top-2 right-2 p-1 transition-colors"
                style={{ color: copied ? '#22c55e' : '#666' }}
                title="Copy to clipboard"
              >
                {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          )}
        </div>

        {/* Alternatives */}
        <div className="border p-4" style={{ backgroundColor: 'rgba(59, 130, 246, 0.03)', borderColor: 'rgba(59, 130, 246, 0.2)' }}>
          <h2 className="text-xs font-semibold mb-3" style={{ color: '#60a5fa' }}>
            <Terminal className="w-3.5 h-3.5 inline-block mr-1.5 -mt-0.5" />
            Alternatives
          </h2>
          <div className="text-xs space-y-3" style={{ color: '#999' }}>
            <div>
              <p className="mb-1">Run without authentication (development):</p>
              <code
                className="block px-3 py-2 font-mono"
                style={{ backgroundColor: '#111', color: '#60a5fa', border: '1px solid rgba(59, 130, 246, 0.2)' }}
              >
                bun run dev:console:noauth
              </code>
            </div>
            <div>
              <p className="mb-1">Run the self-hosted workbench (no WorkOS/Stripe needed):</p>
              <code
                className="block px-3 py-2 font-mono"
                style={{ backgroundColor: '#111', color: '#60a5fa', border: '1px solid rgba(59, 130, 246, 0.2)' }}
              >
                bun run dev:workbench
              </code>
            </div>
          </div>
        </div>

        {/* Footer */}
        <p className="text-center text-xs mt-6" style={{ color: '#555' }}>
          See <span className="font-mono">.env.example</span> for all available configuration options.
        </p>
      </div>
    </div>
  );
}
