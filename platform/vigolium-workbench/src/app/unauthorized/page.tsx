'use client';

import { useTheme } from '@/contexts/ThemeContext';

export default function UnauthorizedPage() {
  const { themeId } = useTheme();
  const isDark = themeId === 'dark';

  return (
    <div
      className="min-h-screen flex flex-col items-center justify-center px-4 font-mono"
      style={{ backgroundColor: isDark ? '#151413' : '#fafaf8' }}
    >
      <img
        src="/vigolium-logo-minimal.png"
        alt="Vigolium"
        className="w-20 h-20 mb-6 opacity-60"
      />
      <h1
        className="text-lg font-bold mb-3"
        style={{ color: isDark ? '#e06c75' : '#dc3545' }}
      >
        Access Denied
      </h1>
      <p
        className="text-sm text-center max-w-md mb-6 leading-relaxed"
        style={{ color: isDark ? '#918175' : '#6c757d' }}
      >
        Your account is not associated with any organization.
        Please contact your administrator for an invitation.
      </p>
      <div className="flex gap-4">
        <a
          href="/api/auth/logout"
          className="px-4 py-2 text-xs border rounded transition-colors"
          style={{
            borderColor: isDark ? '#2e2b26' : '#dee2e6',
            color: isDark ? '#918175' : '#6c757d',
          }}
        >
          Sign out
        </a>
        <button
          onClick={() => window.location.href = '/'}
          className="px-4 py-2 text-xs border rounded transition-colors"
          style={{
            borderColor: isDark ? '#7fd962' : '#2e8b57',
            color: isDark ? '#7fd962' : '#2e8b57',
          }}
        >
          Try again
        </button>
      </div>
    </div>
  );
}
