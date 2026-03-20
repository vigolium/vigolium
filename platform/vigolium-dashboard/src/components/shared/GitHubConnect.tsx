'use client';

import React, { useCallback } from 'react';
import { Github } from 'lucide-react';
import { useQueryClient } from '@tanstack/react-query';
import { useGitHubStatus, useGitHubDisconnect } from '@/api/hooks';
import { getGitHubAuthURL } from '@/api/client';

interface GitHubConnectProps {
  onBrowseRepos?: () => void;
  compact?: boolean;
}

export default function GitHubConnect({ onBrowseRepos, compact }: GitHubConnectProps) {
  const { data: status, isLoading } = useGitHubStatus();
  const disconnect = useGitHubDisconnect();
  const queryClient = useQueryClient();

  const handleConnect = useCallback(async () => {
    try {
      const { url } = await getGitHubAuthURL();
      // Open GitHub OAuth in a popup
      const width = 600;
      const height = 700;
      const left = window.screenX + (window.outerWidth - width) / 2;
      const top = window.screenY + (window.outerHeight - height) / 2;
      const popup = window.open(
        url,
        'github-oauth',
        `width=${width},height=${height},left=${left},top=${top},toolbar=no,menubar=no`
      );

      // Poll for popup close and refetch status
      if (popup) {
        const interval = setInterval(() => {
          if (popup.closed) {
            clearInterval(interval);
            // Refetch status after popup closes (user completed OAuth)
            window.dispatchEvent(new Event('github-oauth-complete'));
          }
        }, 500);
      }
    } catch (err) {
      console.error('Failed to get GitHub auth URL:', err);
    }
  }, []);

  // Listen for OAuth completion (dispatched by the popup callback page)
  React.useEffect(() => {
    const handler = () => {
      queryClient.invalidateQueries({ queryKey: ['github-status'] });
    };
    window.addEventListener('github-oauth-complete', handler);
    return () => window.removeEventListener('github-oauth-complete', handler);
  }, [queryClient]);

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--v-muted)' }}>
        <Github size={16} /> Checking GitHub...
      </div>
    );
  }

  if (!status?.configured) {
    return (
      <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--v-muted)' }}>
        <Github size={16} />
        <span>GitHub not configured</span>
      </div>
    );
  }

  if (status.connected) {
    if (compact) {
      return (
        <div className="flex items-center gap-2">
          <button
            onClick={onBrowseRepos}
            className="px-2 py-1 text-xs font-mono border rounded transition-colors"
            style={{
              borderColor: 'var(--v-border)',
              color: 'var(--v-accent)',
              background: 'transparent',
            }}
            onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--v-hover)')}
            onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
          >
            <Github size={12} className="inline mr-1" />
            Browse
          </button>
        </div>
      );
    }

    return (
      <div className="flex items-center gap-3 text-sm">
        <Github size={16} style={{ color: 'var(--v-accent)' }} />
        <span>Connected as <strong style={{ color: 'var(--v-accent)' }}>@{status.github_login}</strong></span>
        {onBrowseRepos && (
          <button
            onClick={onBrowseRepos}
            className="px-2 py-1 text-xs font-mono border rounded transition-colors"
            style={{
              borderColor: 'var(--v-border)',
              color: 'var(--v-text)',
              background: 'transparent',
            }}
            onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--v-hover)')}
            onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
          >
            Browse Repos
          </button>
        )}
        <button
          onClick={() => disconnect.mutate()}
          disabled={disconnect.isPending}
          className="px-2 py-1 text-xs font-mono border rounded transition-colors"
          style={{
            borderColor: 'var(--v-border)',
            color: 'var(--v-muted)',
            background: 'transparent',
          }}
          onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--v-hover)')}
          onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
        >
          {disconnect.isPending ? 'Disconnecting...' : 'Disconnect'}
        </button>
      </div>
    );
  }

  // Not connected
  return (
    <div className="flex items-center gap-3 text-sm">
      <Github size={16} style={{ color: 'var(--v-muted)' }} />
      <button
        onClick={handleConnect}
        className="px-3 py-1.5 text-xs font-mono border rounded transition-colors"
        style={{
          borderColor: 'var(--v-border)',
          color: 'var(--v-text)',
          background: 'transparent',
        }}
        onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--v-hover)')}
        onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
      >
        Connect GitHub
      </button>
    </div>
  );
}
