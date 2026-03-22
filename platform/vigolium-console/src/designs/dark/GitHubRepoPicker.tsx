'use client';

import { useState, useRef, useEffect } from 'react';
import { Github, Lock, Globe, Search, Unplug, Loader2 } from 'lucide-react';
import { useGitHubStatus, useGitHubRepos, useGitHubCloneUrl } from '@/api/hooks';

interface GitHubRepoPickerProps {
  onSelect: (cloneUrl: string, repoFullName: string) => void;
  selectedRepo?: string;
}

export default function GitHubRepoPicker({ onSelect, selectedRepo }: GitHubRepoPickerProps) {
  const { data: status } = useGitHubStatus();
  const { data: reposData, isLoading: reposLoading } = useGitHubRepos(status?.connected === true);
  const cloneUrl = useGitHubCloneUrl();
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const [generating, setGenerating] = useState<string | null>(null);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  const handleSelect = async (repoFullName: string) => {
    setGenerating(repoFullName);
    try {
      const res = await cloneUrl.mutateAsync({ repo: repoFullName });
      onSelect(res.clone_url, repoFullName);
      setOpen(false);
    } catch {
      // error handled by mutation
    } finally {
      setGenerating(null);
    }
  };

  if (!status?.connected) {
    return (
      <a
        href="/api/github/install"
        className="inline-flex items-center gap-1.5 px-2 py-1 text-xs border rounded transition-colors"
        style={{ borderColor: 'var(--v-border)', color: 'var(--v-text-muted)' }}
      >
        <Github className="w-3 h-3" />
        Connect GitHub
      </a>
    );
  }

  const repos = reposData?.repos ?? [];
  const filtered = repos.filter((r) =>
    !search || r.full_name.toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(!open)}
        className="inline-flex items-center gap-1.5 px-2 py-1 text-xs border rounded transition-colors w-full"
        style={{ borderColor: 'var(--v-border)', color: selectedRepo ? 'var(--v-text)' : 'var(--v-text-muted)' }}
      >
        <Github className="w-3 h-3 shrink-0" />
        <span className="truncate flex-1 text-left">{selectedRepo || 'Select GitHub repo...'}</span>
        <span style={{ color: 'var(--v-border)' }}>&#x25BE;</span>
      </button>

      {open && (
        <div
          className="absolute z-50 mt-1 w-full max-h-64 overflow-auto border rounded shadow-lg"
          style={{ backgroundColor: 'var(--v-surface)', borderColor: 'var(--v-border)' }}
        >
          <div className="sticky top-0 p-1.5" style={{ backgroundColor: 'var(--v-surface)' }}>
            <div className="flex items-center gap-1 px-1.5 border rounded" style={{ borderColor: 'var(--v-border)' }}>
              <Search className="w-3 h-3 shrink-0" style={{ color: 'var(--v-text-muted)' }} />
              <input
                autoFocus
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search repos..."
                className="w-full py-1 text-xs bg-transparent outline-none"
                style={{ color: 'var(--v-text)' }}
              />
            </div>
          </div>

          {reposLoading && (
            <div className="flex items-center gap-2 px-3 py-3 text-xs" style={{ color: 'var(--v-text-muted)' }}>
              <Loader2 className="w-3 h-3 animate-spin" /> Loading repos...
            </div>
          )}

          {!reposLoading && filtered.length === 0 && (
            <div className="px-3 py-3 text-xs" style={{ color: 'var(--v-text-muted)' }}>
              {search ? 'No repos match' : 'No repos found'}
            </div>
          )}

          {filtered.map((repo) => (
            <button
              key={repo.full_name}
              onClick={() => handleSelect(repo.full_name)}
              disabled={generating !== null}
              className="w-full text-left px-3 py-1.5 text-xs flex items-center gap-2 transition-colors"
              style={{
                color: repo.full_name === selectedRepo ? 'var(--v-accent)' : 'var(--v-text)',
              }}
            >
              {repo.private
                ? <Lock className="w-3 h-3 shrink-0" style={{ color: 'var(--v-text-muted)' }} />
                : <Globe className="w-3 h-3 shrink-0" style={{ color: 'var(--v-text-muted)' }} />
              }
              <span className="truncate flex-1">{repo.full_name}</span>
              {generating === repo.full_name && (
                <Loader2 className="w-3 h-3 animate-spin shrink-0" style={{ color: 'var(--v-accent)' }} />
              )}
            </button>
          ))}

          <div className="border-t px-3 py-1.5" style={{ borderColor: 'var(--v-border)' }}>
            <span className="text-[10px]" style={{ color: 'var(--v-text-muted)' }}>
              {repos.length} repos
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
