'use client';

import React, { useState, useCallback } from 'react';
import { X, Search, GitBranch, Lock, Globe, Loader2 } from 'lucide-react';
import { useGitHubRepos, useGitHubBranches, useGitHubClone } from '@/api/hooks';
import type { GitHubRepo } from '@/api/types';

interface RepoBrowserModalProps {
  open: boolean;
  onClose: () => void;
  onSelect: (path: string) => void;
}

export default function RepoBrowserModal({ open, onClose, onSelect }: RepoBrowserModalProps) {
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [selectedRepo, setSelectedRepo] = useState<GitHubRepo | null>(null);
  const [selectedBranch, setSelectedBranch] = useState('');
  const [page, setPage] = useState(1);

  // Debounce search
  const debounceRef = React.useRef<ReturnType<typeof setTimeout>>(undefined);
  const handleSearchChange = useCallback((val: string) => {
    setSearch(val);
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      setDebouncedSearch(val);
      setPage(1);
    }, 300);
  }, []);

  const { data: repos, isLoading: reposLoading } = useGitHubRepos(
    { page, per_page: 30, q: debouncedSearch || undefined },
    open
  );

  const { data: branches, isLoading: branchesLoading } = useGitHubBranches(
    selectedRepo?.owner ?? '',
    selectedRepo?.name ?? '',
    !!selectedRepo
  );

  // Set default branch when branches load
  React.useEffect(() => {
    if (branches && branches.length > 0 && selectedRepo && !selectedBranch) {
      const defaultBr = branches.find(b => b.name === selectedRepo.default_branch);
      setSelectedBranch(defaultBr?.name ?? branches[0].name);
    }
  }, [branches, selectedRepo, selectedBranch]);

  const cloneMut = useGitHubClone();

  const handleClone = useCallback(async () => {
    if (!selectedRepo) return;
    try {
      const result = await cloneMut.mutateAsync({
        clone_url: selectedRepo.clone_url,
        branch: selectedBranch || selectedRepo.default_branch,
      });
      onSelect(result.path);
      onClose();
    } catch (err) {
      console.error('Clone failed:', err);
    }
  }, [selectedRepo, selectedBranch, cloneMut, onSelect, onClose]);

  const handleSelectRepo = useCallback((repo: GitHubRepo) => {
    setSelectedRepo(repo);
    setSelectedBranch('');
  }, []);

  const formatDate = useCallback((dateStr: string) => {
    const d = new Date(dateStr);
    const now = new Date();
    const diff = now.getTime() - d.getTime();
    const hours = Math.floor(diff / (1000 * 60 * 60));
    if (hours < 1) return 'just now';
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    if (days < 30) return `${days}d ago`;
    return d.toLocaleDateString();
  }, []);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: 'rgba(0,0,0,0.6)' }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        className="w-full max-w-2xl max-h-[80vh] flex flex-col rounded border"
        style={{
          background: 'var(--v-bg)',
          borderColor: 'var(--v-border)',
          color: 'var(--v-text)',
        }}
      >
        {/* Header */}
        <div
          className="flex items-center justify-between px-4 py-3 border-b"
          style={{ borderColor: 'var(--v-border)' }}
        >
          <span className="font-mono text-sm font-bold">Select Repository</span>
          <button onClick={onClose} className="p-1 rounded hover:opacity-70">
            <X size={16} />
          </button>
        </div>

        {/* Search */}
        <div className="px-4 py-3 border-b" style={{ borderColor: 'var(--v-border)' }}>
          <div className="flex items-center gap-2">
            <Search size={14} style={{ color: 'var(--v-muted)' }} />
            <input
              type="text"
              value={search}
              onChange={(e) => handleSearchChange(e.target.value)}
              placeholder="Search repos..."
              className="flex-1 bg-transparent text-sm font-mono outline-none"
              style={{ color: 'var(--v-text)' }}
              autoFocus
            />
          </div>
        </div>

        {/* Repo list */}
        <div className="flex-1 overflow-y-auto" style={{ minHeight: '200px', maxHeight: '400px' }}>
          {reposLoading ? (
            <div className="flex items-center justify-center py-8" style={{ color: 'var(--v-muted)' }}>
              <Loader2 size={16} className="animate-spin mr-2" /> Loading repos...
            </div>
          ) : repos && repos.length > 0 ? (
            repos.map((repo) => (
              <button
                key={repo.id}
                onClick={() => handleSelectRepo(repo)}
                className="w-full text-left px-4 py-2.5 border-b transition-colors flex items-center gap-3"
                style={{
                  borderColor: 'var(--v-border)',
                  background: selectedRepo?.id === repo.id ? 'var(--v-hover)' : 'transparent',
                }}
                onMouseEnter={(e) => {
                  if (selectedRepo?.id !== repo.id) e.currentTarget.style.background = 'var(--v-hover)';
                }}
                onMouseLeave={(e) => {
                  if (selectedRepo?.id !== repo.id) e.currentTarget.style.background = 'transparent';
                }}
              >
                {repo.private ? (
                  <Lock size={12} style={{ color: 'var(--v-muted)', flexShrink: 0 }} />
                ) : (
                  <Globe size={12} style={{ color: 'var(--v-muted)', flexShrink: 0 }} />
                )}
                <div className="flex-1 min-w-0">
                  <div className="font-mono text-sm truncate" style={{ color: 'var(--v-accent)' }}>
                    {repo.full_name}
                  </div>
                  {repo.description && (
                    <div className="text-xs truncate mt-0.5" style={{ color: 'var(--v-muted)' }}>
                      {repo.description}
                    </div>
                  )}
                </div>
                <div className="flex items-center gap-3 flex-shrink-0 text-xs" style={{ color: 'var(--v-muted)' }}>
                  {repo.language && <span>{repo.language}</span>}
                  <span>{formatDate(repo.updated_at)}</span>
                </div>
              </button>
            ))
          ) : (
            <div className="flex items-center justify-center py-8 text-sm" style={{ color: 'var(--v-muted)' }}>
              {debouncedSearch ? 'No repos found' : 'No repos available'}
            </div>
          )}
        </div>

        {/* Branch selector + Clone button */}
        {selectedRepo && (
          <div
            className="px-4 py-3 border-t flex items-center gap-3"
            style={{ borderColor: 'var(--v-border)' }}
          >
            <GitBranch size={14} style={{ color: 'var(--v-muted)' }} />
            {branchesLoading ? (
              <span className="text-xs" style={{ color: 'var(--v-muted)' }}>Loading branches...</span>
            ) : (
              <select
                value={selectedBranch}
                onChange={(e) => setSelectedBranch(e.target.value)}
                className="text-sm font-mono bg-transparent border rounded px-2 py-1 outline-none"
                style={{
                  borderColor: 'var(--v-border)',
                  color: 'var(--v-text)',
                }}
              >
                {branches?.map((b) => (
                  <option key={b.name} value={b.name} style={{ background: 'var(--v-bg)' }}>
                    {b.name}
                  </option>
                ))}
              </select>
            )}
            <div className="flex-1" />
            <button
              onClick={handleClone}
              disabled={cloneMut.isPending}
              className="px-4 py-1.5 text-xs font-mono font-bold border rounded transition-colors"
              style={{
                borderColor: 'var(--v-accent)',
                color: 'var(--v-accent)',
                background: 'transparent',
                opacity: cloneMut.isPending ? 0.6 : 1,
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = 'var(--v-accent)';
                e.currentTarget.style.color = 'var(--v-bg)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = 'transparent';
                e.currentTarget.style.color = 'var(--v-accent)';
              }}
            >
              {cloneMut.isPending ? (
                <><Loader2 size={12} className="inline animate-spin mr-1" /> Cloning...</>
              ) : (
                'Clone & Select'
              )}
            </button>
          </div>
        )}

        {/* Clone error */}
        {cloneMut.isError && (
          <div className="px-4 py-2 text-xs border-t" style={{ borderColor: 'var(--v-border)', color: '#ef4444' }}>
            Clone failed: {(cloneMut.error as Error).message}
          </div>
        )}

        {/* Pagination */}
        {repos && repos.length >= 30 && (
          <div
            className="px-4 py-2 border-t flex items-center justify-between text-xs"
            style={{ borderColor: 'var(--v-border)', color: 'var(--v-muted)' }}
          >
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="font-mono px-2 py-0.5 border rounded disabled:opacity-30"
              style={{ borderColor: 'var(--v-border)' }}
            >
              prev
            </button>
            <span>page {page}</span>
            <button
              onClick={() => setPage(p => p + 1)}
              className="font-mono px-2 py-0.5 border rounded"
              style={{ borderColor: 'var(--v-border)' }}
            >
              next
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
