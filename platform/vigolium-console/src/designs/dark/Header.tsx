import { Sun, ShieldCheck } from 'lucide-react';
import { useState, useRef, useEffect } from 'react';
import { useTheme } from '@/contexts/ThemeContext';
import { useToast } from '@/contexts/ToastContext';
import { useProjectContext } from '@/contexts/ProjectContext';
import type { ServerInfoResponse } from '@/api/types';
import { getUserInfo } from '@/api/client';

interface HeaderProps {
  serverInfo?: ServerInfoResponse;
  isConnected: boolean;
}

export default function Header({ serverInfo, isConnected }: HeaderProps) {
  const { toggleTheme } = useTheme();
  const { toasts, dismiss } = useToast();
  const { projectUUID, projects, setProject, createProject } = useProjectContext();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState('');
  const dropdownRef = useRef<HTMLDivElement>(null);

  const currentProject = projects.find((p) => p.uuid === projectUUID);
  const isAllProjects = !projectUUID;
  const displayName = currentProject?.name ?? 'ALL PROJECTS';

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setDropdownOpen(false);
        setCreating(false);
      }
    }
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  const handleCreate = async () => {
    if (!newName.trim()) return;
    await createProject(newName.trim());
    setNewName('');
    setCreating(false);
    setDropdownOpen(false);
  };

  return (
    <header className="border-b sticky top-0 z-40" style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-bg)' }}>
      <div className="px-2 md:px-4 min-h-8 py-1 flex flex-wrap items-center justify-between text-xs gap-y-1">
        <div className="flex items-center gap-2 md:gap-4">
          <span className="font-bold" style={{ color: 'var(--v-accent)' }}>&gt; VIGOLIUM CONSOLE</span>
          {serverInfo && (
            <span className="hidden sm:inline" style={{ color: 'var(--v-text-muted)' }}>{serverInfo.version}</span>
          )}
          <div className="relative" ref={dropdownRef}>
            <button
              onClick={() => setDropdownOpen(!dropdownOpen)}
              className="v-header-link transition-colors"
            >
              {isAllProjects && <ShieldCheck className="w-3 h-3 inline mr-1" />}[PROJECT: <span style={{ color: '#fde68a' }}>{displayName}</span> ▼]
            </button>
            {dropdownOpen && (
              <div className="absolute top-full left-0 mt-1 min-w-[200px] z-50 shadow-lg border" style={{ backgroundColor: 'var(--v-surface)', borderColor: 'var(--v-border)' }}>
                <button
                  onClick={() => { setProject(null); setDropdownOpen(false); }}
                  className="flex items-center gap-1.5 w-full text-left px-3 py-1.5 v-dropdown-item"
                  style={{ color: !projectUUID ? 'var(--v-success)' : 'var(--v-text)' }}
                >
                  <ShieldCheck className="w-3 h-3" /> ALL PROJECTS
                </button>
                {projects.map((p) => (
                  <button
                    key={p.uuid}
                    onClick={() => { setProject(p.uuid); setDropdownOpen(false); }}
                    className="block w-full text-left px-3 py-1.5 v-dropdown-item"
                    style={{ color: projectUUID === p.uuid ? 'var(--v-success)' : 'var(--v-text)' }}
                  >
                    {p.name}
                  </button>
                ))}
                <div className="border-t" style={{ borderColor: 'var(--v-border)' }}>
                  {creating ? (
                    <div className="flex items-center px-2 py-1.5 gap-1">
                      <input
                        autoFocus
                        value={newName}
                        onChange={(e) => setNewName(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && handleCreate()}
                        placeholder="project name"
                        className="px-1.5 py-0.5 text-xs flex-1 outline-none border"
                        style={{ backgroundColor: 'var(--v-bg)', borderColor: 'var(--v-border)', color: 'var(--v-text)' }}
                      />
                      <button onClick={handleCreate} style={{ color: 'var(--v-success)' }}>OK</button>
                    </div>
                  ) : (
                    <button
                      onClick={() => setCreating(true)}
                      className="block w-full text-left px-3 py-1.5 v-dropdown-item"
                      style={{ color: 'var(--v-secondary)' }}
                    >
                      + New Project
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2 md:gap-4">
          {serverInfo?.proxy_addr && (
            <span className="hidden md:inline" style={{ color: 'var(--v-text-muted)' }}>proxy:{serverInfo.proxy_addr}</span>
          )}
          {toasts.map((t) => {
            const toastColor = t.type === 'success' ? 'var(--v-success)' : t.type === 'error' ? 'var(--v-error)' : 'var(--v-secondary)';
            return (
              <span
                key={t.id}
                className="animate-toast-in flex items-center gap-1 border px-2 py-0.5"
                style={{ color: toastColor, borderColor: toastColor, backgroundColor: 'var(--v-surface)' }}
              >
                {t.message}
                <button onClick={() => dismiss(t.id)} className="v-header-btn">[x]</button>
              </span>
            );
          })}
          <span style={{ color: isConnected ? 'var(--v-success)' : 'var(--v-error)' }}>
            {isConnected ? '[CONNECTED]' : '[OFFLINE]'}
          </span>
          {isConnected && getUserInfo() && (
            <span className="hidden lg:inline" style={{ color: 'var(--v-secondary)' }}>
              [Login as <span style={{ color: '#fde68a' }}>{getUserInfo()!.name}</span>]
            </span>
          )}
          {isConnected && (
            <button
              onClick={() => document.getElementById('vigolium-logout')?.click()}
              className="v-header-btn-danger transition-colors"
            >
              [LOG OUT]
            </button>
          )}
          <button
            onClick={toggleTheme}
            className="v-header-btn transition-colors"
            title="Toggle theme"
          >
            <Sun className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </header>
  );
}
