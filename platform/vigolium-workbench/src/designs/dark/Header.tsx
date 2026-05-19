import { Sun, ShieldCheck, Coins, Loader2, Menu } from 'lucide-react';
import { useState, useRef, useEffect } from 'react';
import { useTheme } from '@/contexts/ThemeContext';
import { useToast } from '@/contexts/ToastContext';
import { useProjectContext } from '@/contexts/ProjectContext';
import { isStaticBuild } from '@/lib/buildMode';
import type { ServerInfoResponse } from '@/api/types';
import { getUserInfo } from '@/api/client';
import { useCurrentUser, useCredits } from '@/api/hooks';

interface HeaderProps {
  serverInfo?: ServerInfoResponse;
  isConnected: boolean;
}

export default function Header({ serverInfo, isConnected }: HeaderProps) {
  const { toggleTheme } = useTheme();
  const { toasts, dismiss } = useToast();
  const { projectUUID, projects, setProject, createProject } = useProjectContext();
  const { data: currentUser } = useCurrentUser();
  const { data: creditBalance } = useCredits();
  const displayedCredits = creditBalance?.credits ?? currentUser?.credits ?? 0;
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState('');
  const dropdownRef = useRef<HTMLDivElement>(null);

  const currentProject = projects.find((p) => p.uuid === projectUUID);
  // In cloud mode every user owns at least one project (auto-created on first
  // sign-in by ProjectContext). The legacy "ALL PROJECTS" option is kept only
  // for static/workbench mode where there is no per-user scoping.
  const isAllProjects = !isStaticBuild ? false : !projectUUID;
  const fallbackLabel = isStaticBuild ? 'ALL PROJECTS' : 'no project selected';
  const displayName = currentProject?.name ?? fallbackLabel;

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

  const switchProject = (uuid: string | null) => {
    setDropdownOpen(false);
    if (uuid === projectUUID) return;
    setProject(uuid);
    window.location.href = '/';
  };

  const isDemoUser = !isStaticBuild && currentUser?.role === 'demo';
  const demoLabel = currentUser?.demo_label ?? '';
  const [loggingOut, setLoggingOut] = useState(false);

  const handleLogout = async () => {
    if (isStaticBuild) {
      document.getElementById('vigolium-logout')?.click();
      return;
    }
    setLoggingOut(true);
    await new Promise((r) => setTimeout(r, 600));
    if (isDemoUser) {
      document.cookie = 'vigolium-demo-entered=; path=/; max-age=0';
      window.location.href = '/login';
    } else {
      window.location.href = '/api/auth/logout';
    }
  };

  return (
    <header className="border-b sticky top-0 z-40" style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-bg)' }}>
      <div className="px-2 md:px-4 min-h-8 py-1 flex flex-wrap items-center justify-between text-xs gap-y-1">
        <div className="flex items-center gap-2 md:gap-4">
          <span className="font-bold" style={{ color: 'var(--v-accent)' }}>
            {isStaticBuild ? '> VIGOLIUM' : '> VIGOLIUM CLOUD CONSOLE'}
          </span>
          {!isStaticBuild && process.env.NEXT_PUBLIC_ENTERPRISE_LABEL && (
            <span style={{ color: '#ff8c00' }}>[{process.env.NEXT_PUBLIC_ENTERPRISE_LABEL}]</span>
          )}
          {isStaticBuild && serverInfo && (
            <span className="hidden sm:inline" style={{ color: 'var(--v-text-muted)' }}>[<span style={{ color: '#ff8c00' }}>workbench</span> {serverInfo.version}]</span>
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
                {isStaticBuild && (
                  <button
                    onClick={() => switchProject(null)}
                    className="flex items-center gap-1.5 w-full text-left px-3 py-1.5 v-dropdown-item"
                    style={{ color: !projectUUID ? 'var(--v-success)' : 'var(--v-text)' }}
                  >
                    <ShieldCheck className="w-3 h-3" /> ALL PROJECTS
                  </button>
                )}
                {projects.map((p) => (
                  <button
                    key={p.uuid}
                    onClick={() => switchProject(p.uuid)}
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
                  <a
                    href="/select-project"
                    onClick={() => setDropdownOpen(false)}
                    className="flex items-center gap-1.5 w-full text-left px-3 py-1.5 v-dropdown-item"
                    style={{ color: 'var(--v-accent)' }}
                  >
                    <Menu className="w-3 h-3" /> Select Project
                  </a>
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

          {/* Static mode: connection status + local user info */}
          {isStaticBuild && (
            <>
              <span style={{ color: isConnected ? 'var(--v-success)' : 'var(--v-error)' }}>
                {isConnected ? '[CONNECTED]' : '[OFFLINE]'}
              </span>
              {isConnected && getUserInfo() && (
                <span className="hidden lg:inline" style={{ color: 'var(--v-secondary)' }}>
                  [Login as <span style={{ color: '#fde68a' }}>{getUserInfo()!.name}</span>]
                </span>
              )}
            </>
          )}

          {/* Cloud mode: credits + org + user */}
          {!isStaticBuild && (
            <>
              {!isConnected && (
                <Loader2
                  className="w-3.5 h-3.5 animate-spin"
                  style={{ color: 'var(--v-text-muted)' }}
                  aria-label="Connecting to scanner server"
                />
              )}
              {isConnected && currentUser && !isDemoUser && (
                <div className="flex items-center gap-2 md:gap-4 animate-header-fade">
                  <a href="/billing" className="hidden md:inline-flex items-center gap-1" style={{ color: 'var(--v-accent)' }} title="Credits">
                    <Coins className="w-3 h-3" />
                    <span>Credits:</span>{' '}
                    {creditBalance ? (
                      <span className="font-bold">{displayedCredits.toLocaleString()}</span>
                    ) : (
                      <Loader2 className="w-3 h-3 animate-spin" />
                    )}
                  </a>
                  {currentUser.organization && (
                    <a href="/settings/team" className="hidden lg:inline" style={{ color: 'var(--v-text-muted)' }} title="Team">
                      [{currentUser.organization.name}]
                    </a>
                  )}
                  <a href="/settings" className="hidden lg:inline" style={{ color: 'var(--v-secondary)' }}>
                    [Login as <span style={{ color: '#fde68a' }}>{currentUser.name}</span>]
                  </a>
                </div>
              )}
              {isConnected && isDemoUser && (
                <div className="flex items-center gap-2 md:gap-4 animate-header-fade">
                  <a
                    href="/showcases"
                    className="hidden md:inline-flex items-center border px-2 py-0.5 hover:opacity-80 transition-opacity"
                    style={{
                      color: 'var(--v-accent)',
                      borderColor: 'color-mix(in srgb, var(--v-accent) 45%, transparent)',
                      backgroundColor: 'color-mix(in srgb, var(--v-accent) 8%, transparent)',
                    }}
                  >
                    [Open-source Audit Showcases]
                  </a>
                  <span
                    className="hidden md:inline-flex items-center border px-2 py-0.5"
                    style={{
                      color: '#ff8c00',
                      borderColor: 'color-mix(in srgb, #ff8c00 45%, transparent)',
                      backgroundColor: 'color-mix(in srgb, #ff8c00 8%, transparent)',
                    }}
                    title={
                      (demoLabel
                        ? `demo_key: ${demoLabel}${currentUser?.demo_expires ? ` · expires ${currentUser.demo_expires}` : ''}`
                        : 'demo session') + '\nData may be redacted or truncated in demo mode'
                    }
                  >
                    [Demo preview · read-only]
                  </span>
                </div>
              )}
            </>
          )}

          {isConnected && (
            <button
              onClick={handleLogout}
              disabled={loggingOut}
              className="v-header-btn-danger transition-colors inline-flex items-center gap-1.5 disabled:opacity-70 disabled:cursor-wait"
            >
              {loggingOut ? (
                <><Loader2 className="w-3 h-3 animate-spin" /> Logging out…</>
              ) : (
                isDemoUser ? '[EXIT DEMO]' : '[LOG OUT]'
              )}
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
