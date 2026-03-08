import { Sun, ShieldCheck } from 'lucide-react';
import { useState, useRef, useEffect } from 'react';
import { useTheme } from '@/contexts/ThemeContext';
import { useToast } from '@/contexts/ToastContext';
import { useProjectContext } from '@/contexts/ProjectContext';
import type { ServerInfoResponse } from '@/api/types';

const TOAST_COLORS: Record<string, string> = {
  success: '#98bc37',
  error: '#ef2f27',
  info: '#68a8e4',
};

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
    <header className="border-b border-[#2e2b26] bg-[#1c1b19] sticky top-0 z-40">
      <div className="px-4 h-8 flex items-center justify-between text-xs">
        <div className="flex items-center gap-4">
          <span className="text-[#7fd962] font-bold">&gt; VIGOLIUM</span>
          {serverInfo && (
            <span className="text-[#918175]">{serverInfo.version}</span>
          )}
          <div className="relative" ref={dropdownRef}>
            <button
              onClick={() => setDropdownOpen(!dropdownOpen)}
              className="text-[#68a8e4] hover:text-[#a8e892] transition-colors"
            >
              {isAllProjects && <ShieldCheck className="w-3 h-3 inline mr-1" />}[PROJECT: {displayName} ▼]
            </button>
            {dropdownOpen && (
              <div className="absolute top-full left-0 mt-1 bg-[#272520] border border-[#2e2b26] min-w-[200px] z-50 shadow-lg">
                <button
                  onClick={() => { setProject(null); setDropdownOpen(false); }}
                  className={`flex items-center gap-1.5 w-full text-left px-3 py-1.5 hover:bg-[#2e2b26] ${!projectUUID ? 'text-[#98bc37]' : 'text-[#fce8c3]'}`}
                >
                  <ShieldCheck className="w-3 h-3" /> ALL PROJECTS
                </button>
                {projects.map((p) => (
                  <button
                    key={p.uuid}
                    onClick={() => { setProject(p.uuid); setDropdownOpen(false); }}
                    className={`block w-full text-left px-3 py-1.5 hover:bg-[#2e2b26] ${projectUUID === p.uuid ? 'text-[#98bc37]' : 'text-[#fce8c3]'}`}
                  >
                    {p.name}
                  </button>
                ))}
                <div className="border-t border-[#2e2b26]">
                  {creating ? (
                    <div className="flex items-center px-2 py-1.5 gap-1">
                      <input
                        autoFocus
                        value={newName}
                        onChange={(e) => setNewName(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && handleCreate()}
                        placeholder="project name"
                        className="bg-[#1c1b19] border border-[#2e2b26] text-[#fce8c3] px-1.5 py-0.5 text-xs flex-1 outline-none"
                      />
                      <button onClick={handleCreate} className="text-[#98bc37] hover:text-[#a8e892]">OK</button>
                    </div>
                  ) : (
                    <button
                      onClick={() => setCreating(true)}
                      className="block w-full text-left px-3 py-1.5 text-[#68a8e4] hover:bg-[#2e2b26]"
                    >
                      + New Project
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
        <div className="flex items-center gap-4">
          {serverInfo?.proxy_addr && (
            <span className="text-[#918175]">proxy:{serverInfo.proxy_addr}</span>
          )}
          {toasts.map((t) => (
            <span
              key={t.id}
              className="animate-toast-in flex items-center gap-1 bg-[#272520] border px-2 py-0.5"
              style={{ color: TOAST_COLORS[t.type], borderColor: TOAST_COLORS[t.type] }}
            >
              {t.message}
              <button onClick={() => dismiss(t.id)} className="text-[#918175] hover:text-[#fce8c3]">[x]</button>
            </span>
          ))}
          <span className={isConnected ? 'text-[#98bc37]' : 'text-[#ef2f27]'}>
            {isConnected ? '[CONNECTED]' : '[OFFLINE]'}
          </span>
          {isConnected && (
            <button
              onClick={() => document.getElementById('vigolium-logout')?.click()}
              className="text-[#918175] hover:text-[#ef2f27] transition-colors"
            >
              [LOG OUT]
            </button>
          )}
          <button
            onClick={toggleTheme}
            className="text-[#918175] hover:text-[#a8e892] transition-colors"
            title="Switch to Editorial theme"
          >
            <Sun className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </header>
  );
}
