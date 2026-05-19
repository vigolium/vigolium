'use client';

import { useState, useMemo, useCallback } from 'react';
import { usePathname } from 'next/navigation';
import { useDemoRouter } from '@/lib/useDemoHref';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import Prism from 'prismjs';
import 'prismjs/components/prism-markdown';
import 'prismjs/components/prism-bash';
import 'prismjs/components/prism-javascript';
import 'prismjs/components/prism-json';
import 'prismjs/components/prism-yaml';
import { Info, Search, Settings, Palette, FolderKanban, Plus, Trash2, Check, User, Users, Mail, Monitor, Loader2, Copy } from 'lucide-react';
import { useTheme } from '@/contexts/ThemeContext';
import { COLOR_SCHEMES, type ColorScheme } from '@/lib/colorSchemes';
import { isStaticBuild } from '@/lib/buildMode';
import { TOGGLEABLE_PAGES, useHiddenPages, setHiddenPages } from '@/lib/nav-settings';
import { useConfig, useUpdateConfig, useProjects, useDeleteProject, useCreateProject, useProjectStats, useCurrentUser, useCredits, useTeamMembers, useInviteMember, useRemoveMember } from '@/api/hooks';
import type { ConfigEntry, Project } from '@/api/types';
import { useToast } from '@/contexts/ToastContext';
import { useProjectContext } from '@/contexts/ProjectContext';
import PageShell from './PageShell';

const ABOUT_CONTENT = `Vigolium - High-fidelity vulnerability scanner with native scan precision and agentic scan intelligence.

Vigolium provides two complementary scanning modes:

- **Native Scan** (\`vigolium scan\`) — Deterministic, multi-phase vulnerability scanning. Fast, modular, and repeatable. Runs content discovery, browser spidering, SPA crawling, SAST, and active/passive audit phases with 215 scanner modules covering:
  - **Injection** — XSS (reflected, DOM-based, SSR hydration), SQL injection (error-based, boolean/time-blind), NoSQL injection, SSTI/CSTI, CRLF injection, command injection, XXE/SAML, prototype pollution
  - **Access Control** — CSRF, IDOR, authorization bypass, mass assignment, forbidden bypass, HTTP method tampering
  - **File & Path** — LFI, path traversal, file upload flaws, directory listing, backup/sensitive file discovery, path normalization bypass
  - **API & Protocol** — GraphQL introspection, SSRF (direct & blind), open redirect, HTTP request smuggling, JWT vulnerabilities, JSONP callback, WebSocket security, race conditions
  - **Framework-Specific** — Spring Boot, Django, Laravel, Rails, Express, Next.js, Nuxt, Remix, ASP.NET/Blazor, Flask, FastAPI
  - **CMS** — WordPress (XML-RPC, user enum, AJAX exposure), Drupal, Joomla, CMS installer exposure
  - **Cloud & Infra** — Firebase (RTDB, storage, auth, functions), cloud storage listing/takeover, default credentials, web cache poisoning, CORS misconfiguration
  - **Out-of-Band** — Blind vulnerabilities via OAST callbacks (blind SSRF, blind SSTI, OAST probes)

- **Agentic Scan** (\`vigolium agent\`) — AI-driven scanning powered by Claude, Codex, or Gemini. The agent autonomously plans attack strategies, selects modules, generates custom payloads, and triages results — with the native scan engine handling heavy lifting underneath. Three modes: autopilot, pipeline, and swarm.

It also operates as an API server with traffic ingestion, or a standalone ingestor client.

## Key Features

### Native Scan

- **215 scanner modules** — 130 active (fuzzing) and 85 passive (pattern matching) modules covering OWASP Top 10 and beyond
- **Out-of-band testing (OAST)** — detect blind vulnerabilities (blind XSS, SSRF, command injection) via interactsh callback URLs with automatic payload correlation
- **Value-aware mutation** — classify parameter values by semantic type (integer, UUID, JWT, email, etc.) and generate intelligent mutations per intent (neighbor, boundary, escalation)
- **Multi-phase pipeline** — external harvesting, content discovery, SPA crawling, and audit controlled by strategy presets
- **Scanning profiles** — bundle strategy, pace, scope, and module config into a single YAML file (\`--scanning-profile\`)
- **Multiple input formats** — URLs, OpenAPI/Swagger, Postman, Burp Suite, cURL, Nuclei JSONL
- **Browser-based spider** — Chromium-driven crawler (Spitolas) with SPA support, form filling, and JS analysis
- **Content discovery** — adaptive directory/file enumeration engine (Deparos) with soft-404 detection
- **Header injection** — automatic fuzzing of existing and synthetic headers (X-Forwarded-For, X-Forwarded-Host, True-Client-IP, Referer)
- **Multi-session authentication** — inline sessions (\`--session\`), session files (\`--session-file\`), or full auth configs (\`--auth-config\`) with login flows, token extraction, and IDOR/BOLA testing
- **JavaScript extensions** — custom modules and hooks via embedded JS engine (\`vigolium.http\`, \`vigolium.scan\`) with session-aware HTTP APIs (login flows, cookie jars, CSRF extraction, auth testing, request sequencing)
- **Concurrent architecture** — configurable worker pool with per-host rate limiting and hybrid in-memory/disk/Redis queue
- **HTML reports** — generate self-contained HTML reports with sortable/filterable ag-grid tables (\`--format html\`)

### Agentic Scan

- **Autonomous scanning (Autopilot)** — AI agent autonomously discovers endpoints, runs scans, and triages findings via a sandboxed terminal with command allowlisting
- **Multi-phase pipeline (Pipeline)** — fixed 7-phase workflow (source-analysis → discover → plan → scan → triage → rescan → report) where AI agents handle strategy at checkpoints while native scan phases handle heavy lifting
- **Targeted vulnerability swarm (Swarm)** — master agent analyzes inputs, selects scanner modules, generates custom JS attack extensions, executes scans, and triages results with batched execution for large input sets
- **Query mode** — single-shot prompt execution for code review, endpoint discovery, and secret detection (not a scan — simple Q&A utility)
- **Source-aware intelligence** — when \`--source\` is provided, agents analyze application source code to discover routes, understand auth flows, and identify vulnerability sinks before scanning
- **Multiple AI backends** — Claude, Codex, Gemini, or custom ACP-compatible agents via CLI or REST API (with SSE streaming)

### Platform

- **API server mode** — REST API with Swagger UI, multi-format ingestion, transparent HTTP proxy, OpenAI-compatible agent endpoint`;

function SchemeCard({ scheme, isSelected, onSelect }: { scheme: ColorScheme; isSelected: boolean; onSelect: () => void }) {
  const { colors: c } = scheme;
  return (
    <button onClick={onSelect} className="text-left w-full">
      <div
        className="rounded overflow-hidden border-2 transition-all"
        style={{ borderColor: isSelected ? c.accent : c.border }}
      >
        {/* Header */}
        <div className="h-4 flex items-center px-1.5" style={{ backgroundColor: c.surface }}>
          <span className="text-[6px] font-bold tracking-wide" style={{ color: c.accent }}>VIG</span>
          <div className="flex-1" />
          <div className="w-1 h-1 rounded-full" style={{ backgroundColor: c.success }} />
        </div>
        {/* Nav */}
        <div className="h-2.5 flex items-center px-1.5 gap-0.5" style={{ backgroundColor: c.surface, borderTop: `1px solid ${c.border}` }}>
          {[c.accent, c.secondary, c.tertiary].map((color, i) => (
            <div key={i} className="w-3 h-0.5 rounded-sm" style={{ backgroundColor: color, opacity: 0.8 }} />
          ))}
        </div>
        {/* Body — palette dots */}
        <div className="px-1.5 py-1.5 flex gap-0.5" style={{ backgroundColor: c.bg, borderTop: `1px solid ${c.border}` }}>
          {[c.accent, c.secondary, c.tertiary, c.success, c.error].map((color, i) => (
            <div key={i} className="w-2 h-2 rounded-sm" style={{ backgroundColor: color }} />
          ))}
        </div>
      </div>
      <div className="flex items-center justify-between mt-1 px-0.5">
        <span className="text-[9px] font-medium truncate" style={{ color: isSelected ? 'var(--v-accent)' : 'var(--v-text-muted)' }}>
          {scheme.name}
        </span>
        {isSelected && <span className="text-[9px] font-bold" style={{ color: 'var(--v-accent)' }}>&#10003;</span>}
      </div>
    </button>
  );
}

// Mirrors HIDDEN_PROJECT_UUIDS in src/contexts/ProjectContext.tsx — kept here
// only so the static-mode "default" badge and the non-deletable guard can
// still recognize the seeded project. In cloud mode these UUIDs are filtered
// out before they reach the table.
const DEFAULT_PROJECT_UUIDS = new Set<string>([
  '00000000-0000-0000-0000-000000000001',
  '00000000-0000-0000-defa-c01001000001',
]);

/* ── Static mode tabs ─────────────────────────────────────────────── */

type StaticTab = 'config' | 'projects' | 'theme' | 'about';
type CloudTab = 'projects' | 'team' | 'console' | 'theme';
type SettingsTab = StaticTab | CloudTab;

const STATIC_TABS: StaticTab[] = ['config', 'projects', 'theme', 'about'];
const CLOUD_TABS: CloudTab[] = ['projects', 'console', 'theme'];

const TAB_ICONS: Record<string, typeof Settings> = {
  config: Settings,
  projects: FolderKanban,
  theme: Palette,
  about: Info,
  profile: User,
  team: Users,
  console: Monitor,
};

export default function SettingsPage({ initialTab }: { initialTab?: string }) {
  const defaultTab = isStaticBuild ? 'config' : 'projects';
  const tabs = isStaticBuild ? STATIC_TABS : CLOUD_TABS;
  const validTab = tabs.includes(initialTab as never) ? initialTab as SettingsTab : defaultTab;

  const { schemeId, setScheme } = useTheme();
  const router = useDemoRouter();
  const pathname = usePathname();
  const [activeTab, setActiveTabState] = useState<SettingsTab>(validTab);
  const setActiveTab = useCallback((tab: SettingsTab) => {
    setActiveTabState(tab);
    router.replace(tab === defaultTab ? '/settings' : `/settings/${tab}`, { scroll: false });
  }, [router, defaultTab]);
  const [filter, setFilter] = useState('');
  const hiddenPages = useHiddenPages();

  // ── Config state (static mode) ──
  const [configFilter, setConfigFilter] = useState('');
  const { data: configData } = useConfig(configFilter || undefined);
  const updateConfig = useUpdateConfig();
  const { toast } = useToast();
  const [editingKey, setEditingKey] = useState<string | null>(null);
  const [editValue, setEditValue] = useState('');
  const [revealedKeys, setRevealedKeys] = useState<Set<string>>(new Set());
  const [collapsedSections, setCollapsedSections] = useState<Set<string>>(new Set());
  const [activeTag, setActiveTag] = useState<string | null>(null);

  const configEntries = configData?.entries ?? [];

  const grouped = useMemo(() => {
    const groups: Record<string, ConfigEntry[]> = {};
    for (const entry of configEntries) {
      const prefix = entry.key.split('.')[0] || 'general';
      if (!groups[prefix]) groups[prefix] = [];
      groups[prefix].push(entry);
    }
    return groups;
  }, [configEntries]);

  const toggleSection = (prefix: string) => {
    setCollapsedSections((prev) => {
      const next = new Set(prev);
      if (next.has(prefix)) next.delete(prefix);
      else next.add(prefix);
      return next;
    });
  };

  const startEdit = (entry: ConfigEntry) => {
    setEditingKey(entry.key);
    setEditValue(entry.value);
  };

  const saveEdit = () => {
    if (editingKey) {
      updateConfig.mutate([{ key: editingKey, value: editValue }], {
        onSuccess: () => toast('config updated', 'success'),
        onError: () => toast('error updating config', 'error'),
      });
      setEditingKey(null);
    }
  };

  const toggleReveal = (key: string) => {
    setRevealedKeys((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  // ── Projects state ──
  // Cloud listing comes from Convex; static comes from the scanner. Either
  // way the user only sees projects they have access to — no extra filter
  // needed in this component.
  const { projectUUID, setProject } = useProjectContext();
  const { data: projectsList = [] } = useProjects();
  const deleteProjectMutation = useDeleteProject();
  const createProjectMutation = useCreateProject();
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newProjectName, setNewProjectName] = useState('');
  const [newProjectDesc, setNewProjectDesc] = useState('');
  const [confirmDeleteUUID, setConfirmDeleteUUID] = useState<string | null>(null);
  const [projectSearch, setProjectSearch] = useState('');

  const filteredProjects = useMemo(() => {
    if (!projectSearch) return projectsList;
    const q = projectSearch.toLowerCase();
    return projectsList.filter((p: Project) =>
      p.name.toLowerCase().includes(q) || (p.description && p.description.toLowerCase().includes(q))
    );
  }, [projectsList, projectSearch]);

  const handleCreateProject = () => {
    if (!newProjectName.trim()) return;
    createProjectMutation.mutate({ name: newProjectName.trim(), description: newProjectDesc.trim() || undefined }, {
      onSuccess: (project) => {
        toast(`project "${project.name}" created`, 'success');
        setNewProjectName('');
        setNewProjectDesc('');
        setShowCreateForm(false);
        setProject(project.uuid);
      },
      onError: () => toast('error creating project', 'error'),
    });
  };

  const handleDeleteProject = (uuid: string) => {
    deleteProjectMutation.mutate(uuid, {
      onSuccess: () => {
        toast('project deleted', 'success');
        setConfirmDeleteUUID(null);
        if (projectUUID === uuid) setProject(null);
      },
      onError: () => toast('error deleting project', 'error'),
    });
  };

  // ── Profile state (cloud mode) ──
  const { data: currentUser } = useCurrentUser();
  const { data: creditBalance } = useCredits();
  const displayedCredits = creditBalance?.credits ?? currentUser?.credits ?? 0;

  // ── Team state (cloud mode) ──
  const { data: members, isLoading: membersLoading } = useTeamMembers();
  const invite = useInviteMember();
  const remove = useRemoveMember();
  const [email, setEmail] = useState('');

  const handleInvite = async () => {
    if (!email.trim()) return;
    try {
      await invite.mutateAsync({ email: email.trim() });
      toast(`Invitation sent to ${email}`, 'success');
      setEmail('');
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Failed to invite', 'error');
    }
  };

  const handleRemove = async (membershipId: string, name: string) => {
    if (!confirm(`Remove ${name} from the team?`)) return;
    try {
      await remove.mutateAsync(membershipId);
      toast(`${name} removed`, 'success');
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Failed to remove', 'error');
    }
  };

  // ── Theme state (shared) ──
  const darkSchemes = COLOR_SCHEMES.filter(s => s.base === 'dark');
  const lightSchemes = COLOR_SCHEMES.filter(s => s.base === 'light');

  const matchFilter = (s: ColorScheme) =>
    !filter || s.name.toLowerCase().includes(filter.toLowerCase());

  const filteredDark = darkSchemes.filter(matchFilter);
  const filteredLight = lightSchemes.filter(matchFilter);

  return (
    <PageShell>
      <div className="px-4 py-4">
        <div className="flex items-center gap-4 pb-2 mb-4 border-b" style={{ borderColor: 'var(--v-border)' }}>
          {tabs.map((tab) => {
            const Icon = TAB_ICONS[tab];
            return (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className="flex items-center gap-1 text-xs font-bold uppercase tracking-wide pb-1 border-b-2 transition-colors"
                style={{
                  color: activeTab === tab ? 'var(--v-accent)' : 'var(--v-text-muted)',
                  borderColor: activeTab === tab ? 'var(--v-accent)' : 'transparent',
                }}
              >
                {Icon && <Icon className="w-3 h-3" />}
                {tab.charAt(0).toUpperCase() + tab.slice(1)}
              </button>
            );
          })}
        </div>

        {/* ── Config tab (static mode) ────────────────────────────────── */}
        {activeTab === 'config' && (
          <div className="space-y-4">
          <div className="border overflow-hidden" style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-bg)' }}>
            <div className="px-3 py-1.5 border-b flex items-center justify-between" style={{ borderColor: 'var(--v-border)' }}>
              <span className="text-xs font-bold" style={{ color: 'var(--v-accent)' }}>~/.vigolium/vigolium-configs.yaml</span>
              <input
                type="text"
                value={configFilter}
                onChange={(e) => setConfigFilter(e.target.value)}
                placeholder="filter..."
                className="border text-xs px-2 py-0.5 w-40 focus:outline-none"
                style={{ backgroundColor: 'var(--v-bg)', borderColor: 'var(--v-border)', color: 'var(--v-text)' }}
              />
            </div>

            {Object.keys(grouped).length > 0 && (
              <div className="px-3 py-1.5 border-b flex items-center gap-1.5 overflow-x-auto" style={{ borderColor: 'var(--v-border)' }}>
                <button
                  onClick={() => setActiveTag(null)}
                  className="shrink-0 px-1.5 py-0.5 text-[10px] font-bold uppercase border transition-colors"
                  style={activeTag === null
                    ? { borderColor: 'color-mix(in srgb, var(--v-accent) 50%, transparent)', color: 'var(--v-accent)', backgroundColor: 'color-mix(in srgb, var(--v-accent) 10%, transparent)' }
                    : { borderColor: 'var(--v-border)', color: 'var(--v-text-muted)' }
                  }
                >
                  ALL
                </button>
                {Object.keys(grouped).map((tag) => (
                  <button
                    key={tag}
                    onClick={() => setActiveTag(activeTag === tag ? null : tag)}
                    className="shrink-0 px-1.5 py-0.5 text-[10px] font-bold uppercase border transition-colors"
                    style={activeTag === tag
                      ? { borderColor: 'color-mix(in srgb, var(--v-accent) 50%, transparent)', color: 'var(--v-accent)', backgroundColor: 'color-mix(in srgb, var(--v-accent) 10%, transparent)' }
                      : { borderColor: 'var(--v-border)', color: 'var(--v-text-muted)' }
                    }
                  >
                    {tag}
                  </button>
                ))}
              </div>
            )}

            <div className="overflow-y-auto" style={{ maxHeight: 'calc(100vh - 280px)' }}>
              {Object.entries(grouped).filter(([prefix]) => !activeTag || prefix === activeTag).map(([prefix, items]) => {
                const collapsed = collapsedSections.has(prefix);
                return (
                  <div key={prefix}>
                    <button
                      onClick={() => toggleSection(prefix)}
                      className="w-full px-3 py-1 text-[10px] font-bold uppercase border-b flex items-center gap-1 transition-colors"
                      style={{ backgroundColor: 'var(--v-surface)', color: 'var(--v-accent)', borderColor: 'var(--v-border)' }}
                    >
                      <span>{collapsed ? '\u25b8' : '\u25be'}</span> [{prefix}]
                      <span className="ml-auto font-normal" style={{ color: 'var(--v-text-muted)' }}>{items.length}</span>
                    </button>
                    {!collapsed && <div className="divide-y" style={{ borderColor: 'var(--v-surface)' }}>
                      {items.map((entry) => (
                        <div key={entry.key} className="px-3 py-1 transition-colors text-xs flex items-center justify-between gap-2" style={{ borderColor: 'var(--v-surface)' }}>
                          <span className="shrink-0 w-[280px] truncate" style={{ color: 'var(--v-text-muted)' }}>{entry.key}</span>
                          {editingKey === entry.key ? (
                            <div className="flex items-center gap-1 flex-1">
                              <input
                                type="text"
                                value={editValue}
                                onChange={(e) => setEditValue(e.target.value)}
                                onKeyDown={(e) => e.key === 'Enter' && saveEdit()}
                                className="border text-xs px-1.5 py-0.5 flex-1 focus:outline-none"
                                style={{ backgroundColor: 'var(--v-bg)', borderColor: 'color-mix(in srgb, var(--v-accent) 50%, transparent)', color: 'var(--v-text)' }}
                                autoFocus
                              />
                              <button onClick={saveEdit} className="px-1" style={{ color: 'var(--v-success)' }}>[ok]</button>
                              <button onClick={() => setEditingKey(null)} className="px-1" style={{ color: 'var(--v-error)' }}>[x]</button>
                            </div>
                          ) : (
                            <div className="flex items-center gap-2 flex-1 min-w-0">
                              <span className="truncate flex-1" style={{ color: 'var(--v-text)' }}>
                                {entry.sensitive && !revealedKeys.has(entry.key)
                                  ? '********'
                                  : entry.value}
                              </span>
                              {entry.sensitive && (
                                <button
                                  onClick={() => toggleReveal(entry.key)}
                                  className="text-[10px] shrink-0"
                                  style={{ color: 'var(--v-text-muted)' }}
                                >
                                  {revealedKeys.has(entry.key) ? '[hide]' : '[show]'}
                                </button>
                              )}
                              <button
                                onClick={() => startEdit(entry)}
                                className="text-[10px] shrink-0"
                                style={{ color: 'var(--v-text-muted)' }}
                              >
                                [edit]
                              </button>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>}
                  </div>
                );
              })}
              {configEntries.length === 0 && (
                <div className="px-3 py-4 text-xs" style={{ color: 'var(--v-text-muted)' }}>no config entries</div>
              )}
            </div>
          </div>
          </div>
        )}

        {/* ── Projects tab (shared, with Profile + GitHub in cloud mode) ─ */}
        {activeTab === 'projects' && (
          <div className="space-y-6">
            {!isStaticBuild && (
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <User className="w-4 h-4" style={{ color: 'var(--v-secondary)' }} />
                  <h2 className="text-sm font-bold" style={{ color: 'var(--v-accent)' }}>Profile</h2>
                </div>
                {currentUser ? (
                  <div
                    className="border flex flex-wrap items-center gap-x-6 gap-y-1 px-3 py-2 text-xs"
                    style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-surface)' }}
                  >
                    <div className="flex items-baseline gap-2">
                      <span className="font-bold uppercase" style={{ color: 'var(--v-text-muted)' }}>Name</span>
                      <span style={{ color: 'var(--v-text)' }}>{currentUser.name}</span>
                    </div>
                    <div className="flex items-baseline gap-2">
                      <span className="font-bold uppercase" style={{ color: 'var(--v-text-muted)' }}>Email</span>
                      <span style={{ color: 'var(--v-text)' }}>{currentUser.email}</span>
                    </div>
                    <div className="flex items-baseline gap-2">
                      <span className="font-bold uppercase" style={{ color: 'var(--v-text-muted)' }}>Role</span>
                      <span style={{ color: 'var(--v-text)' }}>{currentUser.role}</span>
                    </div>
                    {currentUser.organization && (
                      <div className="flex items-baseline gap-2">
                        <span className="font-bold uppercase" style={{ color: 'var(--v-text-muted)' }}>Org</span>
                        <span style={{ color: 'var(--v-text)' }}>{currentUser.organization.name}</span>
                      </div>
                    )}
                    <div className="flex items-baseline gap-2">
                      <span className="font-bold uppercase" style={{ color: 'var(--v-text-muted)' }}>Credits</span>
                      <span className="font-bold" style={{ color: 'var(--v-accent)' }}>{displayedCredits.toLocaleString()}</span>
                    </div>
                  </div>
                ) : (
                  <p className="text-xs" style={{ color: 'var(--v-text-muted)' }}>Not signed in</p>
                )}
              </div>
            )}

            <div className="flex items-center gap-2 mb-2">
              <FolderKanban className="w-4 h-4" style={{ color: 'var(--v-secondary)' }} />
              <h2 className="text-sm font-bold" style={{ color: 'var(--v-accent)' }}>Projects</h2>
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-bold shrink-0" style={{ color: 'var(--v-text-muted)' }}>
                {projectsList.length} project{projectsList.length !== 1 ? 's' : ''}
              </span>
              <div className="flex items-center gap-2">
                <div className="flex items-center gap-1.5 border px-2 py-0.5" style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-surface)' }}>
                  <Search className="w-3 h-3" style={{ color: 'var(--v-text-muted)' }} />
                  <input
                    type="text"
                    value={projectSearch}
                    onChange={(e) => setProjectSearch(e.target.value)}
                    placeholder="search projects..."
                    className="bg-transparent text-xs outline-none w-40"
                    style={{ color: 'var(--v-text)' }}
                  />
                </div>
                <button
                  onClick={() => setShowCreateForm(!showCreateForm)}
                  className="flex items-center gap-1 text-[10px] font-bold uppercase px-2 py-0.5 border transition-colors"
                  style={{ borderColor: 'var(--v-accent)', color: 'var(--v-accent)' }}
                >
                  <Plus className="w-3 h-3" /> new
                </button>
              </div>
            </div>

            {showCreateForm && (
              <div className="border p-3 space-y-2" style={{ borderColor: 'var(--v-accent)', backgroundColor: 'var(--v-surface)' }}>
                <input
                  type="text"
                  value={newProjectName}
                  onChange={(e) => setNewProjectName(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleCreateProject()}
                  placeholder="project name"
                  className="w-full border text-xs px-2 py-1 focus:outline-none"
                  style={{ backgroundColor: 'var(--v-bg)', borderColor: 'var(--v-border)', color: 'var(--v-text)' }}
                  autoFocus
                />
                <input
                  type="text"
                  value={newProjectDesc}
                  onChange={(e) => setNewProjectDesc(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleCreateProject()}
                  placeholder="description (optional)"
                  className="w-full border text-xs px-2 py-1 focus:outline-none"
                  style={{ backgroundColor: 'var(--v-bg)', borderColor: 'var(--v-border)', color: 'var(--v-text)' }}
                />
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleCreateProject}
                    disabled={!newProjectName.trim() || createProjectMutation.isPending}
                    className="text-[10px] font-bold uppercase px-2 py-0.5 border transition-colors disabled:opacity-40"
                    style={{ borderColor: 'var(--v-success)', color: 'var(--v-success)' }}
                  >
                    {createProjectMutation.isPending ? 'creating...' : 'create'}
                  </button>
                  <button
                    onClick={() => { setShowCreateForm(false); setNewProjectName(''); setNewProjectDesc(''); }}
                    className="text-[10px] font-bold uppercase px-2 py-0.5 border transition-colors"
                    style={{ borderColor: 'var(--v-border)', color: 'var(--v-text-muted)' }}
                  >
                    cancel
                  </button>
                </div>
              </div>
            )}

            <div className="border overflow-hidden" style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-bg)' }}>
              <div className="grid grid-cols-[1fr_1.2fr_60px_200px_50px_50px_80px_100px] px-3 py-1.5 border-b text-[10px] font-bold uppercase"
                style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-surface)', color: 'var(--v-text-muted)' }}>
                <span>Name</span>
                <span>Description</span>
                <span className="text-right">Records</span>
                <span className="text-right">Findings</span>
                <span className="text-right">Scans</span>
                <span className="text-right">Agents</span>
                <span className="text-right">Created</span>
                <span className="text-right">Actions</span>
              </div>

              <div className="overflow-y-auto" style={{ maxHeight: 'calc(100vh - 320px)' }}>
                {filteredProjects.map((project: Project) => (
                  <ProjectRow
                    key={project.uuid}
                    project={project}
                    isCurrent={projectUUID === project.uuid}
                    isDefault={DEFAULT_PROJECT_UUIDS.has(project.uuid)}
                    isConfirmingDelete={confirmDeleteUUID === project.uuid}
                    onSelect={() => setProject(project.uuid)}
                    onAskDelete={() => setConfirmDeleteUUID(project.uuid)}
                    onCancelDelete={() => setConfirmDeleteUUID(null)}
                    onConfirmDelete={() => handleDeleteProject(project.uuid)}
                  />
                ))}
                {filteredProjects.length === 0 && (
                  <div className="px-3 py-4 text-xs" style={{ color: 'var(--v-text-muted)' }}>
                    {projectSearch ? `no projects match "${projectSearch}"` : 'no projects found'}
                  </div>
                )}
              </div>
            </div>

          </div>
        )}

        {/* ── Team tab (cloud mode) ───────────────────────────────────── */}
        {activeTab === 'team' && (
          <div className="space-y-4">
            <div className="flex items-center gap-2 mb-2">
              <Users className="w-4 h-4" style={{ color: 'var(--v-secondary)' }} />
              <h2 className="text-sm font-bold" style={{ color: 'var(--v-accent)' }}>
                Team{currentUser?.organization ? ` — ${currentUser.organization.name}` : ''}
              </h2>
            </div>

            <div className="flex items-center gap-2">
              <Mail className="w-3 h-3" style={{ color: 'var(--v-text-muted)' }} />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleInvite()}
                placeholder="email@example.com"
                className="flex-1 px-2 py-1 text-xs border outline-none"
                style={{ backgroundColor: 'var(--v-bg)', borderColor: 'var(--v-border)', color: 'var(--v-text)' }}
              />
              <button
                onClick={handleInvite}
                disabled={invite.isPending || !email.trim()}
                className="px-3 py-1 text-xs font-bold border transition-colors"
                style={{ borderColor: 'var(--v-accent)', color: 'var(--v-accent)' }}
              >
                {invite.isPending ? 'Sending...' : 'Invite'}
              </button>
            </div>

            <div className="border overflow-hidden" style={{ borderColor: 'var(--v-border)' }}>
              <table className="w-full text-xs">
                <thead>
                  <tr style={{ backgroundColor: 'color-mix(in srgb, var(--v-surface) 50%, transparent)' }}>
                    <th className="text-left px-3 py-2 font-bold" style={{ color: 'var(--v-text-muted)' }}>Name</th>
                    <th className="text-left px-3 py-2 font-bold" style={{ color: 'var(--v-text-muted)' }}>Email</th>
                    <th className="text-left px-3 py-2 font-bold" style={{ color: 'var(--v-text-muted)' }}>Role</th>
                    <th className="text-left px-3 py-2 font-bold" style={{ color: 'var(--v-text-muted)' }}>Joined</th>
                    <th className="w-8"></th>
                  </tr>
                </thead>
                <tbody>
                  {membersLoading && (
                    <tr><td colSpan={5} className="px-3 py-4 text-center" style={{ color: 'var(--v-text-muted)' }}>Loading...</td></tr>
                  )}
                  {members?.map((m) => (
                    <tr key={m.id} className="border-t" style={{ borderColor: 'var(--v-border)' }}>
                      <td className="px-3 py-1.5" style={{ color: 'var(--v-text)' }}>{m.name}</td>
                      <td className="px-3 py-1.5" style={{ color: 'var(--v-text-muted)' }}>{m.email}</td>
                      <td className="px-3 py-1.5">
                        <span
                          className="px-1.5 py-0.5 text-[10px] uppercase rounded"
                          style={{
                            backgroundColor: m.role === 'admin'
                              ? 'color-mix(in srgb, var(--v-accent) 15%, transparent)'
                              : 'color-mix(in srgb, var(--v-text-muted) 15%, transparent)',
                            color: m.role === 'admin' ? 'var(--v-accent)' : 'var(--v-text-muted)',
                          }}
                        >
                          {m.role}
                        </span>
                      </td>
                      <td className="px-3 py-1.5" style={{ color: 'var(--v-text-muted)' }}>
                        {new Date(m.joined_at).toLocaleDateString()}
                      </td>
                      <td className="px-3 py-1.5">
                        {m.email !== currentUser?.email && (
                          <button
                            onClick={() => handleRemove(m.membership_id, m.name)}
                            className="transition-colors"
                            style={{ color: 'var(--v-error)' }}
                            title="Remove member"
                          >
                            <Trash2 className="w-3 h-3" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                  {!membersLoading && (!members || members.length === 0) && (
                    <tr><td colSpan={5} className="px-3 py-4 text-center" style={{ color: 'var(--v-text-muted)' }}>No team members</td></tr>
                  )}
                </tbody>
              </table>
            </div>

          </div>
        )}

        {/* ── Console tab (cloud mode) ──────────────────────────────── */}
        {activeTab === 'console' && (
          <div>
            <div className="flex items-center gap-2 mb-4">
              <Monitor className="w-4 h-4" style={{ color: 'var(--v-secondary)' }} />
              <h2 className="text-sm font-bold" style={{ color: 'var(--v-accent)' }}>Navigation Pages</h2>
            </div>
            <p className="text-xs mb-4" style={{ color: 'var(--v-text-muted)' }}>
              Toggle which pages appear in the navigation bar. Hidden pages are still accessible via direct URL.
            </p>
            <div className="border rounded" style={{ borderColor: 'var(--v-border)' }}>
              {TOGGLEABLE_PAGES.map((page, i) => {
                const isHidden = hiddenPages.has(page.href);
                return (
                  <div
                    key={page.href}
                    className={`flex items-center justify-between px-4 py-2.5 ${i > 0 ? 'border-t' : ''}`}
                    style={{ borderColor: 'var(--v-border)' }}
                  >
                    <span className="text-xs" style={{ color: isHidden ? 'var(--v-text-muted)' : 'var(--v-text)' }}>
                      {page.label}
                      <span className="ml-2 text-[10px]" style={{ color: 'var(--v-text-muted)' }}>{page.href}</span>
                    </span>
                    <button
                      onClick={() => {
                        const current = new Set(hiddenPages);
                        if (current.has(page.href)) {
                          current.delete(page.href);
                        } else {
                          current.add(page.href);
                        }
                        setHiddenPages(current);
                      }}
                      className="text-[10px] px-2 py-1 border rounded transition-colors"
                      style={{
                        borderColor: isHidden ? 'var(--v-border)' : 'var(--v-accent)',
                        color: isHidden ? 'var(--v-text-muted)' : 'var(--v-accent)',
                        backgroundColor: isHidden ? 'transparent' : 'color-mix(in srgb, var(--v-accent) 10%, transparent)',
                      }}
                    >
                      {isHidden ? 'hidden' : 'visible'}
                    </button>
                  </div>
                );
              })}
            </div>
            <p className="text-[10px] mt-3" style={{ color: 'var(--v-text-muted)' }}>
              Changes take effect immediately. Refresh the page if the navigation bar does not update.
            </p>
          </div>
        )}

        {/* ── Theme tab (shared) ──────────────────────────────────────── */}
        {activeTab === 'theme' && (
          <div>
            <div className="flex items-center gap-2 mb-4 max-w-xs">
              <div className="flex items-center gap-1.5 flex-1 border px-2 py-1" style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-surface)' }}>
                <Search className="w-3 h-3" style={{ color: 'var(--v-text-muted)' }} />
                <input
                  type="text"
                  value={filter}
                  onChange={e => setFilter(e.target.value)}
                  placeholder="Search schemes..."
                  className="bg-transparent text-xs outline-none flex-1"
                  style={{ color: 'var(--v-text)' }}
                />
              </div>
            </div>

            {filteredDark.length > 0 && (
              <>
                <h3 className="text-xs font-bold uppercase tracking-wide mb-2" style={{ color: 'var(--v-text-muted)' }}>
                  Dark ({filteredDark.length})
                </h3>
                <div className="grid grid-cols-4 sm:grid-cols-5 md:grid-cols-7 lg:grid-cols-9 xl:grid-cols-11 gap-2 mb-5">
                  {filteredDark.map(s => (
                    <SchemeCard key={s.id} scheme={s} isSelected={schemeId === s.id} onSelect={() => setScheme(s.id)} />
                  ))}
                </div>
              </>
            )}

            {filteredLight.length > 0 && (
              <>
                <h3 className="text-xs font-bold uppercase tracking-wide mb-2" style={{ color: 'var(--v-text-muted)' }}>
                  Light ({filteredLight.length})
                </h3>
                <div className="grid grid-cols-4 sm:grid-cols-5 md:grid-cols-7 lg:grid-cols-9 xl:grid-cols-11 gap-2 mb-5">
                  {filteredLight.map(s => (
                    <SchemeCard key={s.id} scheme={s} isSelected={schemeId === s.id} onSelect={() => setScheme(s.id)} />
                  ))}
                </div>
              </>
            )}

            {filteredDark.length === 0 && filteredLight.length === 0 && (
              <p className="text-xs" style={{ color: 'var(--v-text-muted)' }}>No schemes match &ldquo;{filter}&rdquo;</p>
            )}
          </div>
        )}

        {/* ── About tab (static mode) ─────────────────────────────────── */}
        {activeTab === 'about' && (
          <div>
            <div className="flex items-center gap-2 mb-4">
              <Info className="w-4 h-4" style={{ color: 'var(--v-secondary)' }} />
              <h2 className="text-sm font-bold" style={{ color: 'var(--v-accent)' }}>About Vigolium</h2>
            </div>
            <div className="prose-v-settings overflow-auto max-h-[calc(100vh-200px)] text-justify px-4 py-3">
              <ReactMarkdown remarkPlugins={[remarkGfm]}
                components={{
                  code({ className, children, ...props }) {
                    const match = /language-(\w+)/.exec(className || '');
                    const lang = match?.[1];
                    const code = String(children).replace(/\n$/, '');
                    if (lang && Prism.languages[lang]) {
                      return (
                        <code
                          className={className}
                          dangerouslySetInnerHTML={{
                            __html: Prism.highlight(code, Prism.languages[lang], lang),
                          }}
                          {...props}
                        />
                      );
                    }
                    return <code className={className} {...props}>{children}</code>;
                  },
                }}
              >
                {ABOUT_CONTENT}
              </ReactMarkdown>
            </div>
            <div className="mt-6 px-4 py-4 border" style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-surface)' }}>
              <h3 className="text-xs font-bold uppercase tracking-wide mb-3" style={{ color: 'var(--v-accent)' }}>Official Resources</h3>
              <div className="flex items-center gap-3">
                <a href="https://www.vigolium.com/" target="_blank" rel="noopener noreferrer"
                  className="text-xs font-bold px-3 py-1.5 border transition-colors hover:opacity-80"
                  style={{ borderColor: 'var(--v-accent)', color: 'var(--v-accent)' }}>
                  [website]
                </a>
                <a href="https://docs.vigolium.com/" target="_blank" rel="noopener noreferrer"
                  className="text-xs font-bold px-3 py-1.5 border transition-colors hover:opacity-80"
                  style={{ borderColor: 'var(--v-secondary)', color: 'var(--v-secondary)' }}>
                  [documentation]
                </a>
              </div>
            </div>
          </div>
        )}
      </div>
    </PageShell>
  );
}

interface ProjectRowProps {
  project: Project;
  isCurrent: boolean;
  isDefault: boolean;
  isConfirmingDelete: boolean;
  onSelect: () => void;
  onAskDelete: () => void;
  onCancelDelete: () => void;
  onConfirmDelete: () => void;
}

function ProjectRow({ project, isCurrent, isDefault, isConfirmingDelete, onSelect, onAskDelete, onCancelDelete, onConfirmDelete }: ProjectRowProps) {
  const { data: s } = useProjectStats(project.uuid);
  const { toast } = useToast();
  const handleCopyUUID = async () => {
    try {
      await navigator.clipboard.writeText(project.uuid);
      toast('project uuid copied', 'success');
    } catch {
      toast('failed to copy uuid', 'error');
    }
  };
  return (
    <div
      className="grid grid-cols-[1fr_1.2fr_60px_200px_50px_50px_80px_100px] px-3 py-1.5 border-b text-xs items-start transition-colors"
      style={{
        borderColor: 'var(--v-surface)',
        backgroundColor: isCurrent ? 'color-mix(in srgb, var(--v-accent) 8%, transparent)' : undefined,
      }}
    >
      <div className="flex items-start gap-1 min-w-0 pr-2">
        {isCurrent && <Check className="w-3 h-3 shrink-0 mt-0.5" style={{ color: 'var(--v-accent)' }} />}
        <div className="min-w-0">
          <span className="font-medium break-words leading-tight" style={{ color: isCurrent ? 'var(--v-accent)' : 'var(--v-text)' }}>
            {project.name}
          </span>
          {isDefault && <span className="text-[9px] px-1 border ml-1 inline-block" style={{ borderColor: 'var(--v-border)', color: 'var(--v-text-muted)' }}>default</span>}
          <button
            onClick={handleCopyUUID}
            title={`Copy project UUID: ${project.uuid}`}
            className="flex items-center gap-1 mt-0.5 font-mono text-[10px] truncate hover:underline"
            style={{ color: 'var(--v-text-muted)' }}
          >
            <Copy className="w-2.5 h-2.5 shrink-0" />
            <span className="truncate">{project.uuid}</span>
          </button>
        </div>
      </div>
      <span className="break-words leading-tight pr-2" style={{ color: 'var(--v-text-muted)' }}>{project.description || '-'}</span>
      <span className="text-right tabular-nums" style={{ color: 'var(--v-text)' }}>{s?.http_records?.total ?? 0}</span>
      <div className="flex items-center justify-end gap-1.5 flex-wrap">
        {(s?.findings?.critical ?? 0) > 0 && <span className="text-[9px] px-1 py-0.5 border" style={{ color: 'var(--v-error)', borderColor: 'color-mix(in srgb, var(--v-error) 30%, transparent)' }}>C:{s!.findings.critical}</span>}
        {(s?.findings?.high ?? 0) > 0 && <span className="text-[9px] px-1 py-0.5 border" style={{ color: '#f97316', borderColor: 'color-mix(in srgb, #f97316 30%, transparent)' }}>H:{s!.findings.high}</span>}
        {(s?.findings?.medium ?? 0) > 0 && <span className="text-[9px] px-1 py-0.5 border" style={{ color: '#eab308', borderColor: 'color-mix(in srgb, #eab308 30%, transparent)' }}>M:{s!.findings.medium}</span>}
        {(s?.findings?.low ?? 0) > 0 && <span className="text-[9px] px-1 py-0.5 border" style={{ color: 'var(--v-secondary)', borderColor: 'color-mix(in srgb, var(--v-secondary) 30%, transparent)' }}>L:{s!.findings.low}</span>}
        {(s?.findings?.info ?? 0) > 0 && <span className="text-[9px] px-1 py-0.5 border" style={{ color: 'var(--v-text-muted)', borderColor: 'var(--v-border)' }}>I:{s!.findings.info}</span>}
        {(s?.findings?.total ?? 0) === 0 && <span style={{ color: 'var(--v-text-muted)' }}>0</span>}
      </div>
      <span className="text-right tabular-nums" style={{ color: 'var(--v-text)' }}>{s?.scans ?? 0}</span>
      <span className="text-right tabular-nums" style={{ color: 'var(--v-text)' }}>{s?.agent_runs ?? 0}</span>
      <span className="text-right text-[10px]" style={{ color: 'var(--v-text-muted)' }}>
        {new Date(project.created_at).toLocaleDateString()}
      </span>
      <div className="flex items-center justify-end gap-1">
        {!isCurrent && (
          <button onClick={onSelect} className="text-[10px] font-bold px-1" style={{ color: 'var(--v-accent)' }}>
            [use]
          </button>
        )}
        {!isDefault && (
          isConfirmingDelete ? (
            <div className="flex items-center gap-0.5">
              <button onClick={onConfirmDelete} className="text-[10px] font-bold px-1" style={{ color: 'var(--v-error)' }}>[yes]</button>
              <button onClick={onCancelDelete} className="text-[10px] font-bold px-1" style={{ color: 'var(--v-text-muted)' }}>[no]</button>
            </div>
          ) : (
            <button onClick={onAskDelete} className="text-[10px] font-bold px-1" style={{ color: 'var(--v-text-muted)' }}>[del]</button>
          )
        )}
      </div>
    </div>
  );
}
