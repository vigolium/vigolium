'use client';

import { useState, useMemo, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import Prism from 'prismjs';
import 'prismjs/components/prism-markdown';
import 'prismjs/components/prism-bash';
import 'prismjs/components/prism-javascript';
import 'prismjs/components/prism-json';
import 'prismjs/components/prism-yaml';
import { Info, Search, Palette, Plus, Trash2, Check, User, Users, Mail } from 'lucide-react';
import { useTheme } from '@/contexts/ThemeContext';
import { COLOR_SCHEMES, type ColorScheme } from '@/lib/colorSchemes';
import { useConfig, useUpdateConfig, useCurrentUser, useTeamMembers, useInviteMember, useRemoveMember } from '@/api/hooks';
import type { ConfigEntry } from '@/api/types';
import { useToast } from '@/contexts/ToastContext';
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

- **Agentic Scan** (\`vigolium agent\`) — AI-driven scanning powered by Claude, Gemini, or OpenCode. The agent autonomously plans attack strategies, selects modules, generates custom payloads, and triages results — with the native scan engine handling heavy lifting underneath. Three modes: autopilot, pipeline, and swarm.

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
- **JavaScript extensions** — custom modules and hooks via embedded JS engine (\`vigolium.http\`, \`vigolium.scan\`, \`vigolium.source\`) with session-aware HTTP APIs (login flows, cookie jars, CSRF extraction, auth testing, request sequencing)
- **Source code awareness** — link repos to hostnames for source-aware scanning with \`vigolium.source.*\` API
- **Concurrent architecture** — configurable worker pool with per-host rate limiting and hybrid in-memory/disk/Redis queue
- **HTML reports** — generate self-contained HTML reports with sortable/filterable ag-grid tables (\`--format html\`)

### Agentic Scan

- **Autonomous scanning (Autopilot)** — AI agent autonomously discovers endpoints, runs scans, and triages findings via a sandboxed terminal with command allowlisting
- **Multi-phase pipeline (Pipeline)** — fixed 7-phase workflow (source-analysis → discover → plan → scan → triage → rescan → report) where AI agents handle strategy at checkpoints while native scan phases handle heavy lifting
- **Targeted vulnerability swarm (Swarm)** — master agent analyzes inputs, selects scanner modules, generates custom JS attack extensions, executes scans, and triages results with batched execution for large input sets
- **Query mode** — single-shot prompt execution for code review, endpoint discovery, and secret detection (not a scan — simple Q&A utility)
- **Source-aware intelligence** — when \`--source\` is provided, agents analyze application source code to discover routes, understand auth flows, and identify vulnerability sinks before scanning
- **Multiple AI backends** — Claude, Gemini, OpenCode, or custom ACP-compatible agents via CLI or REST API (with SSE streaming)

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


type SettingsTab = 'profile' | 'team' | 'theme' | 'about';

export default function SettingsPage({ initialTab = 'profile' }: { initialTab?: SettingsTab }) {
  const { schemeId, setScheme } = useTheme();
  const router = useRouter();
  const [activeTab, setActiveTabState] = useState<SettingsTab>(initialTab);
  const setActiveTab = useCallback((tab: SettingsTab) => {
    setActiveTabState(tab);
    router.replace(tab === 'profile' ? '/settings' : `/settings/${tab}`, { scroll: false });
  }, [router]);
  const [filter, setFilter] = useState('');

  // ── Config state ──
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

  // ── Profile state ──
  const { data: currentUser } = useCurrentUser();

  // ── Team state ──
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

  // ── Theme state ──
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
          {(['profile', 'team', 'theme', 'about'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className="flex items-center gap-1 text-xs font-bold uppercase tracking-wide pb-1 border-b-2 transition-colors"
              style={{
                color: activeTab === tab ? 'var(--v-accent)' : 'var(--v-text-muted)',
                borderColor: activeTab === tab ? 'var(--v-accent)' : 'transparent',
              }}
            >
              {tab === 'profile' && <User className="w-3 h-3" />}
              {tab === 'team' && <Users className="w-3 h-3" />}
              {tab === 'theme' && <Palette className="w-3 h-3" />}
              {tab === 'about' && <Info className="w-3 h-3" />}
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>

        {activeTab === 'profile' && (
          <div>
            <div className="flex items-center gap-2 mb-4">
              <User className="w-4 h-4" style={{ color: 'var(--v-secondary)' }} />
              <h2 className="text-sm font-bold" style={{ color: 'var(--v-accent)' }}>Profile</h2>
            </div>
            {currentUser ? (
              <div className="border" style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-surface)' }}>
                <div className="grid grid-cols-[120px_1fr] text-xs">
                  <span className="px-3 py-2 font-bold uppercase" style={{ color: 'var(--v-text-muted)', borderBottom: '1px solid var(--v-border)' }}>Name</span>
                  <span className="px-3 py-2" style={{ color: 'var(--v-text)', borderBottom: '1px solid var(--v-border)' }}>{currentUser.name}</span>
                  <span className="px-3 py-2 font-bold uppercase" style={{ color: 'var(--v-text-muted)', borderBottom: '1px solid var(--v-border)' }}>Email</span>
                  <span className="px-3 py-2" style={{ color: 'var(--v-text)', borderBottom: '1px solid var(--v-border)' }}>{currentUser.email}</span>
                  <span className="px-3 py-2 font-bold uppercase" style={{ color: 'var(--v-text-muted)', borderBottom: '1px solid var(--v-border)' }}>Role</span>
                  <span className="px-3 py-2" style={{ color: 'var(--v-text)', borderBottom: '1px solid var(--v-border)' }}>{currentUser.role}</span>
                  {currentUser.organization && (
                    <>
                      <span className="px-3 py-2 font-bold uppercase" style={{ color: 'var(--v-text-muted)', borderBottom: '1px solid var(--v-border)' }}>Organization</span>
                      <span className="px-3 py-2" style={{ color: 'var(--v-text)', borderBottom: '1px solid var(--v-border)' }}>{currentUser.organization.name}</span>
                    </>
                  )}
                  <span className="px-3 py-2 font-bold uppercase" style={{ color: 'var(--v-text-muted)' }}>Credits</span>
                  <span className="px-3 py-2 font-bold" style={{ color: 'var(--v-accent)' }}>{(currentUser.credits ?? 0).toLocaleString()}</span>
                </div>
              </div>
            ) : (
              <p className="text-xs" style={{ color: 'var(--v-text-muted)' }}>Not signed in</p>
            )}
          </div>
        )}

        {activeTab === 'team' && (
          <div className="max-w-4xl space-y-4">
            <div className="flex items-center gap-2 mb-2">
              <Users className="w-4 h-4" style={{ color: 'var(--v-secondary)' }} />
              <h2 className="text-sm font-bold" style={{ color: 'var(--v-accent)' }}>
                Team{currentUser?.organization ? ` — ${currentUser.organization.name}` : ''}
              </h2>
            </div>

            {/* Invite */}
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

            {/* Members */}
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
          </div>
        )}
      </div>
    </PageShell>
  );
}
