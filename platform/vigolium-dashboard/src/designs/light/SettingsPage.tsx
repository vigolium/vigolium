'use client';

import { useState, useMemo } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import Prism from 'prismjs';
import 'prismjs/components/prism-markdown';
import 'prismjs/components/prism-bash';
import 'prismjs/components/prism-javascript';
import 'prismjs/components/prism-json';
import 'prismjs/components/prism-yaml';
import { Info, Search, Settings, Palette } from 'lucide-react';
import { useTheme } from '@/contexts/ThemeContext';
import { COLOR_SCHEMES, type ColorScheme } from '@/lib/colorSchemes';
import { useConfig, useUpdateConfig } from '@/api/hooks';
import type { ConfigEntry } from '@/api/types';
import { useToast } from '@/contexts/ToastContext';
import PageShell from './PageShell';

const ABOUT_CONTENT = `Vigolium - High-fidelity vulnerability scanner fusing agentic AI with native speed, modularity, and precision.

It scans web applications for reflected XSS, SQL injection, LFI, SSTI, CRLF injection, CSRF, IDOR, NoSQL injection, open redirects, command injection, path traversal, SAML/XXE, GraphQL issues, file upload flaws, default credentials, CMS vulnerabilities (WordPress, Drupal, Joomla), Firebase misconfigurations, cloud storage security, PHP/ASP.NET framework issues, JS framework security (Next.js, Nuxt, Remix), and more — including blind vulnerabilities via out-of-band (OAST) callbacks.

It operates as a CLI scanner, an API server with traffic ingestion, or a standalone ingestor client. Vigolium also integrates with AI coding agents (Claude, Gemini, OpenCode) for automated security code review, endpoint discovery, and secret detection.

## Key Features

- **149 scanner modules** — 89 active (fuzzing) and 60 passive (pattern matching) modules covering OWASP Top 10 and beyond
- **Out-of-band testing (OAST)** — detect blind vulnerabilities (blind XSS, SSRF, command injection) via interactsh callback URLs with automatic payload correlation
- **Value-aware mutation** — classify parameter values by semantic type (integer, UUID, JWT, email, etc.) and generate intelligent mutations per intent (neighbor, boundary, escalation)
- **Multi-phase pipeline** — external harvesting, content discovery, SPA crawling, and audit controlled by strategy presets
- **Scanning profiles** — bundle strategy, pace, scope, and module config into a single YAML file (\`--scanning-profile\`)
- **Multiple input formats** — URLs, OpenAPI/Swagger, Postman, Burp Suite, cURL, Nuclei JSONL, CrawlerX
- **API server mode** — REST API with Swagger UI, multi-format ingestion, transparent HTTP proxy, OpenAI-compatible agent endpoint
- **Browser-based spider** — Chromium-driven crawler (Spitolas) with SPA support, form filling, and JS analysis
- **Content discovery** — adaptive directory/file enumeration engine (Deparos) with soft-404 detection
- **Header injection** — automatic fuzzing of existing and synthetic headers (X-Forwarded-For, X-Forwarded-Host, True-Client-IP, Referer)
- **Multi-session authentication** — inline sessions (\`--session\`), session files (\`--session-file\`), or full auth configs (\`--auth-config\`) with login flows, token extraction, and IDOR/BOLA testing
- **JavaScript extensions** — custom modules and hooks via embedded JS engine (\`vigolium.http\`, \`vigolium.scan\`, \`vigolium.source\`) with session-aware HTTP APIs (login flows, cookie jars, CSRF extraction, auth testing, request sequencing)
- **Source code awareness** — link repos to hostnames for source-aware scanning with \`vigolium.source.*\` API
- **Concurrent architecture** — configurable worker pool with per-host rate limiting and hybrid in-memory/disk/Redis queue
- **AI agent integration** — run Claude, Gemini, OpenCode, or custom AI agents for security code review, endpoint discovery, and secret detection via CLI or REST API (with SSE streaming). Four modes: query (single-shot), autopilot (autonomous sandboxed scanning), pipeline (multi-phase AI-guided assessment), and swarm (targeted vulnerability hunting with module selection and custom JS extension generation)
- **HTML reports** — generate self-contained HTML reports with sortable/filterable ag-grid tables (\`--format html\`)

## License

Vigolium is made with \u2665 by [@j3ssie](https://twitter.com/j3ssie) & [@theblackturtle](https://github.com/theblackturtle).`;

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

export default function SettingsPage() {
  const { schemeId, setScheme } = useTheme();
  const [activeTab, setActiveTab] = useState<'config' | 'theme' | 'about'>('config');
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
          {(['config', 'theme', 'about'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className="flex items-center gap-1 text-xs font-bold uppercase tracking-wide pb-1 border-b-2 transition-colors"
              style={{
                color: activeTab === tab ? 'var(--v-accent)' : 'var(--v-text-muted)',
                borderColor: activeTab === tab ? 'var(--v-accent)' : 'transparent',
              }}
            >
              {tab === 'config' && <Settings className="w-3 h-3" />}
              {tab === 'theme' && <Palette className="w-3 h-3" />}
              {tab === 'about' && <Info className="w-3 h-3" />}
              {tab === 'config' ? 'Config' : tab === 'theme' ? 'Theme' : 'About'}
            </button>
          ))}
        </div>

        {activeTab === 'config' && (
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
            <div className="prose-v-settings overflow-auto max-h-[calc(100vh-200px)] text-justify">
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
