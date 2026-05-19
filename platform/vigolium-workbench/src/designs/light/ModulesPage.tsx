'use client';

import { useState, useMemo, useCallback } from 'react';
import ReactMarkdown from 'react-markdown';
import { Zap, Eye, Search, RefreshCw } from 'lucide-react';
import { useModules } from '@/api/hooks';
import { SEVERITY_COLORS, CONFIDENCE_COLORS } from './theme';
import PageShell from './PageShell';
import { TableSkeleton } from '@/components/shared/Skeletons';

type SortField = 'id' | 'name' | 'type' | 'scope' | 'confidence' | 'severity';
type SortDir = 'asc' | 'desc';

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, suspect: 5 };
const CONFIDENCE_ORDER: Record<string, number> = { certain: 0, firm: 1, tentative: 2 };

export default function ModulesPage() {
  const [typeFilter, setTypeFilter] = useState<'all' | 'active' | 'passive'>('all');
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [sortField, setSortField] = useState<SortField>('id');
  const [sortDir, setSortDir] = useState<SortDir>('asc');
  const { data: modules, refetch, isFetching } = useModules();

  const toggleSort = useCallback((field: SortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDir('asc');
    }
  }, [sortField]);

  const sorted = useMemo(() => {
    if (!modules) return [];
    const list = modules
      .filter((m) => typeFilter === 'all' || m.type === typeFilter)
      .filter((m) => {
        if (!search) return true;
        const q = search.toLowerCase();
        return m.name.toLowerCase().includes(q) || m.id.toLowerCase().includes(q) || m.description.toLowerCase().includes(q);
      });

    return [...list].sort((a, b) => {
      let cmp = 0;
      switch (sortField) {
        case 'id':
          cmp = a.id.localeCompare(b.id);
          break;
        case 'name':
          cmp = a.name.localeCompare(b.name);
          break;
        case 'type':
          cmp = a.type.localeCompare(b.type);
          break;
        case 'scope':
          cmp = (a.scan_scope?.join(',') || '').localeCompare(b.scan_scope?.join(',') || '');
          break;
        case 'confidence':
          cmp = (CONFIDENCE_ORDER[a.confidence] ?? 99) - (CONFIDENCE_ORDER[b.confidence] ?? 99);
          break;
        case 'severity':
          cmp = (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
          break;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
  }, [modules, typeFilter, search, sortField, sortDir]);

  const sortIndicator = (field: SortField) =>
    sortField === field ? (sortDir === 'asc' ? ' ▲' : ' ▼') : '';

  return (
    <PageShell>
      <div className="border border-[#bbc3c4] bg-[#f6edda] overflow-hidden">
        <div className="px-3 py-1.5 border-b border-[#bbc3c4] flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-1.5">
            <span className="text-[#0078c8] text-xs font-bold">MODULES</span>
            <button onClick={() => refetch()} className="text-[#708e8e] hover:text-[#0078c8] transition-colors" title="Refresh">
              <RefreshCw className={`w-3 h-3 ${isFetching ? 'animate-spin' : ''}`} />
            </button>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <div className="flex border border-[#bbc3c4]">
              <button
                onClick={() => setTypeFilter('all')}
                className={`px-2 py-0.5 text-xs transition-colors ${
                  typeFilter === 'all'
                    ? 'text-[#0078c8] bg-[#0078c8]/10'
                    : 'text-[#708e8e] hover:text-[#005661]'
                }`}
              >
                all
              </button>
              <button
                onClick={() => setTypeFilter('active')}
                className={`px-2 py-0.5 text-xs transition-colors flex items-center gap-1 ${
                  typeFilter === 'active'
                    ? 'text-[#0078c8] bg-[#0078c8]/10'
                    : 'text-[#708e8e] hover:text-[#005661]'
                }`}
              >
                <Zap className="w-3 h-3" />
                active
              </button>
              <button
                onClick={() => setTypeFilter('passive')}
                className={`px-2 py-0.5 text-xs transition-colors flex items-center gap-1 ${
                  typeFilter === 'passive'
                    ? 'text-[#0078c8] bg-[#0078c8]/10'
                    : 'text-[#708e8e] hover:text-[#005661]'
                }`}
              >
                <Eye className="w-3 h-3" />
                passive
              </button>
            </div>
            <span className="text-[#bbc3c4]">|</span>
            <span className="text-[#708e8e]">{sorted.length} modules</span>
            <div className="flex items-center border border-[#bbc3c4] bg-[#f6edda] focus-within:border-[#0078c8]/50">
              <Search className="w-3 h-3 text-[#708e8e] ml-1.5 shrink-0" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="search..."
                className="bg-transparent text-[#005661] text-xs px-1.5 py-0.5 w-40 focus:outline-none"
              />
            </div>
          </div>
        </div>

        {/* Column headers */}
        <div className="px-3 py-1 border-b border-[#bbc3c4] flex items-center justify-between gap-2 text-[11px] text-[#708e8e] select-none">
          <div className="flex items-center gap-3 min-w-0">
            <span className="shrink-0 w-[24px]" />
            <button onClick={() => toggleSort('id')} className="shrink-0 w-[220px] text-left hover:text-[#005661] transition-colors">
              ID{sortIndicator('id')}
            </button>
            <button onClick={() => toggleSort('name')} className="text-left hover:text-[#005661] transition-colors truncate">
              NAME{sortIndicator('name')}
            </button>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            <button onClick={() => toggleSort('type')} className="w-[50px] text-right hover:text-[#005661] transition-colors">
              TYPE{sortIndicator('type')}
            </button>
            <button onClick={() => toggleSort('scope')} className="w-[120px] text-right hover:text-[#005661] transition-colors">
              SCOPE{sortIndicator('scope')}
            </button>
            <button onClick={() => toggleSort('confidence')} className="w-[60px] text-right hover:text-[#005661] transition-colors">
              CONFIDENCE{sortIndicator('confidence')}
            </button>
            <button onClick={() => toggleSort('severity')} className="w-[52px] text-right hover:text-[#005661] transition-colors">
              SEVERITY{sortIndicator('severity')}
            </button>
          </div>
        </div>

        <div className="overflow-y-auto" style={{ maxHeight: 'calc(100vh - 200px)' }}>
          {!modules ? (
            <TableSkeleton
              rows={18}
              showHeader={false}
              columns={['24px', '220px', '40%', '50px', '120px', '60px', '52px']}
            />
          ) : sorted.length === 0 ? (
            <div className="px-3 py-4 text-[#8a9e9e] text-xs">no modules found</div>
          ) : (
            <div className="divide-y divide-[#d4e8e2]">
              {sorted.map((mod) => (
                <div key={mod.id}>
                  <div
                    onClick={() => setExpanded(expanded === mod.id ? null : mod.id)}
                    className="px-3 py-1.5 hover:bg-[#ede4d1] transition-colors flex items-center justify-between gap-2 text-xs cursor-pointer"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <span className="text-[#8a9e9e] shrink-0">{expanded === mod.id ? '[-]' : '[+]'}</span>
                      <span className="text-[#708e8e] shrink-0 w-[220px] truncate">{mod.id}</span>
                      <span className="text-[#004d57] truncate">{mod.name}</span>
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      <span className={`text-[11px] font-bold uppercase w-[50px] text-right ${mod.type === 'active' ? 'text-[#0078c8]' : 'text-[#708e8e]'}`}>
                        {mod.type}
                      </span>
                      <span className="text-[11px] text-[#5a7a7a] w-[120px] text-right truncate">
                        {mod.scan_scope?.map((s) => s.replace('PER_', '')).join(', ') || '—'}
                      </span>
                      <span
                        className="text-[11px] font-bold uppercase w-[60px] text-right"
                        style={{ color: CONFIDENCE_COLORS[mod.confidence] || '#708e8e' }}
                      >
                        {mod.confidence}
                      </span>
                      <span
                        className="text-[11px] font-bold uppercase w-[52px] text-right"
                        style={{ color: SEVERITY_COLORS[mod.severity] || '#708e8e' }}
                      >
                        {mod.severity}
                      </span>
                    </div>
                  </div>
                  {expanded === mod.id && (
                    <div className="px-3 pb-3 pl-12 text-xs space-y-2 bg-[#ede4d1]/50">
                      {/* Metadata row */}
                      <div className="flex items-center gap-4 text-[#708e8e]">
                        <span>type: <span className="text-[#004d57]">{mod.type}</span></span>
                        <span>confidence: <span style={{ color: CONFIDENCE_COLORS[mod.confidence] || '#004d57' }}>{mod.confidence}</span></span>
                        <span>severity: <span style={{ color: SEVERITY_COLORS[mod.severity] || '#004d57' }}>{mod.severity}</span></span>
                        {mod.scan_scope && <span>scope: <span className="text-[#004d57]">{mod.scan_scope.join(', ')}</span></span>}
                      </div>
                      {mod.tags && mod.tags.length > 0 && (
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="text-[#708e8e]">tags:</span>
                          {mod.tags.map((tag) => (
                            <span key={tag} className="text-[10px] px-1.5 py-0.5 bg-[#f6edda] border border-[#bbc3c4] text-[#0078c8]">{tag}</span>
                          ))}
                        </div>
                      )}
                      {mod.short_description && (
                        <div className="text-[#708e8e]">
                          <span className="text-[#0078c8]">short: </span>
                          <span className="text-[#004d57]">{mod.short_description}</span>
                        </div>
                      )}
                      {mod.confirmation_criteria && (
                        <div className="text-[#708e8e]">
                          <span className="text-[#0078c8]">criteria: </span>
                          <span className="text-[#004d57]">{mod.confirmation_criteria}</span>
                        </div>
                      )}
                      {/* Markdown description */}
                      {mod.description && (
                        <div className="border border-[#bbc3c4] bg-[#f6edda] p-3 prose-light-module">
                          <ReactMarkdown>{mod.description}</ReactMarkdown>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </PageShell>
  );
}
