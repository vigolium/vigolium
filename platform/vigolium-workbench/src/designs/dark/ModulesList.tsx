'use client';

import { useState, useMemo } from 'react';
import { useModules } from '@/api/hooks';
import { SEVERITY_COLORS, CONFIDENCE_COLORS } from './theme';

export default function ModulesList() {
  const [tab, setTab] = useState<'active' | 'passive'>('active');
  const [search, setSearch] = useState('');
  const { data: modules } = useModules();

  const filtered = useMemo(() => {
    if (!modules) return [];
    return modules
      .filter((m) => m.type === tab)
      .filter((m) => {
        if (!search) return true;
        const q = search.toLowerCase();
        return m.name.toLowerCase().includes(q) || m.id.toLowerCase().includes(q);
      });
  }, [modules, tab, search]);

  return (
    <div className="border border-[#2e2b26] bg-[#1c1b19] overflow-hidden">
      <div className="px-3 py-1.5 border-b border-[#2e2b26] flex items-center justify-between flex-wrap gap-2">
        <span className="text-[#7fd962] text-xs font-bold">MODULES</span>
        <div className="flex items-center gap-2 text-xs">
          <div className="flex border border-[#2e2b26]">
            <button
              onClick={() => setTab('active')}
              className={`px-2 py-0.5 text-xs transition-colors ${
                tab === 'active'
                  ? 'text-[#7fd962] bg-[#7fd962]/10'
                  : 'text-[#918175] hover:text-[#fce8c3]'
              }`}
            >
              active
            </button>
            <button
              onClick={() => setTab('passive')}
              className={`px-2 py-0.5 text-xs transition-colors ${
                tab === 'passive'
                  ? 'text-[#7fd962] bg-[#7fd962]/10'
                  : 'text-[#918175] hover:text-[#fce8c3]'
              }`}
            >
              passive
            </button>
          </div>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="search..."
            className="bg-[#1c1b19] border border-[#2e2b26] text-[#fce8c3] text-xs px-2 py-0.5 w-32 focus:outline-none focus:border-[#7fd962]/50"
          />
        </div>
      </div>

      <div className="max-h-[300px] overflow-y-auto">
        {filtered.length === 0 ? (
          <div className="px-3 py-4 text-[#403d38] text-xs">no modules found</div>
        ) : (
          <div className="divide-y divide-[#272520]">
            {filtered.map((mod) => (
              <div
                key={mod.id}
                className="px-3 py-1 hover:bg-[#272520] transition-colors flex items-center justify-between gap-2 text-xs"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <span className="text-[#918175] shrink-0 w-[200px] truncate">{mod.id}</span>
                  <span className="text-[#baa67f] truncate">{mod.short_description || mod.name}</span>
                  {mod.tags && mod.tags.length > 0 && (
                    <span className="flex items-center gap-1 shrink-0">
                      {mod.tags.slice(0, 3).map((tag) => (
                        <span key={tag} className="text-[9px] px-1 py-0 bg-[#272520] border border-[#2e2b26] text-[#68a8e4]">{tag}</span>
                      ))}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  {mod.scan_scope && (
                    <span className="text-[10px] text-[#403d38]">
                      {mod.scan_scope.map((s) => s.replace('PER_', '')).join(', ')}
                    </span>
                  )}
                  <span
                    className="text-[10px] font-bold uppercase w-[60px] text-right"
                    style={{ color: CONFIDENCE_COLORS[mod.confidence] || '#918175' }}
                  >
                    {mod.confidence}
                  </span>
                  <span
                    className="text-[10px] font-bold uppercase w-[52px] text-right"
                    style={{ color: SEVERITY_COLORS[mod.severity] || '#918175' }}
                  >
                    {mod.severity}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
