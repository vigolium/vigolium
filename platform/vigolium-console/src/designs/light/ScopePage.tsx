'use client';

import { useState, useMemo } from 'react';
import { useConfig, useUpdateConfig } from '@/api/hooks';
import type { ConfigEntry } from '@/api/types';
import { useToast } from '@/contexts/ToastContext';
import PageShell from './PageShell';

export default function ScopePage() {
  const { data: configData } = useConfig('scope');
  const updateConfig = useUpdateConfig();
  const { toast } = useToast();
  const [editingKey, setEditingKey] = useState<string | null>(null);
  const [editValue, setEditValue] = useState('');
  const [collapsedSections, setCollapsedSections] = useState<Set<string>>(new Set());
  const [activeTag, setActiveTag] = useState<string | null>(null);
  const [search, setSearch] = useState('');

  const toggleSection = (key: string) => {
    setCollapsedSections((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const entries = configData?.entries ?? [];

  /** Group scope entries by category (middle segment: host, path, status_code, …), filtered by search */
  const grouped = useMemo(() => {
    const q = search.toLowerCase();
    const groups: Record<string, ConfigEntry[]> = {};
    for (const entry of entries) {
      if (q && !entry.key.toLowerCase().includes(q) && !entry.value.toLowerCase().includes(q)) continue;
      const parts = entry.key.split('.');
      const category = parts.length >= 3 ? parts.slice(1, -1).join('.') : parts[1] || 'general';
      if (!groups[category]) groups[category] = [];
      groups[category].push(entry);
    }
    return groups;
  }, [entries, search]);

  const startEdit = (entry: ConfigEntry) => {
    setEditingKey(entry.key);
    setEditValue(entry.value);
  };

  const saveEdit = () => {
    if (editingKey) {
      updateConfig.mutate([{ key: editingKey, value: editValue }], {
        onSuccess: () => toast('scope updated', 'success'),
        onError: () => toast('error updating scope', 'error'),
      });
      setEditingKey(null);
    }
  };

  return (
    <PageShell>
      <div className="border border-[#bbc3c4] bg-[#f6edda] overflow-hidden">
        <div className="px-3 py-1.5 border-b border-[#bbc3c4] flex items-center justify-between">
          <span className="text-[#0078c8] text-xs font-bold">SCOPE</span>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="filter..."
            className="bg-[#f6edda] border border-[#bbc3c4] text-[#005661] text-xs px-2 py-0.5 w-40 focus:outline-none focus:border-[#0078c8]/50"
          />
        </div>

        {Object.keys(grouped).length > 0 && (
          <div className="px-3 py-1.5 border-b border-[#bbc3c4] flex items-center gap-1.5 overflow-x-auto">
            <button
              onClick={() => setActiveTag(null)}
              className={`shrink-0 px-1.5 py-0.5 text-[10px] font-bold uppercase border transition-colors ${
                activeTag === null
                  ? 'border-[#0078c8]/50 text-[#0078c8] bg-[#0078c8]/10'
                  : 'border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]'
              }`}
            >
              ALL
            </button>
            {Object.keys(grouped).map((tag) => (
              <button
                key={tag}
                onClick={() => setActiveTag(activeTag === tag ? null : tag)}
                className={`shrink-0 px-1.5 py-0.5 text-[10px] font-bold uppercase border transition-colors ${
                  activeTag === tag
                    ? 'border-[#0078c8]/50 text-[#0078c8] bg-[#0078c8]/10'
                    : 'border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]'
                }`}
              >
                {tag}
              </button>
            ))}
          </div>
        )}

        <div className="overflow-y-auto" style={{ maxHeight: 'calc(100vh - 240px)' }}>
          {Object.entries(grouped).filter(([cat]) => !activeTag || cat === activeTag).map(([cat, items]) => {
            const collapsed = collapsedSections.has(cat);
            return (
            <div key={cat}>
              <button
                onClick={() => toggleSection(cat)}
                className="w-full px-3 py-1 bg-[#ede4d1] text-[#0078c8] text-[10px] font-bold uppercase border-b border-[#bbc3c4] flex items-center gap-1 hover:bg-[#bbc3c4] transition-colors"
              >
                <span>{collapsed ? '\u25b8' : '\u25be'}</span> [{cat}]
                <span className="text-[#708e8e] ml-auto font-normal">{items.length}</span>
              </button>
              {!collapsed && <div className="divide-y divide-[#d4e8e2]">
                {items.map((entry) => (
                  <div key={entry.key} className="px-3 py-1 hover:bg-[#ede4d1] transition-colors text-xs flex items-center justify-between gap-2">
                    <span className="text-[#708e8e] shrink-0 w-[280px] truncate">{entry.key}</span>
                    {editingKey === entry.key ? (
                      <div className="flex items-center gap-1 flex-1">
                        <input
                          type="text"
                          value={editValue}
                          onChange={(e) => setEditValue(e.target.value)}
                          onKeyDown={(e) => e.key === 'Enter' && saveEdit()}
                          className="bg-[#f6edda] border border-[#0078c8]/50 text-[#005661] text-xs px-1.5 py-0.5 flex-1 focus:outline-none"
                          autoFocus
                        />
                        <button onClick={saveEdit} className="text-[#00b368] hover:text-[#00b368]/80 px-1">[ok]</button>
                        <button onClick={() => setEditingKey(null)} className="text-[#e34e1c] hover:text-[#e34e1c]/80 px-1">[x]</button>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2 flex-1 min-w-0">
                        <span className="text-[#005661] truncate flex-1">{entry.value}</span>
                        <button
                          onClick={() => startEdit(entry)}
                          className="text-[#708e8e] hover:text-[#0078c8] text-[10px] shrink-0"
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
          {entries.length === 0 && (
            <div className="px-3 py-4 text-[#bbc3c4] text-xs">loading scope...</div>
          )}
        </div>
      </div>
    </PageShell>
  );
}
