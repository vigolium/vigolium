'use client';

import { useState, useMemo } from 'react';
import { useConfig, useUpdateConfig } from '@/api/hooks';
import type { ConfigEntry } from '@/api/types';
import { useToast } from '@/contexts/ToastContext';
import PageShell from './PageShell';

export default function ConfigPage() {
  const [filter, setFilter] = useState('');
  const { data: configData } = useConfig(filter || undefined);
  const updateConfig = useUpdateConfig();
  const { toast } = useToast();
  const [editingKey, setEditingKey] = useState<string | null>(null);
  const [editValue, setEditValue] = useState('');
  const [revealedKeys, setRevealedKeys] = useState<Set<string>>(new Set());
  const [collapsedSections, setCollapsedSections] = useState<Set<string>>(new Set());
  const [activeTag, setActiveTag] = useState<string | null>(null);

  const toggleSection = (prefix: string) => {
    setCollapsedSections((prev) => {
      const next = new Set(prev);
      if (next.has(prefix)) next.delete(prefix);
      else next.add(prefix);
      return next;
    });
  };

  const entries = configData?.entries ?? [];

  const grouped = useMemo(() => {
    const groups: Record<string, ConfigEntry[]> = {};
    for (const entry of entries) {
      const prefix = entry.key.split('.')[0] || 'general';
      if (!groups[prefix]) groups[prefix] = [];
      groups[prefix].push(entry);
    }
    return groups;
  }, [entries]);

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

  return (
    <PageShell>
      <div className="border border-[#2e2b26] bg-[#1c1b19] overflow-hidden">
        <div className="px-3 py-1.5 border-b border-[#2e2b26] flex items-center justify-between">
          <span className="text-[#7fd962] text-xs font-bold">CONFIG</span>
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="filter..."
            className="bg-[#1c1b19] border border-[#2e2b26] text-[#fce8c3] text-xs px-2 py-0.5 w-40 focus:outline-none focus:border-[#7fd962]/50"
          />
        </div>

        {Object.keys(grouped).length > 0 && (
          <div className="px-3 py-1.5 border-b border-[#2e2b26] flex items-center gap-1.5 overflow-x-auto">
            <button
              onClick={() => setActiveTag(null)}
              className={`shrink-0 px-1.5 py-0.5 text-[10px] font-bold uppercase border transition-colors ${
                activeTag === null
                  ? 'border-[#7fd962]/50 text-[#7fd962] bg-[#7fd962]/10'
                  : 'border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]'
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
                    ? 'border-[#7fd962]/50 text-[#7fd962] bg-[#7fd962]/10'
                    : 'border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]'
                }`}
              >
                {tag}
              </button>
            ))}
          </div>
        )}

        <div className="overflow-y-auto" style={{ maxHeight: 'calc(100vh - 240px)' }}>
          {Object.entries(grouped).filter(([prefix]) => !activeTag || prefix === activeTag).map(([prefix, items]) => {
            const collapsed = collapsedSections.has(prefix);
            return (
            <div key={prefix}>
              <button
                onClick={() => toggleSection(prefix)}
                className="w-full px-3 py-1 bg-[#272520] text-[#7fd962] text-[10px] font-bold uppercase border-b border-[#2e2b26] flex items-center gap-1 hover:bg-[#2e2b26] transition-colors"
              >
                <span>{collapsed ? '\u25b8' : '\u25be'}</span> [{prefix}]
                <span className="text-[#918175] ml-auto font-normal">{items.length}</span>
              </button>
              {!collapsed && <div className="divide-y divide-[#272520]">
                {items.map((entry) => (
                  <div key={entry.key} className="px-3 py-1 hover:bg-[#272520] transition-colors text-xs flex items-center justify-between gap-2">
                    <span className="text-[#918175] shrink-0 w-[280px] truncate">{entry.key}</span>
                    {editingKey === entry.key ? (
                      <div className="flex items-center gap-1 flex-1">
                        <input
                          type="text"
                          value={editValue}
                          onChange={(e) => setEditValue(e.target.value)}
                          onKeyDown={(e) => e.key === 'Enter' && saveEdit()}
                          className="bg-[#1c1b19] border border-[#7fd962]/50 text-[#fce8c3] text-xs px-1.5 py-0.5 flex-1 focus:outline-none"
                          autoFocus
                        />
                        <button onClick={saveEdit} className="text-[#98bc37] hover:text-[#98bc37]/80 px-1">[ok]</button>
                        <button onClick={() => setEditingKey(null)} className="text-[#ef2f27] hover:text-[#ef2f27]/80 px-1">[x]</button>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2 flex-1 min-w-0">
                        <span className="text-[#fce8c3] truncate flex-1">
                          {entry.sensitive && !revealedKeys.has(entry.key)
                            ? '********'
                            : entry.value}
                        </span>
                        {entry.sensitive && (
                          <button
                            onClick={() => toggleReveal(entry.key)}
                            className="text-[#918175] hover:text-[#fce8c3] text-[10px] shrink-0"
                          >
                            {revealedKeys.has(entry.key) ? '[hide]' : '[show]'}
                          </button>
                        )}
                        <button
                          onClick={() => startEdit(entry)}
                          className="text-[#918175] hover:text-[#7fd962] text-[10px] shrink-0"
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
            <div className="px-3 py-4 text-[#403d38] text-xs">no config entries</div>
          )}
        </div>
      </div>
    </PageShell>
  );
}
