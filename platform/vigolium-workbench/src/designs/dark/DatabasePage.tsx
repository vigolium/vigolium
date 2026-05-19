'use client';

import { useState, useMemo, useCallback, useEffect, useRef } from 'react';
import { Database, Search, RefreshCw, Trash2, Pencil, ChevronLeft, ChevronRight, X, Plus, PanelLeftClose, PanelLeftOpen, Copy, Check } from 'lucide-react';
import { useDbTables, useDbColumns, useDbRecords, useDbRecord, useDbUpdateRecord, useDbDeleteRecord, useDbCreateRecord } from '@/api/hooks';
import type { DbRecordsQueryParams } from '@/api/types';
import { useToast } from '@/contexts/ToastContext';
import PageShell from './PageShell';

const PAGE_SIZES = [25, 50, 100, 250, 500];

/* ── JSON Syntax Highlighter ──────────────────────────────────────── */

function highlightJson(json: string): React.ReactNode[] {
  const parts: React.ReactNode[] = [];
  // Match strings, numbers, booleans, null, and property keys
  const regex = /("(?:\\.|[^"\\])*"\s*:)|("(?:\\.|[^"\\])*")|((?:-?\d+\.?\d*(?:[eE][+-]?\d+)?))|(\btrue\b|\bfalse\b)|(\bnull\b)/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  let i = 0;

  while ((match = regex.exec(json)) !== null) {
    // Text before this match (punctuation: braces, commas, colons)
    if (match.index > lastIndex) {
      parts.push(<span key={`p${i++}`} style={{ color: 'var(--v-text-muted)' }}>{json.slice(lastIndex, match.index)}</span>);
    }
    if (match[1]) {
      // Property key (includes the colon)
      const keyPart = match[1];
      const colonIdx = keyPart.lastIndexOf(':');
      parts.push(<span key={`k${i++}`} style={{ color: 'var(--v-secondary)' }}>{keyPart.slice(0, colonIdx)}</span>);
      parts.push(<span key={`c${i++}`} style={{ color: 'var(--v-text-muted)' }}>{keyPart.slice(colonIdx)}</span>);
    } else if (match[2]) {
      // String value
      parts.push(<span key={`s${i++}`} style={{ color: 'var(--v-success)' }}>{match[2]}</span>);
    } else if (match[3]) {
      // Number
      parts.push(<span key={`n${i++}`} style={{ color: 'var(--v-tertiary)' }}>{match[3]}</span>);
    } else if (match[4]) {
      // Boolean
      parts.push(<span key={`b${i++}`} style={{ color: 'var(--v-tertiary)' }}>{match[4]}</span>);
    } else if (match[5]) {
      // Null
      parts.push(<span key={`u${i++}`} style={{ color: 'var(--v-error)' }}>{match[5]}</span>);
    }
    lastIndex = regex.lastIndex;
  }
  // Trailing text
  if (lastIndex < json.length) {
    parts.push(<span key={`e${i++}`} style={{ color: 'var(--v-text-muted)' }}>{json.slice(lastIndex)}</span>);
  }
  return parts;
}

/* ── Themed Page-Size Dropdown ────────────────────────────────────── */

function PageSizeDropdown({ value, onChange }: { value: number; onChange: (v: number) => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(o => !o)}
        className="border text-xs px-2 py-0.5 flex items-center gap-1 transition-colors"
        style={{ borderColor: 'var(--v-border)', color: 'var(--v-text-muted)', backgroundColor: 'var(--v-bg)' }}
      >
        {value}
        <span className="text-[8px]">{'\u25be'}</span>
      </button>
      {open && (
        <div className="absolute top-full right-0 mt-0.5 border z-50 min-w-full" style={{ backgroundColor: 'var(--v-bg)', borderColor: 'var(--v-border)' }}>
          {PAGE_SIZES.map(s => (
            <button
              key={s}
              onClick={() => { onChange(s); setOpen(false); }}
              className="block w-full text-right text-xs px-2 py-0.5 transition-colors v-dropdown-item"
              style={{ color: s === value ? 'var(--v-accent)' : 'var(--v-text-muted)' }}
            >
              {s}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/* ── Record Detail Panel ──────────────────────────────────────────── */

function RecordDetailPanel({
  table,
  recordId,
  columns,
  onClose,
}: {
  table: string;
  recordId: string;
  columns: { name: string; type: string; nullable: string }[];
  onClose: () => void;
}) {
  const { data, isLoading } = useDbRecord(table, recordId);
  const record = data?.record;
  const [tab, setTab] = useState<'fields' | 'json'>('json');
  const [copied, setCopied] = useState(false);

  const copyJson = () => {
    if (!record) return;
    navigator.clipboard.writeText(JSON.stringify(record, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="border-l flex flex-col h-full overflow-hidden" style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-bg)' }}>
      {/* Header */}
      <div className="px-3 py-1.5 border-b flex items-center justify-between shrink-0" style={{ borderColor: 'var(--v-border)' }}>
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-xs font-bold truncate" style={{ color: 'var(--v-accent)' }}>RECORD {recordId}</span>
          <button onClick={copyJson} title="Copy JSON" style={{ color: 'var(--v-text-muted)' }}>
            {copied ? <Check className="w-3 h-3" style={{ color: 'var(--v-success)' }} /> : <Copy className="w-3 h-3" />}
          </button>
        </div>
        <button onClick={onClose} style={{ color: 'var(--v-text-muted)' }} title="Close">
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Tabs */}
      <div className="flex items-center border-b shrink-0" style={{ borderColor: 'var(--v-border)' }}>
        {(['fields', 'json'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className="px-3 py-1 text-xs font-bold uppercase tracking-wide border-b-2 transition-colors"
            style={{
              color: tab === t ? 'var(--v-accent)' : 'var(--v-text-muted)',
              borderColor: tab === t ? 'var(--v-accent)' : 'transparent',
            }}
          >
            {t}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        {isLoading ? (
          <div className="px-3 py-4 text-xs" style={{ color: 'var(--v-text-muted)' }}>loading...</div>
        ) : !record ? (
          <div className="px-3 py-4 text-xs" style={{ color: 'var(--v-text-muted)' }}>record not found</div>
        ) : tab === 'fields' ? (
          <div className="divide-y" style={{ borderColor: 'var(--v-border)' }}>
            {(columns.length > 0 ? columns.map(c => c.name) : Object.keys(record)).map((col) => {
              const colMeta = columns.find(c => c.name === col);
              const val = record[col];
              const isNull = val === null || val === undefined;
              return (
                <div key={col} className="px-3 py-1.5" style={{ borderColor: 'var(--v-border)' }}>
                  <div className="flex items-center gap-1.5 mb-0.5">
                    <span className="text-[11px] font-bold" style={{ color: 'var(--v-text-muted)' }}>{col}</span>
                    {colMeta && (
                      <span className="text-[9px] px-1 border" style={{ color: 'var(--v-border)', borderColor: 'var(--v-border)' }}>
                        {colMeta.type}
                      </span>
                    )}
                  </div>
                  <div className="text-xs break-all whitespace-pre-wrap" style={{ color: isNull ? 'var(--v-border)' : 'var(--v-text)' }}>
                    {isNull ? 'null' : typeof val === 'object' ? JSON.stringify(val, null, 2) : String(val)}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="p-3">
            <pre className="text-xs overflow-x-auto whitespace-pre-wrap break-all">
              {highlightJson(JSON.stringify(record, null, 2))}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}

/* ── Main Page ────────────────────────────────────────────────────── */

export default function DatabasePage() {
  const { toast } = useToast();

  // Table selection
  const [selectedTable, setSelectedTable] = useState<string | null>(null);
  const { data: tablesData, refetch: refetchTables, isFetching: fetchingTables } = useDbTables();

  // Column metadata
  const { data: columnsData } = useDbColumns(selectedTable);
  const allColumns = columnsData?.columns ?? [];
  const primaryKey = columnsData?.primary_key ?? [];

  // Sidebar collapsed
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  // Column visibility
  const [hiddenColumns, setHiddenColumns] = useState<Set<string>>(new Set());
  const [showColumnChooser, setShowColumnChooser] = useState(false);

  // Query params
  const [limit, setLimit] = useState(100);
  const [offset, setOffset] = useState(0);
  const [sortCol, setSortCol] = useState('');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [search, setSearch] = useState('');
  const [searchInput, setSearchInput] = useState('');

  const queryParams = useMemo<DbRecordsQueryParams>(() => {
    const p: DbRecordsQueryParams = { limit, offset, truncate: 200 };
    if (sortCol) { p.sort = sortCol; p.order = sortOrder; }
    if (search) p.search = search;
    return p;
  }, [limit, offset, sortCol, sortOrder, search]);

  const { data: recordsData, refetch: refetchRecords, isFetching: fetchingRecords } = useDbRecords(selectedTable, queryParams);
  const records = recordsData?.records ?? [];
  const totalRecords = recordsData?.total ?? 0;

  // Visible columns
  const visibleColumns = useMemo(() => {
    if (!allColumns.length) return recordsData?.columns ?? [];
    return allColumns.map(c => c.name).filter(c => !hiddenColumns.has(c));
  }, [allColumns, hiddenColumns, recordsData?.columns]);

  // Editing state
  const [editingRecord, setEditingRecord] = useState<{ id: string; data: Record<string, unknown> } | null>(null);
  const [editValues, setEditValues] = useState<Record<string, string>>({});
  const updateRecord = useDbUpdateRecord();
  const deleteRecord = useDbDeleteRecord();
  const createRecord = useDbCreateRecord();

  // Create modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createValues, setCreateValues] = useState<Record<string, string>>({});

  // Delete confirmation
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);

  // Detail panel
  const [selectedRecordId, setSelectedRecordId] = useState<string | null>(null);

  const getPrimaryKeyValue = useCallback((record: Record<string, unknown>): string => {
    if (primaryKey.length === 1) return String(record[primaryKey[0]] ?? '');
    for (const col of ['id', 'uuid', 'name']) {
      if (record[col] !== undefined) return String(record[col]);
    }
    return '';
  }, [primaryKey]);

  const selectTable = (table: string) => {
    setSelectedTable(table);
    setOffset(0);
    setSortCol('');
    setSortOrder('desc');
    setSearch('');
    setSearchInput('');
    setHiddenColumns(new Set());
    setEditingRecord(null);
    setDeleteConfirm(null);
    setSelectedRecordId(null);
  };

  const toggleSort = (col: string) => {
    if (sortCol === col) {
      setSortOrder(o => o === 'asc' ? 'desc' : 'asc');
    } else {
      setSortCol(col);
      setSortOrder('asc');
    }
    setOffset(0);
  };

  const handleSearch = () => {
    setSearch(searchInput);
    setOffset(0);
  };

  const startEdit = (record: Record<string, unknown>) => {
    const id = getPrimaryKeyValue(record);
    const values: Record<string, string> = {};
    for (const col of visibleColumns) {
      values[col] = record[col] !== null && record[col] !== undefined ? String(record[col]) : '';
    }
    setEditingRecord({ id, data: record });
    setEditValues(values);
  };

  const saveEdit = () => {
    if (!editingRecord || !selectedTable) return;
    const changes: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(editValues)) {
      if (primaryKey.includes(key)) continue;
      if (String(editingRecord.data[key] ?? '') !== val) {
        changes[key] = val;
      }
    }
    if (Object.keys(changes).length === 0) {
      setEditingRecord(null);
      return;
    }
    updateRecord.mutate({ table: selectedTable, id: editingRecord.id, data: changes }, {
      onSuccess: () => { toast('record updated', 'success'); setEditingRecord(null); refetchRecords(); },
      onError: (e) => toast(`error: ${e.message}`, 'error'),
    });
  };

  const handleDelete = (id: string) => {
    if (!selectedTable) return;
    deleteRecord.mutate({ table: selectedTable, id }, {
      onSuccess: () => {
        toast('record deleted', 'success');
        setDeleteConfirm(null);
        if (selectedRecordId === id) setSelectedRecordId(null);
        refetchRecords();
      },
      onError: (e) => toast(`error: ${e.message}`, 'error'),
    });
  };

  const handleCreate = () => {
    if (!selectedTable) return;
    const data: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(createValues)) {
      if (val !== '') data[key] = val;
    }
    createRecord.mutate({ table: selectedTable, data }, {
      onSuccess: () => { toast('record created', 'success'); setShowCreateModal(false); setCreateValues({}); refetchRecords(); },
      onError: (e) => toast(`error: ${e.message}`, 'error'),
    });
  };

  const openCreateModal = () => {
    const vals: Record<string, string> = {};
    for (const col of allColumns) {
      if (!primaryKey.includes(col.name) || allColumns.length === 0) vals[col.name] = '';
    }
    setCreateValues(vals);
    setShowCreateModal(true);
  };

  const handleRowClick = (record: Record<string, unknown>) => {
    const pkVal = getPrimaryKeyValue(record);
    setSelectedRecordId(prev => prev === pkVal ? null : pkVal);
  };

  // Escape to close detail panel
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && selectedRecordId !== null) {
        setSelectedRecordId(null);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [selectedRecordId]);

  const totalPages = Math.ceil(totalRecords / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  return (
    <PageShell>
      <div className="flex gap-0 flex-1 min-h-0">
        {/* Table list sidebar */}
        <div
          className="shrink-0 border-r overflow-y-auto transition-all"
          style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-bg)', width: sidebarCollapsed ? 36 : 224 }}
        >
          <div className="px-2 py-1.5 border-b flex items-center justify-between" style={{ borderColor: 'var(--v-border)' }}>
            {!sidebarCollapsed && (
              <div className="flex items-center gap-1.5">
                <Database className="w-3 h-3" style={{ color: 'var(--v-accent)' }} />
                <span className="text-xs font-bold" style={{ color: 'var(--v-accent)' }}>TABLES</span>
              </div>
            )}
            <div className="flex items-center gap-1">
              {!sidebarCollapsed && (
                <button onClick={() => refetchTables()} style={{ color: 'var(--v-text-muted)' }} title="Refresh">
                  <RefreshCw className={`w-3 h-3 ${fetchingTables ? 'animate-spin' : ''}`} />
                </button>
              )}
              <button onClick={() => setSidebarCollapsed(c => !c)} style={{ color: 'var(--v-text-muted)' }} title={sidebarCollapsed ? 'Expand' : 'Collapse'}>
                {sidebarCollapsed ? <PanelLeftOpen className="w-3.5 h-3.5" /> : <PanelLeftClose className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>
          {sidebarCollapsed ? (
            <div className="flex flex-col items-center pt-2 gap-1">
              <button onClick={() => setSidebarCollapsed(false)} title="Show tables" style={{ color: 'var(--v-accent)' }}>
                <Database className="w-3.5 h-3.5" />
              </button>
              <span className="text-[9px]" style={{ color: 'var(--v-text-muted)' }}>{tablesData?.total ?? 0}</span>
            </div>
          ) : (
            <div className="divide-y" style={{ borderColor: 'var(--v-border)' }}>
              {!tablesData ? (
                Array.from({ length: 12 }).map((_, i) => (
                  <div
                    key={`tbl-sk-${i}`}
                    className="w-full px-3 py-1.5 flex items-center justify-between"
                    style={{ borderColor: 'var(--v-border)' }}
                  >
                    <span className="v-skeleton inline-block h-3" style={{ width: `${50 + ((i * 17) % 30)}%` }} />
                    <span className="v-skeleton inline-block h-3 w-6 ml-2" />
                  </div>
                ))
              ) : (
                <>
                  {tablesData.tables.map((t) => (
                    <button
                      key={t.name}
                      onClick={() => selectTable(t.name)}
                      className="w-full px-3 py-1.5 text-left text-xs flex items-center justify-between transition-colors"
                      style={{
                        backgroundColor: selectedTable === t.name ? 'color-mix(in srgb, var(--v-accent) 10%, transparent)' : undefined,
                        color: selectedTable === t.name ? 'var(--v-accent)' : 'var(--v-text)',
                        borderColor: 'var(--v-border)',
                      }}
                    >
                      <span className="truncate font-medium">{t.name}</span>
                      <span className="shrink-0 ml-2 text-[10px]" style={{ color: 'var(--v-text-muted)' }}>{t.row_count.toLocaleString()}</span>
                    </button>
                  ))}
                  {tablesData.tables.length === 0 && (
                    <div className="px-3 py-4 text-xs" style={{ color: 'var(--v-text-muted)' }}>no tables</div>
                  )}
                </>
              )}
            </div>
          )}
        </div>

        {/* Main content + detail panel */}
        <div className="flex-1 flex min-w-0 overflow-hidden">
          {/* Records area */}
          <div className={`flex flex-col min-w-0 overflow-hidden transition-all ${selectedRecordId !== null ? 'w-3/5' : 'w-full'}`}>
            {!selectedTable ? (
              <div className="flex-1 flex items-center justify-center">
                <div className="text-center">
                  <Database className="w-8 h-8 mx-auto mb-2" style={{ color: 'var(--v-border)' }} />
                  <p className="text-xs" style={{ color: 'var(--v-text-muted)' }}>select a table to browse records</p>
                </div>
              </div>
            ) : (
              <>
                {/* Toolbar */}
                <div className="px-3 py-1.5 border-b flex items-center justify-between gap-2 flex-wrap shrink-0" style={{ borderColor: 'var(--v-border)' }}>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold" style={{ color: 'var(--v-accent)' }}>{selectedTable}</span>
                    <span className="text-[10px]" style={{ color: 'var(--v-text-muted)' }}>{totalRecords.toLocaleString()} rows</span>
                    <button onClick={() => refetchRecords()} style={{ color: 'var(--v-text-muted)' }} title="Refresh">
                      <RefreshCw className={`w-3 h-3 ${fetchingRecords ? 'animate-spin' : ''}`} />
                    </button>
                  </div>
                  <div className="flex items-center gap-2 text-xs">
                    {/* Search */}
                    <div className="flex items-center border focus-within:border-opacity-50" style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-bg)' }}>
                      <Search className="w-3 h-3 ml-1.5 shrink-0" style={{ color: 'var(--v-text-muted)' }} />
                      <input
                        type="text"
                        value={searchInput}
                        onChange={(e) => setSearchInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                        placeholder="search..."
                        className="bg-transparent text-xs px-1.5 py-0.5 w-40 focus:outline-none"
                        style={{ color: 'var(--v-text)' }}
                      />
                      {search && (
                        <button onClick={() => { setSearch(''); setSearchInput(''); setOffset(0); }} className="mr-1" style={{ color: 'var(--v-text-muted)' }}>
                          <X className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                    {/* Column chooser */}
                    <div className="relative">
                      <button
                        onClick={() => setShowColumnChooser(!showColumnChooser)}
                        className="px-1.5 py-0.5 text-[10px] font-bold uppercase border transition-colors"
                        style={{
                          borderColor: hiddenColumns.size > 0 ? 'color-mix(in srgb, var(--v-accent) 50%, transparent)' : 'var(--v-border)',
                          color: hiddenColumns.size > 0 ? 'var(--v-accent)' : 'var(--v-text-muted)',
                        }}
                      >
                        COLUMNS {hiddenColumns.size > 0 && `(${allColumns.length - hiddenColumns.size}/${allColumns.length})`}
                      </button>
                      {showColumnChooser && (
                        <div className="absolute right-0 top-full mt-1 z-50 border p-2 w-56 max-h-80 overflow-y-auto" style={{ backgroundColor: 'var(--v-surface)', borderColor: 'var(--v-border)' }}>
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-[10px] font-bold" style={{ color: 'var(--v-accent)' }}>Visible Columns</span>
                            <button onClick={() => setHiddenColumns(new Set())} className="text-[10px]" style={{ color: 'var(--v-text-muted)' }}>[all]</button>
                          </div>
                          {allColumns.map(col => (
                            <label key={col.name} className="flex items-center gap-1.5 py-0.5 text-[11px] cursor-pointer" style={{ color: 'var(--v-text)' }}>
                              <input
                                type="checkbox"
                                checked={!hiddenColumns.has(col.name)}
                                onChange={() => {
                                  setHiddenColumns(prev => {
                                    const next = new Set(prev);
                                    if (next.has(col.name)) next.delete(col.name);
                                    else next.add(col.name);
                                    return next;
                                  });
                                }}
                              />
                              <span className="truncate">{col.name}</span>
                              <span className="ml-auto text-[9px]" style={{ color: 'var(--v-text-muted)' }}>{col.type}</span>
                            </label>
                          ))}
                        </div>
                      )}
                    </div>
                    {/* Page size */}
                    <PageSizeDropdown value={limit} onChange={(v) => { setLimit(v); setOffset(0); }} />
                    {/* Create */}
                    <button
                      onClick={openCreateModal}
                      className="px-1.5 py-0.5 text-[10px] font-bold uppercase border flex items-center gap-1 transition-colors"
                      style={{ borderColor: 'color-mix(in srgb, var(--v-success) 50%, transparent)', color: 'var(--v-success)' }}
                    >
                      <Plus className="w-3 h-3" /> NEW
                    </button>
                  </div>
                </div>

                {/* Records table */}
                <div className="flex-1 overflow-auto">
                  <table className="w-full text-xs" style={{ borderCollapse: 'collapse' }}>
                    <thead>
                      <tr className="sticky top-0" style={{ backgroundColor: 'var(--v-surface)' }}>
                        <th className="px-2 py-1 text-left border-b whitespace-nowrap" style={{ borderColor: 'var(--v-border)', color: 'var(--v-text-muted)', width: '60px' }}>
                          ACTIONS
                        </th>
                        {visibleColumns.map(col => (
                          <th
                            key={col}
                            onClick={() => toggleSort(col)}
                            className="px-2 py-1 text-left border-b cursor-pointer whitespace-nowrap select-none transition-colors"
                            style={{ borderColor: 'var(--v-border)', color: sortCol === col ? 'var(--v-accent)' : 'var(--v-text-muted)' }}
                          >
                            {col.toUpperCase()}
                            {sortCol === col && (sortOrder === 'asc' ? ' \u25B2' : ' \u25BC')}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {!recordsData && Array.from({ length: Math.min(limit, 12) }).map((_, i) => (
                        <tr key={`rec-sk-${i}`} style={{ borderBottom: '1px solid var(--v-border)' }}>
                          <td className="px-2 py-1"><span className="v-skeleton inline-block h-3 w-10" /></td>
                          {visibleColumns.map((col) => (
                            <td key={col} className="px-2 py-1">
                              <span className="v-skeleton inline-block h-3" style={{ width: `${40 + ((col.length * 7 + i * 11) % 50)}%` }} />
                            </td>
                          ))}
                        </tr>
                      ))}
                      {recordsData && records.map((record, idx) => {
                        const pkVal = getPrimaryKeyValue(record);
                        const isEditing = editingRecord?.id === pkVal;
                        const isSelected = selectedRecordId === pkVal;
                        return (
                          <tr
                            key={pkVal || idx}
                            onClick={() => handleRowClick(record)}
                            className="transition-colors cursor-pointer"
                            style={{
                              borderBottom: '1px solid var(--v-border)',
                              backgroundColor: isSelected ? 'color-mix(in srgb, var(--v-accent) 8%, transparent)' : undefined,
                            }}
                            onMouseEnter={(e) => { if (!isSelected) e.currentTarget.style.backgroundColor = 'color-mix(in srgb, var(--v-accent) 5%, transparent)'; }}
                            onMouseLeave={(e) => { if (!isSelected) e.currentTarget.style.backgroundColor = ''; }}
                          >
                            <td className="px-2 py-1 whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                              <div className="flex items-center gap-1">
                                {isEditing ? (
                                  <>
                                    <button onClick={saveEdit} className="text-[10px]" style={{ color: 'var(--v-success)' }}>[save]</button>
                                    <button onClick={() => setEditingRecord(null)} className="text-[10px]" style={{ color: 'var(--v-error)' }}>[x]</button>
                                  </>
                                ) : (
                                  <>
                                    <button onClick={() => startEdit(record)} style={{ color: 'var(--v-text-muted)' }} title="Edit">
                                      <Pencil className="w-3 h-3" />
                                    </button>
                                    {deleteConfirm === pkVal ? (
                                      <>
                                        <button onClick={() => handleDelete(pkVal)} className="text-[10px]" style={{ color: 'var(--v-error)' }}>[yes]</button>
                                        <button onClick={() => setDeleteConfirm(null)} className="text-[10px]" style={{ color: 'var(--v-text-muted)' }}>[no]</button>
                                      </>
                                    ) : (
                                      <button onClick={() => setDeleteConfirm(pkVal)} style={{ color: 'var(--v-text-muted)' }} title="Delete">
                                        <Trash2 className="w-3 h-3" />
                                      </button>
                                    )}
                                  </>
                                )}
                              </div>
                            </td>
                            {visibleColumns.map(col => (
                              <td key={col} className="px-2 py-1 max-w-[300px]" onClick={isEditing ? (e) => e.stopPropagation() : undefined}>
                                {isEditing && !primaryKey.includes(col) ? (
                                  <input
                                    type="text"
                                    value={editValues[col] ?? ''}
                                    onChange={(e) => setEditValues(prev => ({ ...prev, [col]: e.target.value }))}
                                    className="w-full border text-xs px-1 py-0.5 focus:outline-none"
                                    style={{ backgroundColor: 'var(--v-bg)', borderColor: 'color-mix(in srgb, var(--v-accent) 50%, transparent)', color: 'var(--v-text)' }}
                                  />
                                ) : (
                                  <span className="truncate block" style={{ color: primaryKey.includes(col) ? 'var(--v-accent)' : 'var(--v-text)' }}>
                                    {record[col] !== null && record[col] !== undefined ? String(record[col]) : <span style={{ color: 'var(--v-border)' }}>null</span>}
                                  </span>
                                )}
                              </td>
                            ))}
                          </tr>
                        );
                      })}
                      {recordsData && records.length === 0 && (
                        <tr>
                          <td colSpan={visibleColumns.length + 1} className="px-3 py-4 text-center" style={{ color: 'var(--v-text-muted)' }}>
                            no records
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                <div className="px-3 py-1.5 border-t flex items-center justify-between text-xs shrink-0" style={{ borderColor: 'var(--v-border)' }}>
                  <span style={{ color: 'var(--v-text-muted)' }}>
                    {totalRecords > 0 ? `${offset + 1}\u2013${Math.min(offset + limit, totalRecords)}` : '0'} of {totalRecords.toLocaleString()}
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setOffset(Math.max(0, offset - limit))}
                      disabled={offset === 0}
                      className="p-0.5 transition-colors disabled:opacity-30"
                      style={{ color: 'var(--v-text-muted)' }}
                    >
                      <ChevronLeft className="w-4 h-4" />
                    </button>
                    <span style={{ color: 'var(--v-text)' }}>{currentPage} / {totalPages || 1}</span>
                    <button
                      onClick={() => setOffset(offset + limit)}
                      disabled={offset + limit >= totalRecords}
                      className="p-0.5 transition-colors disabled:opacity-30"
                      style={{ color: 'var(--v-text-muted)' }}
                    >
                      <ChevronRight className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </>
            )}
          </div>

          {/* Detail panel */}
          {selectedRecordId !== null && selectedTable && (
            <div className="w-2/5 shrink-0">
              <RecordDetailPanel
                table={selectedTable}
                recordId={selectedRecordId}
                columns={allColumns}
                onClose={() => setSelectedRecordId(null)}
              />
            </div>
          )}
        </div>
      </div>

      {/* Create record modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ backgroundColor: 'rgba(0,0,0,0.6)' }}>
          <div className="border w-[500px] max-h-[80vh] flex flex-col" style={{ backgroundColor: 'var(--v-surface)', borderColor: 'var(--v-border)' }}>
            <div className="px-3 py-2 border-b flex items-center justify-between" style={{ borderColor: 'var(--v-border)' }}>
              <span className="text-xs font-bold" style={{ color: 'var(--v-accent)' }}>Create Record — {selectedTable}</span>
              <button onClick={() => setShowCreateModal(false)} style={{ color: 'var(--v-text-muted)' }}>
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-3 overflow-y-auto flex-1 space-y-2">
              {allColumns.filter(c => !primaryKey.includes(c.name) || c.nullable === 'yes').map(col => (
                <div key={col.name} className="flex items-center gap-2">
                  <label className="text-xs w-40 shrink-0 text-right" style={{ color: 'var(--v-text-muted)' }}>
                    {col.name}
                    <span className="text-[9px] ml-1" style={{ color: 'var(--v-border)' }}>({col.type})</span>
                  </label>
                  <input
                    type="text"
                    value={createValues[col.name] ?? ''}
                    onChange={(e) => setCreateValues(prev => ({ ...prev, [col.name]: e.target.value }))}
                    className="flex-1 border text-xs px-1.5 py-0.5 focus:outline-none"
                    style={{ backgroundColor: 'var(--v-bg)', borderColor: 'var(--v-border)', color: 'var(--v-text)' }}
                  />
                </div>
              ))}
            </div>
            <div className="px-3 py-2 border-t flex items-center justify-end gap-2" style={{ borderColor: 'var(--v-border)' }}>
              <button onClick={() => setShowCreateModal(false)} className="px-2 py-0.5 text-xs border" style={{ borderColor: 'var(--v-border)', color: 'var(--v-text-muted)' }}>
                Cancel
              </button>
              <button onClick={handleCreate} className="px-2 py-0.5 text-xs border font-bold" style={{ borderColor: 'color-mix(in srgb, var(--v-success) 50%, transparent)', color: 'var(--v-success)' }}>
                Create
              </button>
            </div>
          </div>
        </div>
      )}
    </PageShell>
  );
}
