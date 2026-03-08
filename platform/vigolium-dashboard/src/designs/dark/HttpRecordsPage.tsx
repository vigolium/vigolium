'use client';

import { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { AgGridReact } from 'ag-grid-react';
import type { ColDef, RowClickedEvent, SelectionChangedEvent } from 'ag-grid-community';
import { Activity, Globe, Server, Search, RefreshCw, List, Layers, ChevronRight, ChevronDown, X } from 'lucide-react';
import { useHttpRecords, useScanRecords, useDeleteHttpRecord } from '@/api/hooks';
import { useToast } from '@/contexts/ToastContext';
import type { HTTPRecord, HttpRecordsQueryParams } from '@/api/types';

import { registerAgGrid } from '@/lib/ag-grid-register';
import { formatDate, formatBytes } from '@/lib/formatters';
import { METHOD_COLORS, STATUS_COLORS, AG_GRID_THEME } from './theme';
import PageShell from './PageShell';
import HttpRecordDetailPanel from './HttpRecordDetailPanel';
import Dropdown from './Dropdown';
import ColumnChooser from './ColumnChooser';

registerAgGrid();

const PAGE_SIZE = 100;

function MethodRenderer({ value }: { value: string }) {
  const color = METHOD_COLORS[value] || '#918175';
  return (
    <span className="text-xs font-bold" style={{ color }}>
      {value}
    </span>
  );
}

function StatusRenderer({ value }: { value: number }) {
  if (!value) return <span className="text-[#403d38] text-xs">---</span>;
  const cat = `${Math.floor(value / 100)}xx`;
  const color = STATUS_COLORS[cat] || '#918175';
  return (
    <span className="text-xs font-bold" style={{ color }}>
      {value}
    </span>
  );
}

function BytesRenderer({ value }: { value: number }) {
  return <span className="text-xs text-[#918175]">{formatBytes(value)}</span>;
}

function DateRenderer({ value }: { value: string }) {
  return <span className="text-xs text-[#918175]">{formatDate(value)}</span>;
}

const CTYPE_COLORS: Record<string, string> = {
  html: '#68a8e4',
  json: '#7fd962',
  xml: '#2be4d0',
  javascript: '#f0c674',
  css: '#b294bb',
  text: '#918175',
  image: '#ff5c8f',
  font: '#c07840',
  pdf: '#e8b84b',
  form: '#0aaeb3',
  multipart: '#0aaeb3',
  octet: '#706560',
  video: '#ef2f27',
  audio: '#98bc37',
};

function ContentTypeRenderer({ value }: { value: string }) {
  if (!value) return <span className="text-[#403d38] text-xs">—</span>;
  const lower = value.toLowerCase();
  const matched = Object.keys(CTYPE_COLORS).find((k) => lower.includes(k));
  const color = matched ? CTYPE_COLORS[matched] : '#918175';
  return <span className="text-xs font-bold" style={{ color }}>{value}</span>;
}

const EXTRA_HIDDEN_FIELDS = [
  'uuid', 'scheme', 'port', 'ip', 'url', 'http_version',
  'request_content_type', 'request_content_length', 'request_hash',
  'status_phrase', 'response_http_version', 'response_hash',
  'has_response',
  'received_at', 'created_at', 'remarks',
];

const STATIC_CTYPE_KEYWORDS = ['image', 'font', 'video', 'audio', 'css', 'javascript', 'woff', 'svg', 'ico', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'mp4', 'webm'];

type ViewTab = 'table' | 'by-host';

/* ── Grouped-by-host view ─────────────────────────────────────────── */
function GroupedByHostView({
  records,
  onSelectRecord,
  selectedRecordUuid,
}: {
  records: HTTPRecord[];
  onSelectRecord: (uuid: string) => void;
  selectedRecordUuid: string | null;
}) {
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  const grouped = useMemo(() => {
    const map = new Map<string, HTTPRecord[]>();
    for (const r of records) {
      const host = r.hostname || '(unknown)';
      if (!map.has(host)) map.set(host, []);
      map.get(host)!.push(r);
    }
    // Sort by count descending
    return [...map.entries()].sort((a, b) => b[1].length - a[1].length);
  }, [records]);

  const toggle = (host: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(host)) next.delete(host);
      else next.add(host);
      return next;
    });
  };

  return (
    <div className="overflow-y-auto flex-1">
      {/* Column headers */}
      <div className="flex items-center gap-2 px-3 pl-7 py-1 border-b border-[#2e2b26] text-[#918175] text-xs font-bold sticky top-0 bg-[#1c1b19] z-10">
        <span className="w-16 shrink-0">METH</span>
        <span className="w-10 shrink-0">SC</span>
        <span className="flex-1">PATH</span>
        <span className="w-16 shrink-0 text-right">CTYPE</span>
        <span className="w-14 shrink-0 text-right">SIZE</span>
        <span className="w-12 shrink-0 text-right">WORDS</span>
        <span className="w-12 shrink-0 text-right">MS</span>
      </div>
      {grouped.map(([host, recs]) => (
        <div key={host}>
          <button
            onClick={() => toggle(host)}
            className="w-full flex items-center gap-1.5 px-3 py-1.5 border-b border-[#2e2b26] hover:bg-[#272520] text-left"
          >
            {collapsed.has(host) ? (
              <ChevronRight className="w-3 h-3 text-[#918175] shrink-0" />
            ) : (
              <ChevronDown className="w-3 h-3 text-[#918175] shrink-0" />
            )}
            <span className="text-[#68a8e4] text-xs font-bold truncate">{host}</span>
            <span className="text-[#918175] text-xs ml-auto shrink-0">{recs.length}</span>
          </button>
          {!collapsed.has(host) && (
            <div>
              {recs.map((r) => (
                <button
                  key={r.uuid}
                  onClick={() => onSelectRecord(r.uuid)}
                  className={`w-full flex items-center gap-2 px-3 pl-7 py-1 border-b border-[#2e2b26]/50 hover:bg-[#272520] text-left text-xs ${
                    selectedRecordUuid === r.uuid ? 'bg-[#272520]' : ''
                  }`}
                >
                  <span className="font-bold w-16 shrink-0" style={{ color: METHOD_COLORS[r.method] || '#918175' }}>
                    {r.method}
                  </span>
                  <span className="font-bold w-10 shrink-0" style={{ color: STATUS_COLORS[`${Math.floor(r.status_code / 100)}xx`] || '#918175' }}>
                    {r.status_code || '---'}
                  </span>
                  <span className="text-[#fce8c3] truncate flex-1">{r.path}</span>
                  <span className="text-[#918175] w-16 shrink-0 text-right">{r.response_content_type ? r.response_content_type.split(';')[0].split('/').pop() : '—'}</span>
                  <span className="text-[#918175] w-14 shrink-0 text-right">{formatBytes(r.response_content_length)}</span>
                  <span className="text-[#918175] w-12 shrink-0 text-right">{r.response_words || '-'}</span>
                  <span className="text-[#918175] w-12 shrink-0 text-right">{r.response_time_ms ? `${r.response_time_ms}ms` : '-'}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      ))}
      {grouped.length === 0 && (
        <div className="p-3 text-xs text-[#403d38] text-center">no records</div>
      )}
    </div>
  );
}

export default function HttpRecordsPage({ initialId }: { initialId?: string | null }) {
  const [params, setParams] = useState<HttpRecordsQueryParams>({
    limit: PAGE_SIZE,
    offset: 0,
  });
  const [searchInput, setSearchInput] = useState('');
  const [methodFilter, setMethodFilter] = useState('');
  const [hostnameFilter, setHostnameFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [selectedRecordUuid, setSelectedRecordUuid] = useState<string | null>(initialId ?? null);
  const [selectedRows, setSelectedRows] = useState<HTTPRecord[]>([]);
  const gridRef = useRef<AgGridReact<HTTPRecord>>(null);
  const [hiddenColumns, setHiddenColumns] = useState<Set<string>>(new Set(EXTRA_HIDDEN_FIELDS));
  const [viewTab, setViewTab] = useState<ViewTab>('table');
  const [filterWithTitle, setFilterWithTitle] = useState(false);
  const [filterWithRemarks, setFilterWithRemarks] = useState(false);
  const [filterHideStatic, setFilterHideStatic] = useState(false);

  const scanRecords = useScanRecords();
  const deleteRecord = useDeleteHttpRecord();
  const { toast } = useToast();

  useEffect(() => {
    setSelectedRecordUuid(initialId ?? null);
  }, [initialId]);

  const navigateToRecord = useCallback((uuid: string | null) => {
    setSelectedRecordUuid(uuid);
    window.history.pushState(null, '', uuid !== null ? `/http-records/${uuid}` : '/http-records');
  }, []);

  const handleDeleteSelected = useCallback(async () => {
    const uuids = selectedRows.map((r) => r.uuid);
    const results = await Promise.allSettled(uuids.map((uuid) => deleteRecord.mutateAsync(uuid)));
    const succeeded = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.length - succeeded;
    if (failed === 0) {
      toast(`Deleted ${succeeded} record(s)`, 'success');
    } else {
      toast(`Deleted ${succeeded}, failed ${failed}`, 'error');
    }
    setSelectedRows([]);
    gridRef.current?.api?.deselectAll();
  }, [selectedRows, deleteRecord, toast]);

  const queryParams = useMemo(
    () => ({
      ...params,
      method: methodFilter || undefined,
      search: searchInput || undefined,
      hostname: hostnameFilter || undefined,
      source: sourceFilter || undefined,
    }),
    [params, methodFilter, searchInput, hostnameFilter, sourceFilter]
  );

  const { data, isLoading, refetch, isFetching } = useHttpRecords(queryParams);

  const columnDefs = useMemo<ColDef<HTTPRecord>[]>(
    () => [
      { headerCheckboxSelection: true, checkboxSelection: true, width: 40, sortable: false, filter: false, resizable: false },
      { field: 'method', headerName: 'METH', width: 70, cellRenderer: MethodRenderer },
      { field: 'status_code', headerName: 'SC', width: 55, cellRenderer: StatusRenderer },
      { field: 'hostname', headerName: 'HOST', flex: 1, minWidth: 120 },
      { field: 'path', headerName: 'PATH', flex: 2, minWidth: 180 },
      {
        field: 'response_time_ms',
        headerName: 'MS',
        width: 60,
        valueFormatter: (p) => (p.value ? `${p.value}` : '-'),
      },
      { field: 'response_content_type', headerName: 'CTYPE', width: 110, cellRenderer: ContentTypeRenderer },
      { field: 'response_content_length', headerName: 'SIZE', width: 70, cellRenderer: BytesRenderer },
      { field: 'response_title', headerName: 'TITLE', width: 150 },
      { field: 'response_words', headerName: 'WORDS', width: 70 },
      { field: 'risk_score', headerName: 'RISK', width: 50 },
      { field: 'source', headerName: 'SRC', width: 60 },
      { field: 'sent_at', headerName: 'TIME', width: 120, cellRenderer: DateRenderer },
      // Hidden-by-default columns
      { field: 'uuid', headerName: 'UUID', width: 280, hide: true },
      { field: 'scheme', headerName: 'SCHEME', width: 70, hide: true },
      { field: 'port', headerName: 'PORT', width: 60, hide: true },
      { field: 'ip', headerName: 'IP', width: 120, hide: true },
      { field: 'url', headerName: 'URL', flex: 2, minWidth: 200, hide: true },
      { field: 'http_version', headerName: 'HTTP VER', width: 80, hide: true },
      { field: 'request_content_type', headerName: 'REQ CTYPE', width: 110, hide: true },
      { field: 'request_content_length', headerName: 'REQ SIZE', width: 80, cellRenderer: BytesRenderer, hide: true },
      { field: 'request_hash', headerName: 'REQ HASH', width: 100, hide: true },
      { field: 'status_phrase', headerName: 'STATUS', width: 100, hide: true },
      { field: 'response_http_version', headerName: 'RES VER', width: 80, hide: true },
      { field: 'response_hash', headerName: 'RES HASH', width: 100, hide: true },
      { field: 'has_response', headerName: 'HAS RES', width: 70, hide: true },
      { field: 'received_at', headerName: 'RECEIVED', width: 120, cellRenderer: DateRenderer, hide: true },
      { field: 'created_at', headerName: 'CREATED', width: 120, cellRenderer: DateRenderer, hide: true },
      { field: 'remarks', headerName: 'REMARKS', width: 150, valueFormatter: (p) => (p.value as string[])?.join(', ') || '', hide: true },
    ],
    []
  );

  const toggleableColumns = useMemo(() => {
    const seen = new Set<string>();
    return columnDefs
      .filter((c) => c.field && !seen.has(c.field) && (seen.add(c.field), true))
      .map((c) => ({ field: c.field!, label: c.headerName || c.field! }));
  }, [columnDefs]);

  const effectiveColumnDefs = useMemo(
    () => columnDefs.map((c) => (!c.field ? c : { ...c, hide: hiddenColumns.has(c.field) })),
    [columnDefs, hiddenColumns]
  );

  const currentPage = Math.floor((params.offset || 0) / PAGE_SIZE) + 1;
  const totalPages = Math.ceil((data?.total || 0) / PAGE_SIZE);

  const goToPage = useCallback((page: number) => {
    setParams((prev) => ({ ...prev, offset: (page - 1) * PAGE_SIZE }));
  }, []);

  const resetOffset = () => setParams((p) => ({ ...p, offset: 0 }));

  const isExternalFilterPresent = useCallback(
    () => statusFilter !== '' || hostnameFilter !== '' || sourceFilter !== '' || filterWithTitle || filterWithRemarks || filterHideStatic,
    [statusFilter, hostnameFilter, sourceFilter, filterWithTitle, filterWithRemarks, filterHideStatic]
  );
  const doesExternalFilterPass = useCallback(
    (node: { data: HTTPRecord | undefined }) => {
      if (!node.data) return true;
      if (statusFilter && Math.floor(node.data.status_code / 100) !== parseInt(statusFilter)) return false;
      if (hostnameFilter && !(node.data.hostname || '').toLowerCase().includes(hostnameFilter.toLowerCase())) return false;
      if (sourceFilter && !(node.data.source || '').toLowerCase().includes(sourceFilter.toLowerCase())) return false;
      if (filterWithTitle && !node.data.response_title) return false;
      if (filterWithRemarks && (!node.data.remarks || node.data.remarks.length === 0)) return false;
      if (filterHideStatic) {
        const ctype = (node.data.response_content_type || '').toLowerCase();
        if (STATIC_CTYPE_KEYWORDS.some((k) => ctype.includes(k))) return false;
      }
      return true;
    },
    [statusFilter, hostnameFilter, sourceFilter, filterWithTitle, filterWithRemarks, filterHideStatic]
  );

  useEffect(() => {
    gridRef.current?.api?.onFilterChanged();
  }, [statusFilter, hostnameFilter, sourceFilter, filterWithTitle, filterWithRemarks, filterHideStatic]);

  const selectedRecordUuidRef = useRef(selectedRecordUuid);
  selectedRecordUuidRef.current = selectedRecordUuid;

  const onRowClicked = useCallback((event: RowClickedEvent<HTTPRecord>) => {
    const target = event.event?.target as HTMLElement | undefined;
    if (target?.closest('.ag-checkbox-input-wrapper, .ag-selection-checkbox')) return;
    if (event.data?.uuid) {
      navigateToRecord(selectedRecordUuidRef.current === event.data!.uuid ? null : event.data!.uuid);
    }
  }, [navigateToRecord]);

  const onSelectionChanged = useCallback((event: SelectionChangedEvent<HTTPRecord>) => {
    const selected = event.api.getSelectedRows();
    setSelectedRows(selected);
  }, []);

  const handleScanSelected = () => {
    const uuids = selectedRows.map((r) => r.uuid);
    scanRecords.mutate({ record_uuids: uuids }, {
      onSuccess: (res) => {
        toast(`Scan started: ${res.scan_id} (${res.records_to_scan ?? uuids.length} records)`, 'success');
      },
      onError: (err) => {
        toast((err as Error).message, 'error');
      },
    });
  };

  const handleFilterHostname = useCallback((hostname: string) => {
    setHostnameFilter(hostname);
    resetOffset();
  }, []);

  const handleSelectRecordFromGrouped = useCallback((uuid: string) => {
    navigateToRecord(selectedRecordUuidRef.current === uuid ? null : uuid);
  }, [navigateToRecord]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && selectedRecordUuidRef.current !== null) {
        const tag = (e.target as HTMLElement)?.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA') return;
        navigateToRecord(null);
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [navigateToRecord]);

  return (
    <PageShell>
      <div className="flex" style={{ height: 'calc(100vh - 120px)', minHeight: 500 }}>
        {/* Table section */}
        <div className={`border border-[#2e2b26] bg-[#1c1b19] overflow-hidden flex flex-col ${selectedRecordUuid !== null ? 'w-1/2' : 'w-full'} transition-all`}>
          <div className="px-3 py-1.5 border-b border-[#2e2b26] flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-1.5">
              <span className="text-[#7fd962] text-xs font-bold">HTTP_RECORDS</span>
              <button onClick={() => refetch()} className="text-[#918175] hover:text-[#7fd962] transition-colors" title="Refresh">
                <RefreshCw className={`w-3 h-3 ${isFetching ? 'animate-spin' : ''}`} />
              </button>
              {/* View tabs */}
              <div className="flex items-center gap-0.5 ml-2 border border-[#2e2b26] rounded-sm">
                <button
                  onClick={() => setViewTab('table')}
                  className={`flex items-center gap-1 px-1.5 py-0.5 text-xs transition-colors ${
                    viewTab === 'table'
                      ? 'text-[#7fd962] bg-[#7fd962]/10'
                      : 'text-[#918175] hover:text-[#fce8c3]'
                  }`}
                  title="Table view"
                >
                  <List className="w-3 h-3" />
                  Table
                </button>
                <button
                  onClick={() => setViewTab('by-host')}
                  className={`flex items-center gap-1 px-1.5 py-0.5 text-xs transition-colors ${
                    viewTab === 'by-host'
                      ? 'text-[#7fd962] bg-[#7fd962]/10'
                      : 'text-[#918175] hover:text-[#fce8c3]'
                  }`}
                  title="Group by hostname"
                >
                  <Layers className="w-3 h-3" />
                  By Host
                </button>
              </div>
            </div>
            <div className="flex items-center gap-2 text-xs flex-wrap">
              {(methodFilter || hostnameFilter || sourceFilter || statusFilter || searchInput || filterWithTitle || filterWithRemarks || filterHideStatic) && (
                <button
                  onClick={() => {
                    setMethodFilter(''); setHostnameFilter(''); setSourceFilter('');
                    setStatusFilter(''); setSearchInput('');
                    setFilterWithTitle(false); setFilterWithRemarks(false); setFilterHideStatic(false);
                    resetOffset();
                  }}
                  className="flex items-center gap-0.5 px-1.5 py-0.5 border border-[#ef2f27]/40 text-[#ef2f27] hover:bg-[#ef2f27]/10 transition-colors"
                  title="Clear all filters"
                >
                  <X className="w-3 h-3" />
                  clear
                </button>
              )}
              <Dropdown
                value={methodFilter}
                icon={<Activity className="w-3 h-3" />}
                options={[
                  { value: '', label: 'meth:all' },
                  ...['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map((m) => ({ value: m, label: m })),
                ]}
                onChange={(v) => { setMethodFilter(v); resetOffset(); }}
              />
              <div className="flex items-center border border-[#2e2b26] bg-[#1c1b19] focus-within:border-[#7fd962]/50">
                <Globe className="w-3 h-3 text-[#918175] ml-1.5 shrink-0" />
                <input type="text" value={hostnameFilter} onChange={(e) => { setHostnameFilter(e.target.value); resetOffset(); }} placeholder="host..." className="bg-transparent text-[#fce8c3] text-xs px-1.5 py-0.5 w-28 focus:outline-none" />
              </div>
              <div className="flex items-center border border-[#2e2b26] bg-[#1c1b19] focus-within:border-[#7fd962]/50">
                <Server className="w-3 h-3 text-[#918175] ml-1.5 shrink-0" />
                <input type="text" value={sourceFilter} onChange={(e) => { setSourceFilter(e.target.value); resetOffset(); }} placeholder="source..." className="bg-transparent text-[#fce8c3] text-xs px-1.5 py-0.5 w-20 focus:outline-none" />
              </div>
              <div className="flex items-center gap-0.5">
                {[
                  { value: '', label: 'ALL' },
                  { value: '2', label: '2xx' },
                  { value: '3', label: '3xx' },
                  { value: '4', label: '4xx' },
                  { value: '5', label: '5xx' },
                ].map((btn) => (
                  <button
                    key={btn.value}
                    onClick={() => setStatusFilter(btn.value)}
                    className={`px-1.5 py-0.5 border text-xs transition-colors ${
                      statusFilter === btn.value
                        ? 'border-[#7fd962]/50 text-[#7fd962] bg-[#7fd962]/10'
                        : 'border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]'
                    }`}
                    style={statusFilter === btn.value && btn.value ? { color: STATUS_COLORS[`${btn.value}xx`] } : undefined}
                  >
                    {btn.label}
                  </button>
                ))}
              </div>
              <div className="flex items-center border border-[#2e2b26] bg-[#1c1b19] focus-within:border-[#7fd962]/50">
                <Search className="w-3 h-3 text-[#918175] ml-1.5 shrink-0" />
                <input type="text" value={searchInput} onChange={(e) => { setSearchInput(e.target.value); resetOffset(); }} placeholder="search..." className="bg-transparent text-[#fce8c3] text-xs px-1.5 py-0.5 w-36 focus:outline-none" />
              </div>
              <div className="flex items-center gap-0.5">
                <button
                  onClick={() => setFilterWithTitle((v) => !v)}
                  className={`px-1.5 py-0.5 border text-xs transition-colors ${
                    filterWithTitle
                      ? 'border-[#68a8e4]/50 text-[#68a8e4] bg-[#68a8e4]/10'
                      : 'border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]'
                  }`}
                  title="Show only records with a title"
                >
                  title
                </button>
                <button
                  onClick={() => setFilterWithRemarks((v) => !v)}
                  className={`px-1.5 py-0.5 border text-xs transition-colors ${
                    filterWithRemarks
                      ? 'border-[#2be4d0]/50 text-[#2be4d0] bg-[#2be4d0]/10'
                      : 'border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]'
                  }`}
                  title="Show only records with remarks"
                >
                  remarks
                </button>
                <button
                  onClick={() => setFilterHideStatic((v) => !v)}
                  className={`px-1.5 py-0.5 border text-xs transition-colors ${
                    filterHideStatic
                      ? 'border-[#f0c674]/50 text-[#f0c674] bg-[#f0c674]/10'
                      : 'border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]'
                  }`}
                  title="Hide static assets (images, fonts, CSS, JS, etc.)"
                >
                  -static
                </button>
              </div>
              {viewTab === 'table' && (
                <ColumnChooser columns={toggleableColumns} hiddenColumns={hiddenColumns} onChange={setHiddenColumns} />
              )}
            </div>
          </div>

          {/* Action toolbar */}
          {selectedRows.length > 0 && viewTab === 'table' && (
            <div className="px-3 py-1.5 border-b border-[#2e2b26] bg-[#272520] flex items-center gap-3 text-xs flex-wrap">
              <span className="text-[#fce8c3]">{selectedRows.length} selected</span>
              <button
                onClick={handleDeleteSelected}
                disabled={deleteRecord.isPending}
                className="px-2 py-0.5 border border-[#ef2f27]/50 text-[#ef2f27] hover:bg-[#ef2f27]/10 disabled:opacity-50 transition-colors"
              >
                {deleteRecord.isPending ? 'deleting...' : '[DELETE SELECTED]'}
              </button>
              <button
                onClick={handleScanSelected}
                disabled={scanRecords.isPending}
                className="px-2 py-0.5 border border-[#98bc37]/50 text-[#98bc37] hover:bg-[#98bc37]/10 disabled:opacity-50 transition-colors"
              >
                {scanRecords.isPending ? 'scanning...' : '[SCAN SELECTED]'}
              </button>
              {scanRecords.isError && (
                <span className="text-[#ef2f27]">error: {(scanRecords.error as Error).message}</span>
              )}
            </div>
          )}

          {/* Table view */}
          {viewTab === 'table' && (
            <>
              <div className={`${AG_GRID_THEME} w-full flex-1`}>
                <AgGridReact<HTTPRecord>
                  ref={gridRef}
                  rowData={data?.data || []}
                  columnDefs={effectiveColumnDefs}
                  loading={isLoading}
                  suppressCellFocus
                  animateRows
                  domLayout="normal"
                  onRowClicked={onRowClicked}
                  rowSelection="multiple"
                  suppressRowClickSelection
                  onSelectionChanged={onSelectionChanged}
                  isExternalFilterPresent={isExternalFilterPresent}
                  doesExternalFilterPass={doesExternalFilterPass}
                  overlayNoRowsTemplate='<span style="color:#403d38">no records</span>'
                />
              </div>

              {(data?.total || 0) > 0 && (
                <div className="flex items-center justify-between px-3 py-1 border-t border-[#2e2b26] text-xs text-[#918175]">
                  <span>
                    {(params.offset || 0) + 1}-{Math.min((params.offset || 0) + PAGE_SIZE, data?.total || 0)}/{data?.total || 0}
                  </span>
                  <div className="flex items-center gap-1">
                    <button onClick={() => goToPage(currentPage - 1)} disabled={currentPage <= 1} className="hover:text-[#7fd962] disabled:opacity-30 px-1">{'<'}</button>
                    <span className="px-1">{currentPage}/{totalPages}</span>
                    <button onClick={() => goToPage(currentPage + 1)} disabled={currentPage >= totalPages} className="hover:text-[#7fd962] disabled:opacity-30 px-1">{'>'}</button>
                  </div>
                </div>
              )}
            </>
          )}

          {/* Grouped by host view */}
          {viewTab === 'by-host' && (
            <>
              {isLoading ? (
                <div className="p-3 text-xs text-[#918175]">loading...</div>
              ) : (
                <GroupedByHostView
                  records={data?.data || []}
                  onSelectRecord={handleSelectRecordFromGrouped}
                  selectedRecordUuid={selectedRecordUuid}
                />
              )}
              {(data?.total || 0) > 0 && (
                <div className="flex items-center justify-between px-3 py-1 border-t border-[#2e2b26] text-xs text-[#918175]">
                  <span>
                    {(params.offset || 0) + 1}-{Math.min((params.offset || 0) + PAGE_SIZE, data?.total || 0)}/{data?.total || 0}
                  </span>
                  <div className="flex items-center gap-1">
                    <button onClick={() => goToPage(currentPage - 1)} disabled={currentPage <= 1} className="hover:text-[#7fd962] disabled:opacity-30 px-1">{'<'}</button>
                    <span className="px-1">{currentPage}/{totalPages}</span>
                    <button onClick={() => goToPage(currentPage + 1)} disabled={currentPage >= totalPages} className="hover:text-[#7fd962] disabled:opacity-30 px-1">{'>'}</button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Detail panel */}
        {selectedRecordUuid !== null && (
          <div className="w-1/2">
            <HttpRecordDetailPanel
              uuid={selectedRecordUuid}
              onClose={() => navigateToRecord(null)}
              onFilterHostname={handleFilterHostname}
            />
          </div>
        )}
      </div>
    </PageShell>
  );
}
