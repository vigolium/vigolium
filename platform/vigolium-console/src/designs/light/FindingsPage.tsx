'use client';

import { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { AgGridReact } from 'ag-grid-react';
import type { ColDef, RowClickedEvent, SelectionChangedEvent } from 'ag-grid-community';
import { Shield, Globe, Box, Search, RefreshCw, List, Layers, ChevronRight, ChevronDown } from 'lucide-react';
import { useFindings, useDeleteFinding } from '@/api/hooks';
import { withDemoKey } from '@/api/client';
import { useToast } from '@/contexts/ToastContext';
import type { Finding, FindingsQueryParams } from '@/api/types';

import { registerAgGrid } from '@/lib/ag-grid-register';
import { formatDate } from '@/lib/formatters';
import { SEVERITY_COLORS, CONFIDENCE_COLORS, MODULE_TYPE_COLORS, AG_GRID_THEME } from './theme';
import PageShell from './PageShell';
import FindingDetailPanel from './FindingDetailPanel';
import Dropdown from './Dropdown';
import ColumnChooser from './ColumnChooser';

registerAgGrid();

const PAGE_SIZE = 100;

type ViewTab = 'table' | 'by-host';

/* ── Grouped-by-host view ─────────────────────────────────────────── */
function GroupedByHostView({
  findings,
  onSelectFinding,
  selectedFindingId,
}: {
  findings: Finding[];
  onSelectFinding: (id: number) => void;
  selectedFindingId: number | null;
}) {
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  const grouped = useMemo(() => {
    const map = new Map<string, Finding[]>();
    for (const f of findings) {
      let host = '(unknown)';
      if (f.matched_at && f.matched_at.length > 0) {
        try {
          host = new URL(f.matched_at[0]).hostname;
        } catch {
          host = '(unknown)';
        }
      }
      if (!map.has(host)) map.set(host, []);
      map.get(host)!.push(f);
    }
    return [...map.entries()].sort((a, b) => b[1].length - a[1].length);
  }, [findings]);

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
      <div className="flex items-center gap-2 px-3 pl-7 py-1 border-b border-[#bbc3c4] text-[#708e8e] text-xs font-bold sticky top-0 bg-[#f6edda] z-10">
        <span className="w-16 shrink-0">SEV</span>
        <span className="w-16 shrink-0">CONF</span>
        <span className="w-40 shrink-0">MODULE</span>
        <span className="flex-1">DESCRIPTION</span>
        <span className="w-52 shrink-0 text-right">MATCHED_AT</span>
        <span className="w-28 shrink-0 text-right">TIME</span>
      </div>
      {grouped.map(([host, items]) => (
        <div key={host}>
          <button
            onClick={() => toggle(host)}
            className="w-full flex items-center gap-1.5 px-3 py-1.5 border-b border-[#bbc3c4] hover:bg-[#ede4d1] text-left"
          >
            {collapsed.has(host) ? (
              <ChevronRight className="w-3 h-3 text-[#708e8e] shrink-0" />
            ) : (
              <ChevronDown className="w-3 h-3 text-[#708e8e] shrink-0" />
            )}
            <span className="text-[#0078c8] text-xs font-bold truncate">{host}</span>
            <span className="text-[#708e8e] text-xs ml-auto shrink-0">{items.length}</span>
          </button>
          {!collapsed.has(host) && (
            <div>
              {items.map((f) => (
                <button
                  key={f.id}
                  onClick={() => onSelectFinding(f.id)}
                  className={`w-full flex items-center gap-2 px-3 pl-7 py-1 border-b border-[#bbc3c4]/50 hover:bg-[#ede4d1] text-left text-xs ${
                    selectedFindingId === f.id ? 'bg-[#ede4d1]' : ''
                  }`}
                >
                  <span className="font-bold w-16 shrink-0 uppercase" style={{ color: SEVERITY_COLORS[f.severity] || '#708e8e' }}>
                    {f.severity}
                  </span>
                  <span className="w-16 shrink-0" style={{ color: CONFIDENCE_COLORS[f.confidence] || '#708e8e' }}>
                    {f.confidence}
                  </span>
                  <span className="text-[#708e8e] w-40 shrink-0 truncate">{f.module_name}</span>
                  <span className="text-[#005661] truncate flex-1 min-w-0">{f.description || '—'}</span>
                  <span className="text-[#708e8e] w-52 shrink-0 text-right truncate">{f.matched_at?.join(', ') || '—'}</span>
                  <span className="text-[#708e8e] w-28 shrink-0 text-right">{f.found_at ? formatDate(f.found_at) : '—'}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      ))}
      {grouped.length === 0 && (
        <div className="p-3 text-xs text-[#bbc3c4] text-center">no findings</div>
      )}
    </div>
  );
}

function SeverityRenderer({ value }: { value: string }) {
  const color = SEVERITY_COLORS[value] || '#708e8e';
  return (
    <span className="text-xs font-bold uppercase" style={{ color }}>
      {value}
    </span>
  );
}

function ConfidenceRenderer({ value }: { value: string }) {
  const color = CONFIDENCE_COLORS[value] || '#708e8e';
  return (
    <span className="text-xs" style={{ color }}>
      {value}
    </span>
  );
}

function ModuleTypeRenderer({ value }: { value: string }) {
  const color = MODULE_TYPE_COLORS[value] || '#708e8e';
  return (
    <span className="text-xs" style={{ color }}>
      {value}
    </span>
  );
}

function DateRenderer({ value }: { value: string }) {
  return <span className="text-xs text-[#708e8e]">{formatDate(value)}</span>;
}

const HASH_COLORS = [
  '#00845a', '#0068b8', '#c04600', '#8839b0', '#007a7a',
  '#c02040', '#a06000', '#4a8c00', '#9050d0', '#2878c0',
];

function hashColor(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
  }
  return HASH_COLORS[Math.abs(hash) % HASH_COLORS.length];
}

function RepoNameRenderer({ value }: { value: string }) {
  if (!value) return null;
  return (
    <span className="text-xs font-medium" style={{ color: hashColor(value) }}>
      {value}
    </span>
  );
}

function TagsRenderer({ value }: { value: string[] }) {
  if (!value || value.length === 0) return null;
  return (
    <span className="text-xs">
      {value.map((tag, i) => (
        <span key={tag}>
          {i > 0 && <span className="text-[#708e8e]">, </span>}
          <span style={{ color: hashColor(tag) }}>{tag}</span>
        </span>
      ))}
    </span>
  );
}

export default function FindingsPage({ initialId }: { initialId?: number | null }) {
  const [params, setParams] = useState<FindingsQueryParams>({
    limit: PAGE_SIZE,
    offset: 0,
  });
  const [searchInput, setSearchInput] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [domainFilter, setDomainFilter] = useState('');
  const [moduleFilter, setModuleFilter] = useState('');
  const [moduleTypeFilter, setModuleTypeFilter] = useState('');
  const [findingSourceFilter, setFindingSourceFilter] = useState('');
  const [selectedFindingId, setSelectedFindingId] = useState<number | null>(initialId ?? null);
  const [selectedRows, setSelectedRows] = useState<Finding[]>([]);
  const gridRef = useRef<AgGridReact<Finding>>(null);
  const [hiddenColumns, setHiddenColumns] = useState<Set<string>>(new Set(['scan_uuid']));
  const [viewTab, setViewTab] = useState<ViewTab>('table');

  const deleteFinding = useDeleteFinding();
  const { toast } = useToast();

  useEffect(() => {
    setSelectedFindingId(initialId ?? null);
  }, [initialId]);

  const navigateToFinding = useCallback((id: number | null) => {
    setSelectedFindingId(id);
    window.history.pushState(null, '', withDemoKey(id !== null ? `/findings/${id}` : '/findings'));
  }, []);

  const handleDeleteSelected = useCallback(async () => {
    const ids = selectedRows.map((r) => r.id);
    const results = await Promise.allSettled(ids.map((id) => deleteFinding.mutateAsync(id)));
    const succeeded = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.length - succeeded;
    if (failed === 0) {
      toast(`Deleted ${succeeded} finding(s)`, 'success');
    } else {
      toast(`Deleted ${succeeded}, failed ${failed}`, 'error');
    }
    setSelectedRows([]);
    gridRef.current?.api?.deselectAll();
  }, [selectedRows, deleteFinding, toast]);

  const queryParams = useMemo(
    () => ({
      ...params,
      severity: severityFilter || undefined,
      search: searchInput || undefined,
      domain: domainFilter || undefined,
      module_name: moduleFilter || undefined,
      module_type: moduleTypeFilter || undefined,
      finding_source: findingSourceFilter || undefined,
    }),
    [params, severityFilter, searchInput, domainFilter, moduleFilter, moduleTypeFilter, findingSourceFilter]
  );

  const { data, isLoading, refetch, isFetching } = useFindings(queryParams);

  const columnDefs = useMemo<ColDef<Finding>[]>(
    () => [
      { width: 40, sortable: false, filter: false, resizable: false },
      { field: 'id', headerName: 'ID', width: 60 },
      { field: 'severity', headerName: 'SEV', width: 80, cellRenderer: SeverityRenderer },
      { field: 'confidence', headerName: 'CONF', width: 100, cellRenderer: ConfidenceRenderer },
      { field: 'module_name', headerName: 'MODULE', flex: 1, minWidth: 140 },
      { field: 'module_type', headerName: 'TYPE', width: 80, cellRenderer: ModuleTypeRenderer },
      { field: 'description', headerName: 'DESCRIPTION', flex: 2, minWidth: 200 },
      {
        field: 'matched_at',
        headerName: 'MATCHED_AT',
        flex: 1,
        minWidth: 120,
        valueFormatter: (p) => (p.value as string[])?.join(', ') || '',
      },
      {
        field: 'tags',
        headerName: 'TAGS',
        width: 140,
        cellRenderer: TagsRenderer,
      },
      { field: 'scan_uuid', headerName: 'SCAN_ID', width: 100 },
      { field: 'finding_source', headerName: 'SOURCE', width: 120 },
      { field: 'repo_name', headerName: 'REPO', width: 140, cellRenderer: RepoNameRenderer },
      { field: 'source_file', headerName: 'FILE', width: 160 },
      { field: 'found_at', headerName: 'TIME', width: 120, cellRenderer: DateRenderer },
    ],
    []
  );

  const toggleableColumns = useMemo(
    () => columnDefs.filter((c) => c.field).map((c) => ({ field: c.field!, label: c.headerName || c.field! })),
    [columnDefs]
  );

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

  const selectedFindingIdRef = useRef(selectedFindingId);
  selectedFindingIdRef.current = selectedFindingId;

  const onRowClicked = useCallback((event: RowClickedEvent<Finding>) => {
    const target = event.event?.target as HTMLElement | undefined;
    if (target?.closest('.ag-checkbox-input-wrapper, .ag-selection-checkbox')) return;
    if (event.data?.id != null) {
      navigateToFinding(selectedFindingIdRef.current === event.data!.id ? null : event.data!.id);
    }
  }, [navigateToFinding]);

  const onSelectionChanged = useCallback((event: SelectionChangedEvent<Finding>) => {
    setSelectedRows(event.api.getSelectedRows());
  }, []);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && selectedFindingId !== null) {
        const tag = (e.target as HTMLElement)?.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA') return;
        navigateToFinding(null);
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [selectedFindingId, navigateToFinding]);

  return (
    <PageShell>
      <div className="flex" style={{ height: 'calc(100vh - 120px)', minHeight: 500 }}>
        {/* Table section */}
        <div className={`border border-[#bbc3c4] bg-[#f6edda] overflow-hidden flex flex-col ${selectedFindingId !== null ? 'w-1/2' : 'w-full'} transition-all`}>
          <div className="px-3 py-1.5 border-b border-[#bbc3c4] flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-1.5">
              <span className="text-[#0078c8] text-xs font-bold">FINDINGS</span>
              <button onClick={() => refetch()} className="text-[#708e8e] hover:text-[#0078c8] transition-colors" title="Refresh">
                <RefreshCw className={`w-3 h-3 ${isFetching ? 'animate-spin' : ''}`} />
              </button>
              {/* View tabs */}
              <div className="flex items-center gap-0.5 ml-2 border border-[#bbc3c4] rounded-sm">
                <button
                  onClick={() => setViewTab('table')}
                  className={`flex items-center gap-1 px-1.5 py-0.5 text-xs transition-colors ${
                    viewTab === 'table'
                      ? 'text-[#0078c8] bg-[#0078c8]/10'
                      : 'text-[#708e8e] hover:text-[#005661]'
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
                      ? 'text-[#0078c8] bg-[#0078c8]/10'
                      : 'text-[#708e8e] hover:text-[#005661]'
                  }`}
                  title="Group by hostname"
                >
                  <Layers className="w-3 h-3" />
                  By Host
                </button>
              </div>
            </div>
            <div className="flex items-center gap-2 text-xs flex-wrap">
              <Dropdown
                value={severityFilter}
                icon={<Shield className="w-3 h-3" />}
                options={[
                  { value: '', label: 'sev:all' },
                  { value: 'critical', label: 'critical' },
                  { value: 'high', label: 'high' },
                  { value: 'medium', label: 'medium' },
                  { value: 'low', label: 'low' },
                  { value: 'info', label: 'info' },
                ]}
                onChange={(v) => { setSeverityFilter(v); resetOffset(); }}
              />
              <div className="flex items-center border border-[#bbc3c4] bg-[#f6edda] focus-within:border-[#0078c8]/50">
                <Globe className="w-3 h-3 text-[#708e8e] ml-1.5 shrink-0" />
                <input type="text" value={domainFilter} onChange={(e) => { setDomainFilter(e.target.value); resetOffset(); }} placeholder="domain..." className="bg-transparent text-[#005661] text-xs px-1.5 py-0.5 w-28 focus:outline-none" />
              </div>
              <div className="flex items-center border border-[#bbc3c4] bg-[#f6edda] focus-within:border-[#0078c8]/50">
                <Box className="w-3 h-3 text-[#708e8e] ml-1.5 shrink-0" />
                <input type="text" value={moduleFilter} onChange={(e) => { setModuleFilter(e.target.value); resetOffset(); }} placeholder="module..." className="bg-transparent text-[#005661] text-xs px-1.5 py-0.5 w-28 focus:outline-none" />
              </div>
              <Dropdown
                value={moduleTypeFilter}
                options={[
                  { value: '', label: 'type:all' },
                  { value: 'active', label: 'active' },
                  { value: 'passive', label: 'passive' },
                ]}
                onChange={(v) => { setModuleTypeFilter(v); resetOffset(); }}
              />
              <Dropdown
                value={findingSourceFilter}
                options={[
                  { value: '', label: 'source:all' },
                  { value: 'audit', label: 'audit' },
                  { value: 'spa', label: 'spa' },
                  { value: 'agent', label: 'agent' },
                  { value: 'oast', label: 'oast' },
                  { value: 'source-tools', label: 'source-tools' },
                  { value: 'extension', label: 'extension' },
                ]}
                onChange={(v) => { setFindingSourceFilter(v); resetOffset(); }}
              />
              <div className="flex items-center border border-[#bbc3c4] bg-[#f6edda] focus-within:border-[#0078c8]/50">
                <Search className="w-3 h-3 text-[#708e8e] ml-1.5 shrink-0" />
                <input type="text" value={searchInput} onChange={(e) => { setSearchInput(e.target.value); resetOffset(); }} placeholder="search..." className="bg-transparent text-[#005661] text-xs px-1.5 py-0.5 w-36 focus:outline-none" />
              </div>
              {viewTab === 'table' && (
                <ColumnChooser columns={toggleableColumns} hiddenColumns={hiddenColumns} onChange={setHiddenColumns} />
              )}
            </div>
          </div>

          {/* Action toolbar */}
          {viewTab === 'table' && selectedRows.length > 0 && (
            <div className="px-3 py-1.5 border-b border-[#bbc3c4] bg-[#ede4d1] flex items-center gap-3 text-xs">
              <span className="text-[#005661]">{selectedRows.length} selected</span>
              <button
                onClick={handleDeleteSelected}
                disabled={deleteFinding.isPending}
                className="px-2 py-0.5 border border-[#e34e1c]/50 text-[#e34e1c] hover:bg-[#e34e1c]/10 disabled:opacity-50 transition-colors"
              >
                {deleteFinding.isPending ? 'deleting...' : '[DELETE SELECTED]'}
              </button>
            </div>
          )}

          {/* Table view */}
          {viewTab === 'table' && (
            <>
              <div className={`${AG_GRID_THEME} w-full flex-1`}>
                <AgGridReact<Finding>
                  ref={gridRef}
                  rowData={data?.data || []}
                  columnDefs={effectiveColumnDefs}
                  loading={isLoading}
                  suppressCellFocus
                  animateRows
                  domLayout="normal"
                  onRowClicked={onRowClicked}
                  rowSelection={{ mode: 'multiRow', headerCheckbox: true, checkboxes: true, enableClickSelection: false }}
                  onSelectionChanged={onSelectionChanged}
                  overlayNoRowsTemplate='<span style="color:#bbc3c4">no findings</span>'
                />
              </div>

              {(data?.total || 0) > 0 && (
                <div className="flex items-center justify-between px-3 py-1 border-t border-[#bbc3c4] text-xs text-[#708e8e]">
                  <span>
                    {(params.offset || 0) + 1}-{Math.min((params.offset || 0) + PAGE_SIZE, data?.total || 0)}/{data?.total || 0}
                  </span>
                  <div className="flex items-center gap-1">
                    <button onClick={() => goToPage(currentPage - 1)} disabled={currentPage <= 1} className="hover:text-[#0078c8] disabled:opacity-30 px-1">{'<'}</button>
                    <span className="px-1">{currentPage}/{totalPages}</span>
                    <button onClick={() => goToPage(currentPage + 1)} disabled={currentPage >= totalPages} className="hover:text-[#0078c8] disabled:opacity-30 px-1">{'>'}</button>
                  </div>
                </div>
              )}
            </>
          )}

          {/* Grouped by host view */}
          {viewTab === 'by-host' && (
            <>
              {isLoading ? (
                <div className="p-3 text-xs text-[#708e8e]">loading...</div>
              ) : (
                <GroupedByHostView
                  findings={data?.data || []}
                  onSelectFinding={(id) => navigateToFinding(selectedFindingId === id ? null : id)}
                  selectedFindingId={selectedFindingId}
                />
              )}
              {(data?.total || 0) > 0 && (
                <div className="flex items-center justify-between px-3 py-1 border-t border-[#bbc3c4] text-xs text-[#708e8e]">
                  <span>
                    {(params.offset || 0) + 1}-{Math.min((params.offset || 0) + PAGE_SIZE, data?.total || 0)}/{data?.total || 0}
                  </span>
                  <div className="flex items-center gap-1">
                    <button onClick={() => goToPage(currentPage - 1)} disabled={currentPage <= 1} className="hover:text-[#0078c8] disabled:opacity-30 px-1">{'<'}</button>
                    <span className="px-1">{currentPage}/{totalPages}</span>
                    <button onClick={() => goToPage(currentPage + 1)} disabled={currentPage >= totalPages} className="hover:text-[#0078c8] disabled:opacity-30 px-1">{'>'}</button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Detail panel */}
        {selectedFindingId !== null && (
          <div className="w-1/2">
            <FindingDetailPanel
              findingId={selectedFindingId}
              onClose={() => navigateToFinding(null)}
            />
          </div>
        )}
      </div>
    </PageShell>
  );
}
