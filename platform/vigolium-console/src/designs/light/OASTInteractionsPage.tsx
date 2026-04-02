'use client';

import { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { AgGridReact } from 'ag-grid-react';
import type { ColDef, RowClickedEvent, SelectionChangedEvent } from 'ag-grid-community';
import { Network, Box, ArrowUpDown, ArrowUp, ArrowDown, Search, RefreshCw } from 'lucide-react';
import { useOASTInteractions, useDeleteOASTInteraction } from '@/api/hooks';
import { useToast } from '@/contexts/ToastContext';
import type { OASTInteraction, OASTInteractionsQueryParams } from '@/api/types';

import { registerAgGrid } from '@/lib/ag-grid-register';
import { formatDate } from '@/lib/formatters';
import { PROTOCOL_COLORS, AG_GRID_THEME } from './theme';
import PageShell from './PageShell';
import OASTInteractionDetailPanel from './OASTInteractionDetailPanel';
import Dropdown from './Dropdown';

registerAgGrid();

const PAGE_SIZE = 100;

function ProtocolRenderer({ value }: { value: string }) {
  const color = PROTOCOL_COLORS[value?.toLowerCase()] || '#708e8e';
  return (
    <span className="text-xs font-bold" style={{ color }}>
      {value}
    </span>
  );
}

function DateRenderer({ value }: { value: string }) {
  return <span className="text-xs text-[#708e8e]">{formatDate(value)}</span>;
}

export default function OASTInteractionsPage({ initialId }: { initialId?: number | null }) {
  const [params, setParams] = useState<OASTInteractionsQueryParams>({
    limit: PAGE_SIZE,
    offset: 0,
  });
  const [searchInput, setSearchInput] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('');
  const [moduleFilter, setModuleFilter] = useState('');
  const [sortField, setSortField] = useState('');
  const [sortOrder, setSortOrder] = useState('');
  const [selectedId, setSelectedId] = useState<number | null>(initialId ?? null);
  const [selectedRows, setSelectedRows] = useState<OASTInteraction[]>([]);
  const gridRef = useRef<AgGridReact<OASTInteraction>>(null);

  useEffect(() => {
    setSelectedId(initialId ?? null);
  }, [initialId]);

  const navigateToInteraction = useCallback((id: number | null) => {
    setSelectedId(id);
    window.history.pushState(null, '', id !== null ? `/oast-interactions/${id}` : '/oast-interactions');
  }, []);

  const queryParams = useMemo(
    () => ({
      ...params,
      protocol: protocolFilter || undefined,
      module_id: moduleFilter || undefined,
      search: searchInput || undefined,
      sort: sortField || undefined,
      order: sortOrder || undefined,
    }),
    [params, protocolFilter, moduleFilter, searchInput, sortField, sortOrder]
  );

  const { data, isLoading, refetch, isFetching } = useOASTInteractions(queryParams);
  const deleteInteraction = useDeleteOASTInteraction();
  const { toast } = useToast();

  const handleDelete = useCallback((id: number) => {
    deleteInteraction.mutate(id, {
      onSuccess: (res) => {
        toast(res.message, 'success');
        navigateToInteraction(null);
      },
      onError: (err) => {
        toast((err as Error).message, 'error');
      },
    });
  }, [deleteInteraction, toast, navigateToInteraction]);

  const handleDeleteSelected = useCallback(async () => {
    const ids = selectedRows.map((r) => r.id);
    const results = await Promise.allSettled(ids.map((id) => deleteInteraction.mutateAsync(id)));
    const succeeded = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.length - succeeded;
    if (failed === 0) {
      toast(`Deleted ${succeeded} interaction(s)`, 'success');
    } else {
      toast(`Deleted ${succeeded}, failed ${failed}`, 'error');
    }
    setSelectedRows([]);
    gridRef.current?.api?.deselectAll();
    if (selectedId !== null && ids.includes(selectedId)) navigateToInteraction(null);
  }, [selectedRows, deleteInteraction, toast, selectedId, navigateToInteraction]);

  const columnDefs = useMemo<ColDef<OASTInteraction>[]>(
    () => [
      { width: 40, sortable: false, filter: false, resizable: false },
      { field: 'id', headerName: 'ID', width: 60 },
      { field: 'protocol', headerName: 'PROTO', width: 80, cellRenderer: ProtocolRenderer },
      { field: 'unique_id', headerName: 'UNIQUE_ID', flex: 1, minWidth: 120 },
      { field: 'q_type', headerName: 'QTYPE', width: 70 },
      { field: 'target_url', headerName: 'TARGET_URL', flex: 2, minWidth: 160 },
      { field: 'parameter_name', headerName: 'PARAM', flex: 1, minWidth: 80 },
      { field: 'injection_type', headerName: 'INJ_TYPE', width: 100 },
      { field: 'module_id', headerName: 'MODULE', width: 120 },
      { field: 'remote_address', headerName: 'REMOTE_ADDR', width: 130 },
      { field: 'interacted_at', headerName: 'TIME', width: 120, cellRenderer: DateRenderer },
    ],
    []
  );

  const currentPage = Math.floor((params.offset || 0) / PAGE_SIZE) + 1;
  const totalPages = Math.ceil((data?.total || 0) / PAGE_SIZE);

  const goToPage = useCallback((page: number) => {
    setParams((prev) => ({ ...prev, offset: (page - 1) * PAGE_SIZE }));
  }, []);

  const resetOffset = () => setParams((p) => ({ ...p, offset: 0 }));

  const selectedIdRef = useRef(selectedId);
  selectedIdRef.current = selectedId;

  const onRowClicked = useCallback((event: RowClickedEvent<OASTInteraction>) => {
    const target = event.event?.target as HTMLElement | undefined;
    if (target?.closest('.ag-checkbox-input-wrapper, .ag-selection-checkbox')) return;
    if (event.data?.id) {
      navigateToInteraction(selectedIdRef.current === event.data!.id ? null : event.data!.id);
    }
  }, [navigateToInteraction]);

  const onSelectionChanged = useCallback((event: SelectionChangedEvent<OASTInteraction>) => {
    setSelectedRows(event.api.getSelectedRows());
  }, []);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && selectedIdRef.current !== null) {
        const tag = (e.target as HTMLElement)?.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA') return;
        navigateToInteraction(null);
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [navigateToInteraction]);

  const inputClass = "bg-[#f6edda] border border-[#bbc3c4] text-[#005661] text-xs px-2 py-0.5 focus:outline-none focus:border-[#0078c8]/50";

  return (
    <PageShell>
      <div className="flex" style={{ height: 'calc(100vh - 120px)', minHeight: 500 }}>
        {/* Table section */}
        <div className={`border border-[#bbc3c4] bg-[#f6edda] overflow-hidden flex flex-col ${selectedId !== null ? 'w-1/2' : 'w-full'} transition-all`}>
          <div className="px-3 py-1.5 border-b border-[#bbc3c4] flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-1.5">
              <span className="text-[#0078c8] text-xs font-bold">OAST_INTERACTIONS</span>
              <button onClick={() => refetch()} className="text-[#708e8e] hover:text-[#0078c8] transition-colors" title="Refresh">
                <RefreshCw className={`w-3 h-3 ${isFetching ? 'animate-spin' : ''}`} />
              </button>
            </div>
            <div className="flex items-center gap-2 text-xs flex-wrap">
              <Dropdown
                value={protocolFilter}
                icon={<Network className="w-3 h-3" />}
                options={[
                  { value: '', label: 'proto:all' },
                  ...['dns', 'http', 'ldap', 'smtp'].map((p) => ({ value: p, label: p })),
                ]}
                onChange={(v) => { setProtocolFilter(v); resetOffset(); }}
              />
              <div className="flex items-center border border-[#bbc3c4] bg-[#f6edda] focus-within:border-[#0078c8]/50">
                <Box className="w-3 h-3 text-[#708e8e] ml-1.5 shrink-0" />
                <input type="text" value={moduleFilter} onChange={(e) => { setModuleFilter(e.target.value); resetOffset(); }} placeholder="module..." className="bg-transparent text-[#005661] text-xs px-1.5 py-0.5 w-28 focus:outline-none" />
              </div>
              <Dropdown
                value={sortField}
                icon={<ArrowUpDown className="w-3 h-3" />}
                options={[
                  { value: '', label: 'sort:default' },
                  { value: 'interacted_at', label: 'time' },
                  { value: 'protocol', label: 'protocol' },
                ]}
                onChange={setSortField}
              />
              <Dropdown
                value={sortOrder}
                icon={sortOrder === 'desc' ? <ArrowDown className="w-3 h-3" /> : <ArrowUp className="w-3 h-3" />}
                options={[
                  { value: '', label: 'asc' },
                  { value: 'desc', label: 'desc' },
                ]}
                onChange={setSortOrder}
              />
              <div className="flex items-center border border-[#bbc3c4] bg-[#f6edda] focus-within:border-[#0078c8]/50">
                <Search className="w-3 h-3 text-[#708e8e] ml-1.5 shrink-0" />
                <input type="text" value={searchInput} onChange={(e) => { setSearchInput(e.target.value); resetOffset(); }} placeholder="search..." className="bg-transparent text-[#005661] text-xs px-1.5 py-0.5 w-36 focus:outline-none" />
              </div>
            </div>
          </div>

          {/* Action toolbar */}
          {selectedRows.length > 0 && (
            <div className="px-3 py-1.5 border-b border-[#bbc3c4] bg-[#ede4d1] flex items-center gap-3 text-xs">
              <span className="text-[#005661]">{selectedRows.length} selected</span>
              <button
                onClick={handleDeleteSelected}
                disabled={deleteInteraction.isPending}
                className="px-2 py-0.5 border border-[#e34e1c]/50 text-[#e34e1c] hover:bg-[#e34e1c]/10 disabled:opacity-50 transition-colors"
              >
                {deleteInteraction.isPending ? 'deleting...' : '[DELETE SELECTED]'}
              </button>
            </div>
          )}

          <div className={`${AG_GRID_THEME} w-full flex-1`}>
            <AgGridReact<OASTInteraction>
              ref={gridRef}
              rowData={data?.data || []}
              columnDefs={columnDefs}
              loading={isLoading}
              suppressCellFocus
              animateRows
              domLayout="normal"
              onRowClicked={onRowClicked}
              rowSelection={{ mode: 'multiRow', headerCheckbox: true, checkboxes: true, enableClickSelection: false }}
              onSelectionChanged={onSelectionChanged}
              overlayNoRowsTemplate='<span style="color:#bbc3c4">no interactions</span>'
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
        </div>

        {/* Detail panel */}
        {selectedId !== null && (
          <div className="w-1/2">
            <OASTInteractionDetailPanel
              id={selectedId}
              onClose={() => navigateToInteraction(null)}
              onDelete={handleDelete}
              isDeleting={deleteInteraction.isPending}
            />
          </div>
        )}
      </div>
    </PageShell>
  );
}
