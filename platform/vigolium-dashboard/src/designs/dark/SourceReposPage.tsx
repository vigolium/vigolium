'use client';

import { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { AgGridReact } from 'ag-grid-react';
import type { ColDef, RowClickedEvent, SelectionChangedEvent } from 'ag-grid-community';
import { Globe, ArrowUpDown, ArrowUp, ArrowDown, Search, RefreshCw } from 'lucide-react';
import { useSourceRepos, useDeleteSourceRepo } from '@/api/hooks';
import { useToast } from '@/contexts/ToastContext';
import type { SourceRepo, SourceReposQueryParams } from '@/api/types';

import { registerAgGrid } from '@/lib/ag-grid-register';
import { formatDate } from '@/lib/formatters';
import { AG_GRID_THEME } from './theme';
import PageShell from './PageShell';
import SourceRepoDetailPanel from './SourceRepoDetailPanel';
import Dropdown from './Dropdown';

registerAgGrid();

const PAGE_SIZE = 100;

const REPO_TYPE_COLORS: Record<string, string> = {
  git: '#68a8e4',
  folder: '#7fd962',
  archive: '#ff5c8f',
};

function RepoTypeRenderer({ value }: { value: string }) {
  const color = REPO_TYPE_COLORS[value?.toLowerCase()] || '#918175';
  return (
    <span className="text-xs font-bold" style={{ color }}>
      {value}
    </span>
  );
}

function DateRenderer({ value }: { value: string }) {
  return <span className="text-xs text-[#918175]">{formatDate(value)}</span>;
}

export default function SourceReposPage({ initialId }: { initialId?: number | null }) {
  const [params, setParams] = useState<SourceReposQueryParams>({
    limit: PAGE_SIZE,
    offset: 0,
  });
  const [searchInput, setSearchInput] = useState('');
  const [hostnameFilter, setHostnameFilter] = useState('');
  const [sortField, setSortField] = useState('');
  const [sortOrder, setSortOrder] = useState('');
  const [selectedId, setSelectedId] = useState<number | null>(initialId ?? null);
  const [selectedRows, setSelectedRows] = useState<SourceRepo[]>([]);
  const gridRef = useRef<AgGridReact<SourceRepo>>(null);

  useEffect(() => {
    setSelectedId(initialId ?? null);
  }, [initialId]);

  const navigateToRepo = useCallback((id: number | null) => {
    setSelectedId(id);
    window.history.pushState(null, '', id !== null ? `/source-repos/${id}` : '/source-repos');
  }, []);

  const queryParams = useMemo(
    () => ({
      ...params,
      hostname: hostnameFilter || undefined,
      search: searchInput || undefined,
      sort: sortField || undefined,
      order: sortOrder || undefined,
    }),
    [params, hostnameFilter, searchInput, sortField, sortOrder]
  );

  const { data, isLoading, refetch, isFetching } = useSourceRepos(queryParams);
  const deleteRepo = useDeleteSourceRepo();
  const { toast } = useToast();

  const handleDelete = useCallback((id: number) => {
    deleteRepo.mutate(id, {
      onSuccess: (res) => {
        toast(res.message, 'success');
        navigateToRepo(null);
      },
      onError: (err) => {
        toast((err as Error).message, 'error');
      },
    });
  }, [deleteRepo, toast, navigateToRepo]);

  const handleDeleteSelected = useCallback(async () => {
    const ids = selectedRows.map((r) => r.id);
    const results = await Promise.allSettled(ids.map((id) => deleteRepo.mutateAsync(id)));
    const succeeded = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.length - succeeded;
    if (failed === 0) {
      toast(`Deleted ${succeeded} repo(s)`, 'success');
    } else {
      toast(`Deleted ${succeeded}, failed ${failed}`, 'error');
    }
    setSelectedRows([]);
    gridRef.current?.api?.deselectAll();
    if (selectedId !== null && ids.includes(selectedId)) navigateToRepo(null);
  }, [selectedRows, deleteRepo, toast, selectedId, navigateToRepo]);

  const columnDefs = useMemo<ColDef<SourceRepo>[]>(
    () => [
      { headerCheckboxSelection: true, checkboxSelection: true, width: 40, sortable: false, filter: false, resizable: false },
      { field: 'id', headerName: 'ID', width: 60 },
      { field: 'name', headerName: 'NAME', flex: 2, minWidth: 140 },
      { field: 'hostname', headerName: 'HOSTNAME', flex: 1, minWidth: 120 },
      { field: 'repo_type', headerName: 'TYPE', width: 80, cellRenderer: RepoTypeRenderer },
      { field: 'language', headerName: 'LANG', width: 90 },
      { field: 'framework', headerName: 'FRAMEWORK', width: 110 },
      { field: 'root_path', headerName: 'ROOT_PATH', flex: 2, minWidth: 160 },
      { field: 'third_party_scan_status', headerName: 'SCAN_STATUS', width: 110 },
      { field: 'created_at', headerName: 'CREATED', width: 120, cellRenderer: DateRenderer },
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

  const onRowClicked = useCallback((event: RowClickedEvent<SourceRepo>) => {
    const target = event.event?.target as HTMLElement | undefined;
    if (target?.closest('.ag-checkbox-input-wrapper, .ag-selection-checkbox')) return;
    if (event.data?.id) {
      navigateToRepo(selectedIdRef.current === event.data!.id ? null : event.data!.id);
    }
  }, [navigateToRepo]);

  const onSelectionChanged = useCallback((event: SelectionChangedEvent<SourceRepo>) => {
    setSelectedRows(event.api.getSelectedRows());
  }, []);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && selectedIdRef.current !== null) {
        const tag = (e.target as HTMLElement)?.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA') return;
        navigateToRepo(null);
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [navigateToRepo]);

  return (
    <PageShell>
      <div className="flex" style={{ height: 'calc(100vh - 120px)', minHeight: 500 }}>
        {/* Table section */}
        <div className={`border border-[#2e2b26] bg-[#1c1b19] overflow-hidden flex flex-col ${selectedId !== null ? 'w-1/2' : 'w-full'} transition-all`}>
          <div className="px-3 py-1.5 border-b border-[#2e2b26] flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-1.5">
              <span className="text-[#7fd962] text-xs font-bold">SOURCE_REPOS</span>
              <button onClick={() => refetch()} className="text-[#918175] hover:text-[#7fd962] transition-colors" title="Refresh">
                <RefreshCw className={`w-3 h-3 ${isFetching ? 'animate-spin' : ''}`} />
              </button>
            </div>
            <div className="flex items-center gap-2 text-xs flex-wrap">
              <div className="flex items-center border border-[#2e2b26] bg-[#1c1b19] focus-within:border-[#7fd962]/50">
                <Globe className="w-3 h-3 text-[#918175] ml-1.5 shrink-0" />
                <input type="text" value={hostnameFilter} onChange={(e) => { setHostnameFilter(e.target.value); resetOffset(); }} placeholder="hostname..." className="bg-transparent text-[#fce8c3] text-xs px-1.5 py-0.5 w-28 focus:outline-none" />
              </div>
              <Dropdown
                value={sortField}
                icon={<ArrowUpDown className="w-3 h-3" />}
                options={[
                  { value: '', label: 'sort:default' },
                  { value: 'name', label: 'name' },
                  { value: 'created_at', label: 'created' },
                  { value: 'language', label: 'language' },
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
              <div className="flex items-center border border-[#2e2b26] bg-[#1c1b19] focus-within:border-[#7fd962]/50">
                <Search className="w-3 h-3 text-[#918175] ml-1.5 shrink-0" />
                <input type="text" value={searchInput} onChange={(e) => { setSearchInput(e.target.value); resetOffset(); }} placeholder="search..." className="bg-transparent text-[#fce8c3] text-xs px-1.5 py-0.5 w-36 focus:outline-none" />
              </div>
            </div>
          </div>

          {/* Action toolbar */}
          {selectedRows.length > 0 && (
            <div className="px-3 py-1.5 border-b border-[#2e2b26] bg-[#272520] flex items-center gap-3 text-xs">
              <span className="text-[#fce8c3]">{selectedRows.length} selected</span>
              <button
                onClick={handleDeleteSelected}
                disabled={deleteRepo.isPending}
                className="px-2 py-0.5 border border-[#ef2f27]/50 text-[#ef2f27] hover:bg-[#ef2f27]/10 disabled:opacity-50 transition-colors"
              >
                {deleteRepo.isPending ? 'deleting...' : '[DELETE SELECTED]'}
              </button>
            </div>
          )}

          <div className={`${AG_GRID_THEME} w-full flex-1`}>
            <AgGridReact<SourceRepo>
              ref={gridRef}
              rowData={data?.data || []}
              columnDefs={columnDefs}
              loading={isLoading}
              suppressCellFocus
              animateRows
              domLayout="normal"
              onRowClicked={onRowClicked}
              rowSelection="multiple"
              suppressRowClickSelection
              onSelectionChanged={onSelectionChanged}
              overlayNoRowsTemplate='<span style="color:#403d38">no source repos</span>'
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
        </div>

        {/* Detail panel */}
        {selectedId !== null && (
          <div className="w-1/2">
            <SourceRepoDetailPanel
              id={selectedId}
              onClose={() => navigateToRepo(null)}
              onDelete={handleDelete}
              isDeleting={deleteRepo.isPending}
            />
          </div>
        )}
      </div>
    </PageShell>
  );
}
