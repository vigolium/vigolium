'use client';

import { useState, useMemo, useCallback } from 'react';
import { AgGridReact } from 'ag-grid-react';
import type { ColDef } from 'ag-grid-community';
import { useFindings } from '@/api/hooks';
import type { Finding, FindingsQueryParams } from '@/api/types';
import { registerAgGrid } from '@/lib/ag-grid-register';
import { formatDate } from '@/lib/formatters';
import { SEVERITY_COLORS, CONFIDENCE_COLORS, AG_GRID_THEME } from './theme';
import { Search, RefreshCw } from 'lucide-react';

registerAgGrid();

const PAGE_SIZE = 50;

function SeverityRenderer({ value }: { value: string }) {
  const color = SEVERITY_COLORS[value] || '#918175';
  return (
    <span className="text-xs font-bold uppercase" style={{ color }}>
      {value}
    </span>
  );
}

function ConfidenceRenderer({ value }: { value: string }) {
  const color = CONFIDENCE_COLORS[value] || '#918175';
  return (
    <span className="text-xs" style={{ color }}>
      {value}
    </span>
  );
}

function DateRenderer({ value }: { value: string }) {
  return <span className="text-xs text-[#918175]">{formatDate(value)}</span>;
}

const HASH_COLORS = [
  '#7fd962', // lime
  '#68a8e4', // blue
  '#e4a868', // orange
  '#c678dd', // purple
  '#56b6c2', // cyan
  '#e06c75', // red
  '#d19a66', // amber
  '#98c379', // green
  '#e5c07b', // yellow
  '#61afef', // sky
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
          {i > 0 && <span className="text-[#918175]">, </span>}
          <span style={{ color: hashColor(tag) }}>{tag}</span>
        </span>
      ))}
    </span>
  );
}

export default function FindingsTable() {
  const [params, setParams] = useState<FindingsQueryParams>({
    limit: PAGE_SIZE,
    offset: 0,
  });
  const [searchInput, setSearchInput] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');

  const queryParams = useMemo(
    () => ({
      ...params,
      severity: severityFilter || undefined,
      search: searchInput || undefined,
    }),
    [params, severityFilter, searchInput]
  );

  const { data, isLoading, refetch, isFetching } = useFindings(queryParams);

  const columnDefs = useMemo<ColDef<Finding>[]>(
    () => [
      { field: 'id', headerName: 'ID', width: 60 },
      { field: 'severity', headerName: 'SEV', width: 80, cellRenderer: SeverityRenderer },
      { field: 'confidence', headerName: 'CONF', width: 80, cellRenderer: ConfidenceRenderer },
      { field: 'module_name', headerName: 'MODULE', flex: 1, minWidth: 140 },
      { field: 'module_type', headerName: 'TYPE', width: 80 },
      { field: 'finding_source', headerName: 'SOURCE', width: 120 },
      { field: 'repo_name', headerName: 'REPO', width: 140, cellRenderer: RepoNameRenderer },
      { field: 'source_file', headerName: 'FILE', width: 160 },
      { field: 'description', headerName: 'DESCRIPTION', flex: 2, minWidth: 180 },
      {
        field: 'matched_at',
        headerName: 'MATCHED_AT',
        flex: 1,
        minWidth: 100,
        valueFormatter: (p) => (p.value as string[])?.join(', ') || '',
      },
      {
        field: 'tags',
        headerName: 'TAGS',
        width: 120,
        cellRenderer: TagsRenderer,
        valueFormatter: (p) => (p.value as string[])?.join(', ') || '',
      },
      { field: 'found_at', headerName: 'TIME', width: 120, cellRenderer: DateRenderer },
    ],
    []
  );

  const currentPage = Math.floor((params.offset || 0) / PAGE_SIZE) + 1;
  const totalPages = Math.ceil((data?.total || 0) / PAGE_SIZE);

  const goToPage = useCallback((page: number) => {
    setParams((prev) => ({ ...prev, offset: (page - 1) * PAGE_SIZE }));
  }, []);

  return (
    <div className="border border-[#2e2b26] bg-[#1c1b19] overflow-hidden">
      {(data?.total || 0) > 0 && (
        <div className="flex items-center justify-between px-3 py-1 border-b border-[#2e2b26] text-xs text-[#918175]">
          <span>
            {(params.offset || 0) + 1}-{Math.min((params.offset || 0) + PAGE_SIZE, data?.total || 0)}/{data?.total || 0}
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => goToPage(currentPage - 1)}
              disabled={currentPage <= 1}
              className="hover:text-[#7fd962] disabled:opacity-30 px-1"
            >
              {'<'}
            </button>
            <span className="px-1">
              {currentPage}/{totalPages}
            </span>
            <button
              onClick={() => goToPage(currentPage + 1)}
              disabled={currentPage >= totalPages}
              className="hover:text-[#7fd962] disabled:opacity-30 px-1"
            >
              {'>'}
            </button>
          </div>
        </div>
      )}
      <div className="px-3 py-1.5 border-b border-[#2e2b26] flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-1.5">
          <span className="text-[#7fd962] text-xs font-bold">FINDINGS</span>
          <button onClick={() => refetch()} className="text-[#918175] hover:text-[#7fd962] transition-colors" title="Refresh">
            <RefreshCw className={`w-3 h-3 ${isFetching ? 'animate-spin' : ''}`} />
          </button>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setParams((p) => ({ ...p, offset: 0 }));
            }}
            className="bg-[#1c1b19] border border-[#2e2b26] text-[#fce8c3] text-xs px-1.5 py-0.5 focus:outline-none focus:border-[#7fd962]/50"
          >
            <option value="">all</option>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
            <option value="info">info</option>
          </select>
          <div className="flex items-center border border-[#2e2b26] focus-within:border-[#7fd962]/50">
            <Search className="w-3 h-3 text-[#918175] ml-1.5 shrink-0" />
            <input
              type="text"
              value={searchInput}
              onChange={(e) => {
                setSearchInput(e.target.value);
                setParams((p) => ({ ...p, offset: 0 }));
              }}
              placeholder="search..."
              className="bg-transparent text-[#fce8c3] text-xs px-1.5 py-0.5 w-32 focus:outline-none"
            />
          </div>
        </div>
      </div>

      <div className={`${AG_GRID_THEME} w-full`} style={{ height: 500 }}>
        <AgGridReact<Finding>
          rowData={data?.data || []}
          columnDefs={columnDefs}
          loading={isLoading}
          suppressCellFocus
          animateRows
          domLayout="normal"
          overlayNoRowsTemplate='<span style="color:#403d38">no findings</span>'
        />
      </div>

    </div>
  );
}
