'use client';

import { useState, useMemo, useCallback } from 'react';
import { AgGridReact } from 'ag-grid-react';
import type { ColDef } from 'ag-grid-community';
import { useHttpRecords } from '@/api/hooks';
import type { HTTPRecord, HttpRecordsQueryParams } from '@/api/types';
import { registerAgGrid } from '@/lib/ag-grid-register';
import { formatDate, formatBytes } from '@/lib/formatters';
import { METHOD_COLORS, STATUS_COLORS, AG_GRID_THEME } from './theme';
import { Search, Columns3 } from 'lucide-react';

registerAgGrid();

const PAGE_SIZE = 50;

function MethodRenderer({ value }: { value: string }) {
  const color = METHOD_COLORS[value] || '#708e8e';
  return (
    <span className="text-xs font-bold" style={{ color }}>
      {value}
    </span>
  );
}

function StatusRenderer({ value }: { value: number }) {
  if (!value) return <span className="text-[#bbc3c4] text-xs">---</span>;
  const cat = `${Math.floor(value / 100)}xx`;
  const color = STATUS_COLORS[cat] || '#708e8e';
  return (
    <span className="text-xs font-bold" style={{ color }}>
      {value}
    </span>
  );
}

function BytesRenderer({ value }: { value: number }) {
  return <span className="text-xs text-[#708e8e]">{formatBytes(value)}</span>;
}

function DateRenderer({ value }: { value: string }) {
  return <span className="text-xs text-[#708e8e]">{formatDate(value)}</span>;
}

const CTYPE_COLORS: Record<string, string> = {
  html: '#0078c8',
  json: '#00b368',
  xml: '#005661',
  javascript: '#f49725',
  css: '#ff5792',
  text: '#708e8e',
  image: '#e34e1c',
  font: '#8b6914',
  pdf: '#b45309',
  form: '#00bdd6',
  multipart: '#00bdd6',
  octet: '#708e8e',
  video: '#e34e1c',
  audio: '#00b368',
};

function ContentTypeRenderer({ value }: { value: string }) {
  if (!value) return <span className="text-[#bbc3c4] text-xs">—</span>;
  const lower = value.toLowerCase();
  const matched = Object.keys(CTYPE_COLORS).find((k) => lower.includes(k));
  const color = matched ? CTYPE_COLORS[matched] : '#708e8e';
  return <span className="text-xs font-bold" style={{ color }}>{value}</span>;
}

const ALL_COLUMNS: { field: string; headerName: string; def: ColDef<HTTPRecord> }[] = [
  { field: 'method', headerName: 'METH', def: { field: 'method', headerName: 'METH', width: 70, cellRenderer: MethodRenderer } },
  { field: 'status_code', headerName: 'SC', def: { field: 'status_code', headerName: 'SC', width: 55, cellRenderer: StatusRenderer } },
  { field: 'hostname', headerName: 'HOST', def: { field: 'hostname', headerName: 'HOST', flex: 1, minWidth: 120 } },
  { field: 'path', headerName: 'PATH', def: { field: 'path', headerName: 'PATH', flex: 2, minWidth: 160 } },
  { field: 'response_time_ms', headerName: 'MS', def: { field: 'response_time_ms', headerName: 'MS', width: 60, valueFormatter: (p) => (p.value ? `${p.value}` : '-') } },
  { field: 'response_content_type', headerName: 'CTYPE', def: { field: 'response_content_type', headerName: 'CTYPE', width: 110, cellRenderer: ContentTypeRenderer } },
  { field: 'response_content_length', headerName: 'SIZE', def: { field: 'response_content_length', headerName: 'SIZE', width: 70, cellRenderer: BytesRenderer } },
  { field: 'response_title', headerName: 'TITLE', def: { field: 'response_title', headerName: 'TITLE', flex: 1, minWidth: 100 } },
  { field: 'response_words', headerName: 'WORDS', def: { field: 'response_words', headerName: 'WORDS', width: 65, valueFormatter: (p) => (p.value != null ? `${p.value}` : '-') } },
  { field: 'risk_score', headerName: 'RISK', def: { field: 'risk_score', headerName: 'RISK', width: 50 } },
  { field: 'source', headerName: 'SRC', def: { field: 'source', headerName: 'SRC', width: 60 } },
  { field: 'sent_at', headerName: 'TIME', def: { field: 'sent_at', headerName: 'TIME', width: 120, cellRenderer: DateRenderer } },
];

const DEFAULT_VISIBLE = new Set([
  'method', 'status_code', 'hostname', 'path', 'response_time_ms',
  'response_content_type', 'response_content_length',
  'response_title', 'response_words',
  'sent_at',
]);

export default function HttpRecordsTable() {
  const [params, setParams] = useState<HttpRecordsQueryParams>({
    limit: PAGE_SIZE,
    offset: 0,
  });
  const [searchInput, setSearchInput] = useState('');
  const [methodFilter, setMethodFilter] = useState('');
  const [visibleCols, setVisibleCols] = useState<Set<string>>(() => new Set(DEFAULT_VISIBLE));
  const [showColPicker, setShowColPicker] = useState(false);

  const toggleColumn = useCallback((field: string) => {
    setVisibleCols((prev) => {
      const next = new Set(prev);
      if (next.has(field)) next.delete(field);
      else next.add(field);
      return next;
    });
  }, []);

  const queryParams = useMemo(
    () => ({
      ...params,
      method: methodFilter || undefined,
      search: searchInput || undefined,
    }),
    [params, methodFilter, searchInput]
  );

  const { data, isLoading } = useHttpRecords(queryParams);

  const columnDefs = useMemo<ColDef<HTTPRecord>[]>(
    () => ALL_COLUMNS.filter((c) => visibleCols.has(c.field)).map((c) => c.def),
    [visibleCols]
  );

  const currentPage = Math.floor((params.offset || 0) / PAGE_SIZE) + 1;
  const totalPages = Math.ceil((data?.total || 0) / PAGE_SIZE);

  const goToPage = useCallback((page: number) => {
    setParams((prev) => ({ ...prev, offset: (page - 1) * PAGE_SIZE }));
  }, []);

  return (
    <div className="border border-[#bbc3c4] bg-[#f6edda] overflow-hidden">
      {(data?.total || 0) > 0 && (
        <div className="flex items-center justify-between px-3 py-1 border-b border-[#bbc3c4] text-xs text-[#708e8e]">
          <span>
            {(params.offset || 0) + 1}-{Math.min((params.offset || 0) + PAGE_SIZE, data?.total || 0)}/{data?.total || 0}
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => goToPage(currentPage - 1)}
              disabled={currentPage <= 1}
              className="hover:text-[#0078c8] disabled:opacity-30 px-1"
            >
              {'<'}
            </button>
            <span className="px-1">
              {currentPage}/{totalPages}
            </span>
            <button
              onClick={() => goToPage(currentPage + 1)}
              disabled={currentPage >= totalPages}
              className="hover:text-[#0078c8] disabled:opacity-30 px-1"
            >
              {'>'}
            </button>
          </div>
        </div>
      )}
      <div className="px-3 py-1.5 border-b border-[#bbc3c4] flex items-center justify-between flex-wrap gap-2">
        <span className="text-[#0078c8] text-xs font-bold">HTTP_RECORDS</span>
        <div className="flex items-center gap-2 text-xs">
          <div className="relative">
            <button
              onClick={() => setShowColPicker((v) => !v)}
              className={`flex items-center gap-1 px-1.5 py-0.5 border border-[#bbc3c4] hover:border-[#708e8e] transition-colors ${showColPicker ? 'text-[#0078c8] border-[#0078c8]/50' : 'text-[#708e8e]'}`}
            >
              <Columns3 className="w-3 h-3" />
              columns
            </button>
            {showColPicker && (
              <div className="absolute right-0 top-full mt-1 z-50 bg-[#f6edda] border border-[#bbc3c4] shadow-lg py-1 min-w-[140px]">
                {ALL_COLUMNS.map((col) => (
                  <label
                    key={col.field}
                    className="flex items-center gap-2 px-2.5 py-1 hover:bg-[#e8dcc8] cursor-pointer text-[#708e8e] hover:text-[#005661]"
                  >
                    <input
                      type="checkbox"
                      checked={visibleCols.has(col.field)}
                      onChange={() => toggleColumn(col.field)}
                      className="accent-[#0078c8]"
                    />
                    {col.headerName}
                  </label>
                ))}
              </div>
            )}
          </div>
          <select
            value={methodFilter}
            onChange={(e) => {
              setMethodFilter(e.target.value);
              setParams((p) => ({ ...p, offset: 0 }));
            }}
            className="bg-[#f6edda] border border-[#bbc3c4] text-[#005661] text-xs px-1.5 py-0.5 focus:outline-none focus:border-[#0078c8]/50"
          >
            <option value="">all</option>
            {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map((m) => (
              <option key={m} value={m}>{m}</option>
            ))}
          </select>
          <div className="flex items-center border border-[#bbc3c4] focus-within:border-[#0078c8]/50">
            <Search className="w-3 h-3 text-[#708e8e] ml-1.5 shrink-0" />
            <input
              type="text"
              value={searchInput}
              onChange={(e) => {
                setSearchInput(e.target.value);
                setParams((p) => ({ ...p, offset: 0 }));
              }}
              placeholder="search..."
              className="bg-transparent text-[#005661] text-xs px-1.5 py-0.5 w-32 focus:outline-none"
            />
          </div>
        </div>
      </div>

      <div className={`${AG_GRID_THEME} w-full`} style={{ height: 500 }}>
        <AgGridReact<HTTPRecord>
          rowData={data?.data || []}
          columnDefs={columnDefs}
          loading={isLoading}
          suppressCellFocus
          animateRows
          domLayout="normal"
          overlayNoRowsTemplate='<span style="color:#bbc3c4">no records</span>'
        />
      </div>

    </div>
  );
}
