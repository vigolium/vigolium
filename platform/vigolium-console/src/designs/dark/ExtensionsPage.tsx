'use client';

import { useState, useMemo, useCallback, useEffect, useRef } from 'react';
import { AgGridReact } from 'ag-grid-react';
import type { ColDef, RowClickedEvent } from 'ag-grid-community';
import { Zap, Eye, Search, RefreshCw } from 'lucide-react';
import { useExtensions, useExtensionDocs } from '@/api/hooks';
import type { Extension, ExtensionApiFunction } from '@/api/types';
import { useToast } from '@/contexts/ToastContext';
import { registerAgGrid } from '@/lib/ag-grid-register';
import { SEVERITY_COLORS, CONFIDENCE_COLORS, AG_GRID_THEME } from './theme';
import PageShell from './PageShell';
import ExtensionDetailPanel from './ExtensionDetailPanel';

registerAgGrid();

type Tab = 'extensions' | 'docs';

// --- Extensions table renderers ---

function IdRenderer({ value }: { value: number }) {
  return <span className="text-xs font-bold" style={{ color: '#68a8e4' }}>{value}</span>;
}

function LangRenderer({ value }: { value: string }) {
  const color = value === 'js' ? '#f0c674' : value === 'yaml' ? '#b294bb' : '#918175';
  return <span className="text-xs font-bold" style={{ color }}>{value}</span>;
}

function SeverityRenderer({ value }: { value: string }) {
  return (
    <span className="text-xs font-bold uppercase" style={{ color: SEVERITY_COLORS[value] || '#918175' }}>
      {value}
    </span>
  );
}

function ConfidenceRenderer({ value }: { value: string }) {
  return (
    <span className="text-xs font-bold uppercase" style={{ color: CONFIDENCE_COLORS[value] || '#918175' }}>
      {value}
    </span>
  );
}

function TypeRenderer({ value }: { value: string }) {
  return (
    <span className={`text-xs font-bold uppercase ${value === 'active' ? 'text-[#68a8e4]' : 'text-[#baa67f]'}`}>
      {value}
    </span>
  );
}

function ScanTypesRenderer({ value }: { value: string[] }) {
  return <span className="text-xs text-[#a89888]">{value?.join(', ') || '—'}</span>;
}

function TagsRenderer({ value }: { value: string[] }) {
  if (!value || value.length === 0) return <span className="text-xs text-[#403d38]">—</span>;
  return (
    <span className="flex items-center gap-1 flex-wrap py-0.5">
      {value.map((tag) => (
        <span key={tag} className="text-[9px] px-1 py-0 bg-[#272520] border border-[#2e2b26] text-[#68a8e4]">{tag}</span>
      ))}
    </span>
  );
}

// --- API Docs table renderers ---

const CATEGORY_COLORS: Record<string, string> = {
  http: '#68a8e4',
  scan: '#7fd962',
  ingest: '#f0c674',
  source: '#2be4d0',
  db: '#ff5c8f',
  database: '#ff5c8f',
  parse: '#0aaeb3',
  agent: '#b294bb',
  log: '#e8b84b',
  utils: '#c07840',
};

function CategoryRenderer({ value }: { value: string }) {
  const color = CATEGORY_COLORS[value?.toLowerCase()] || '#918175';
  return <span className="text-xs font-bold" style={{ color }}>{value}</span>;
}

function NamespaceRenderer({ value }: { value: string }) {
  const tail = value?.split('.').pop()?.toLowerCase() || '';
  const color = CATEGORY_COLORS[tail] || '#918175';
  return <span className="text-xs font-bold" style={{ color }}>{value}</span>;
}

const RETURNS_COLORS: Record<string, string> = {
  void: '#706560',
  boolean: '#7fd962',
  string: '#2be4d0',
  number: '#f0c674',
  object: '#68a8e4',
  array: '#b294bb',
};

function ReturnsRenderer({ value }: { value: string }) {
  const color = RETURNS_COLORS[value?.toLowerCase()] || '#918175';
  return <span className="text-xs font-bold" style={{ color }}>{value}</span>;
}

export default function ExtensionsPage() {
  const [tab, setTab] = useState<Tab>('extensions');
  const [typeFilter, setTypeFilter] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [docsSearch, setDocsSearch] = useState('');
  const [selectedFileName, setSelectedFileName] = useState<string | null>(null);

  const queryParams = useMemo(
    () => ({
      type: typeFilter || undefined,
      search: searchInput || undefined,
    }),
    [typeFilter, searchInput]
  );

  const { data: extData, isLoading: extLoading, refetch: extRefetch, isFetching: extFetching } = useExtensions(queryParams);
  const { data: docsData, isLoading: docsLoading, refetch: docsRefetch, isFetching: docsFetching } = useExtensionDocs(docsSearch || undefined);

  const extColumnDefs = useMemo<ColDef<Extension>[]>(
    () => [
      { field: 'id', headerName: 'ID', width: 220, cellRenderer: IdRenderer },
      { field: 'name', headerName: 'NAME', flex: 2, minWidth: 160 },
      { field: 'language', headerName: 'LANG', width: 80, cellRenderer: LangRenderer },
      { field: 'type', headerName: 'TYPE', width: 80, cellRenderer: TypeRenderer },
      { field: 'severity', headerName: 'SEVERITY', width: 90, cellRenderer: SeverityRenderer },
      { field: 'confidence', headerName: 'CONFIDENCE', width: 100, cellRenderer: ConfidenceRenderer },
      { field: 'scan_types', headerName: 'SCAN TYPES', flex: 1, minWidth: 120, cellRenderer: ScanTypesRenderer, valueFormatter: (p) => (p.value as string[])?.join(', ') || '' },
      { field: 'tags', headerName: 'TAGS', flex: 1, minWidth: 140, cellRenderer: TagsRenderer, valueFormatter: (p) => (p.value as string[])?.join(', ') || '' },
    ],
    []
  );

  const docsColumnDefs = useMemo<ColDef<ExtensionApiFunction>[]>(
    () => [
      { field: 'category', headerName: 'CATEGORY', width: 160, cellRenderer: NamespaceRenderer, wrapText: true, autoHeight: true },
      { field: 'namespace', headerName: 'NAMESPACE', width: 180, cellRenderer: NamespaceRenderer },
      { field: 'name', headerName: 'FUNCTION', width: 140 },
      { field: 'signature', headerName: 'SIGNATURE', flex: 2, minWidth: 200 },
      { field: 'returns', headerName: 'RETURNS', width: 150, cellRenderer: ReturnsRenderer, wrapText: true, autoHeight: true },
      { field: 'description', headerName: 'DESCRIPTION', flex: 2, minWidth: 200, wrapText: true, autoHeight: true },
    ],
    []
  );

  const { toast } = useToast();

  const selectedFileNameRef = useRef(selectedFileName);
  selectedFileNameRef.current = selectedFileName;

  const onExtRowClicked = useCallback((event: RowClickedEvent<Extension>) => {
    if (event.data?.file_name) {
      setSelectedFileName((prev) => (prev === event.data!.file_name ? null : event.data!.file_name));
    }
  }, []);

  const onDocsRowClicked = useCallback((event: RowClickedEvent<ExtensionApiFunction>) => {
    const row = event.data;
    if (row) {
      const fullName = row.namespace ? `${row.namespace}.${row.name}` : row.name;
      navigator.clipboard.writeText(fullName).then(() => {
        toast(`Copied: ${fullName}`, 'success');
      });
    }
  }, [toast]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && selectedFileNameRef.current !== null) {
        const tag = (e.target as HTMLElement)?.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA') return;
        setSelectedFileName(null);
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, []);

  const tabBtnClass = (active: boolean) =>
    `px-3 py-0.5 text-xs font-bold transition-colors ${
      active
        ? 'text-[#7fd962] bg-[#7fd962]/10'
        : 'text-[#918175] hover:text-[#fce8c3]'
    }`;

  return (
    <PageShell>
      <div className="flex" style={{ height: 'calc(100vh - 120px)', minHeight: 500 }}>
        {/* Table section */}
        <div className={`border border-[#2e2b26] bg-[#1c1b19] overflow-hidden flex flex-col ${selectedFileName !== null ? 'w-1/2' : 'w-full'} transition-all`}>
          <div className="px-3 py-1.5 border-b border-[#2e2b26] flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-1.5">
              {/* Tab bar */}
              <div className="flex border border-[#2e2b26]">
                <button onClick={() => { setTab('extensions'); setSelectedFileName(null); }} className={tabBtnClass(tab === 'extensions')}>
                  ENABLED EXTENSIONS
                </button>
                <button onClick={() => { setTab('docs'); setSelectedFileName(null); }} className={tabBtnClass(tab === 'docs')}>
                  API DOCS
                </button>
              </div>
              <button
                onClick={() => tab === 'extensions' ? extRefetch() : docsRefetch()}
                className="text-[#918175] hover:text-[#7fd962] transition-colors"
                title="Refresh"
              >
                <RefreshCw className={`w-3 h-3 ${(tab === 'extensions' ? extFetching : docsFetching) ? 'animate-spin' : ''}`} />
              </button>
            </div>
            <div className="flex items-center gap-2 text-xs">
              {tab === 'extensions' && (
                <>
                  <div className="flex border border-[#2e2b26]">
                    <button
                      onClick={() => setTypeFilter('')}
                      className={`px-2 py-0.5 text-xs transition-colors ${
                        !typeFilter ? 'text-[#7fd962] bg-[#7fd962]/10' : 'text-[#918175] hover:text-[#fce8c3]'
                      }`}
                    >
                      all
                    </button>
                    <button
                      onClick={() => setTypeFilter('active')}
                      className={`px-2 py-0.5 text-xs transition-colors flex items-center gap-1 ${
                        typeFilter === 'active' ? 'text-[#7fd962] bg-[#7fd962]/10' : 'text-[#918175] hover:text-[#fce8c3]'
                      }`}
                    >
                      <Zap className="w-3 h-3" />active
                    </button>
                    <button
                      onClick={() => setTypeFilter('passive')}
                      className={`px-2 py-0.5 text-xs transition-colors flex items-center gap-1 ${
                        typeFilter === 'passive' ? 'text-[#7fd962] bg-[#7fd962]/10' : 'text-[#918175] hover:text-[#fce8c3]'
                      }`}
                    >
                      <Eye className="w-3 h-3" />passive
                    </button>
                  </div>
                  <span className="text-[#706560]">|</span>
                  <span className="text-[#918175]">{extData?.total ?? 0} extensions</span>
                  <div className="flex items-center border border-[#2e2b26] bg-[#1c1b19] focus-within:border-[#7fd962]/50">
                    <Search className="w-3 h-3 text-[#918175] ml-1.5 shrink-0" />
                    <input
                      type="text"
                      value={searchInput}
                      onChange={(e) => setSearchInput(e.target.value)}
                      placeholder="search..."
                      className="bg-transparent text-[#fce8c3] text-xs px-1.5 py-0.5 w-40 focus:outline-none"
                    />
                  </div>
                </>
              )}
              {tab === 'docs' && (
                <>
                  <span className="text-[#918175]">{docsData?.total ?? 0} functions</span>
                  <div className="flex items-center border border-[#2e2b26] bg-[#1c1b19] focus-within:border-[#7fd962]/50">
                    <Search className="w-3 h-3 text-[#918175] ml-1.5 shrink-0" />
                    <input
                      type="text"
                      value={docsSearch}
                      onChange={(e) => setDocsSearch(e.target.value)}
                      placeholder="search functions..."
                      className="bg-transparent text-[#fce8c3] text-xs px-1.5 py-0.5 w-48 focus:outline-none"
                    />
                  </div>
                </>
              )}
            </div>
          </div>

          <div className={`${AG_GRID_THEME} w-full flex-1`}>
            {tab === 'extensions' && (
              <AgGridReact<Extension>
                rowData={extData?.extensions || []}
                columnDefs={extColumnDefs}
                loading={extLoading}
                suppressCellFocus
                animateRows
                domLayout="normal"
                onRowClicked={onExtRowClicked}
                getRowId={(params) => params.data.file_name}
                overlayNoRowsTemplate='<span style="color:#403d38">no extensions</span>'
              />
            )}
            {tab === 'docs' && (
              <AgGridReact<ExtensionApiFunction>
                rowData={docsData?.functions || []}
                columnDefs={docsColumnDefs}
                loading={docsLoading}
                suppressCellFocus
                animateRows
                domLayout="normal"
                onRowClicked={onDocsRowClicked}
                getRowId={(params) => params.data.full_name}
                overlayNoRowsTemplate='<span style="color:#403d38">no functions</span>'
              />
            )}
          </div>
        </div>

        {/* Detail panel */}
        {selectedFileName !== null && (
          <div className="w-1/2">
            <ExtensionDetailPanel
              fileName={selectedFileName}
              onClose={() => setSelectedFileName(null)}
            />
          </div>
        )}
      </div>
    </PageShell>
  );
}
