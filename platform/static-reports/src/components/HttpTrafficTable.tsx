import { useState, useCallback, useMemo } from "react";
import { AgGridReact } from "ag-grid-react";
import {
  AllCommunityModule,
  ModuleRegistry,
  type ColDef,
  type GridReadyEvent,
  type GridApi,
} from "ag-grid-community";
import { Download, Search, X, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from "lucide-react";
import type { HttpRecord } from "../types";
import { useTheme } from "../utils/theme";
import { getMethodColors, getStatusColors } from "../utils/chartTheme";
import FilterDropdown from "./FilterDropdown";
import HostSitemap from "./HostSitemap";
import ColumnChooser, { type ColumnOption } from "./ColumnChooser";

ModuleRegistry.registerModules([AllCommunityModule]);

interface Props {
  data: HttpRecord[];
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function decodeBase64(b64: string | null): string {
  if (!b64) return "";
  try {
    return atob(b64);
  } catch {
    return b64;
  }
}

function HeaderChips({ headers }: { headers: Record<string, string | string[]> }) {
  const entries = Object.entries(headers);
  if (entries.length === 0) return null;
  return (
    <div className="overflow-x-auto max-h-24 overflow-y-auto">
      <div className="flex flex-wrap gap-1">
        {entries.map(([k, v]) => (
          <span key={k} className="inline-flex whitespace-nowrap text-[10px] px-1.5 py-0.5 bg-cream border border-warm-border rounded">
            <span className="text-terracotta font-semibold">{k}:</span>
            <span className="text-charcoal-light ml-1">{Array.isArray(v) ? v.join(", ") : v}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

function TrimNote({ note }: { note?: string | null }) {
  if (!note) return null;
  return (
    <div className="text-[11px] text-terracotta bg-terracotta/10 border border-terracotta/30 rounded px-2 py-1 whitespace-pre-wrap">
      ⚠ {note}
    </div>
  );
}

function RecordDetail({ record }: { record: HttpRecord }) {
  // Generated reports drop the redundant raw_request/raw_response and carry the
  // (trimmed) body in request_body/response_body. A manually-dropped full JSONL
  // export still has the raw fields, so prefer those when present.
  const reqBody = decodeBase64(record.raw_request) || decodeBase64(record.request_body);
  const respBody = decodeBase64(record.raw_response) || decodeBase64(record.response_body);
  const reqTrim = record.request_body_trimmed ? record.request_body_note : null;
  const respTrim = record.response_body_trimmed ? record.response_body_note : null;

  return (
    <div className="p-4 bg-cream-dark/50 border-t border-warm-border space-y-3 text-sm font-sans">
      <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-text-muted">
        <span><strong className="text-charcoal">Status:</strong> {record.status_code}{record.status_phrase ? ` ${record.status_phrase}` : ""}</span>
        <span><strong className="text-charcoal">IP:</strong> {record.ip || "N/A"}</span>
        <span><strong className="text-charcoal">Scheme:</strong> {record.scheme}</span>
        <span><strong className="text-charcoal">Port:</strong> {record.port}</span>
        <span><strong className="text-charcoal">HTTP:</strong> {record.http_version}</span>
        <span><strong className="text-charcoal">Response Time:</strong> {record.response_time_ms}ms</span>
        <span><strong className="text-charcoal">Source:</strong> {record.source || "N/A"}</span>
        {record.response_title && <span><strong className="text-charcoal">Title:</strong> {record.response_title}</span>}
      </div>

      <div className="space-y-3">
        {/* Request */}
        <div className="space-y-2">
          <span className="text-xs text-text-muted uppercase tracking-wider font-semibold">Request</span>
          {record.request_headers && Object.keys(record.request_headers).length > 0 && (
            <HeaderChips headers={record.request_headers} />
          )}
          <TrimNote note={reqTrim} />
          {reqBody && (
            <pre className="text-[11px] bg-cream border border-warm-border rounded p-3 overflow-x-auto whitespace-pre-wrap text-charcoal-light overflow-y-auto">
              {reqBody}
            </pre>
          )}
        </div>

        {/* Response */}
        <div className="space-y-2">
          <span className="text-xs text-text-muted uppercase tracking-wider font-semibold">Response</span>
          {record.response_headers && Object.keys(record.response_headers).length > 0 && (
            <HeaderChips headers={record.response_headers} />
          )}
          <TrimNote note={respTrim} />
          {respBody && (
            <pre className="text-[11px] bg-cream border border-warm-border rounded p-3 overflow-x-auto whitespace-pre-wrap text-charcoal-light overflow-y-auto">
              {respBody}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}

const ALL_COLUMN_OPTIONS: ColumnOption[] = [
  { field: "method", label: "Method" },
  { field: "url", label: "URL" },
  { field: "status_code", label: "Status Code" },
  { field: "response_content_length", label: "Response Size" },
  { field: "response_time_ms", label: "Response Time" },
  { field: "response_content_type", label: "Content-Type" },
  { field: "hostname", label: "Hostname" },
  { field: "response_title", label: "Title" },
  { field: "source", label: "Source" },
  { field: "uuid", label: "UUID" },
  { field: "scheme", label: "Scheme" },
  { field: "port", label: "Port" },
  { field: "ip", label: "IP" },
  { field: "path", label: "Path" },
  { field: "http_version", label: "HTTP Version" },
  { field: "request_content_length", label: "Request Size" },
  { field: "request_hash", label: "Request Hash" },
  { field: "raw_request", label: "Raw Request" },
  { field: "status_phrase", label: "Status Phrase" },
  { field: "response_http_version", label: "Response HTTP Version" },
  { field: "response_body", label: "Response Body" },
  { field: "response_hash", label: "Response Hash" },
  { field: "raw_response", label: "Raw Response" },
  { field: "response_words", label: "Response Words" },
  { field: "has_response", label: "Has Response" },
  { field: "sent_at", label: "Sent At" },
  { field: "received_at", label: "Received At" },
  { field: "created_at", label: "Created At" },
  { field: "remarks", label: "Remarks" },
  { field: "risk_score", label: "Risk Score" },
];

const DEFAULT_COLUMNS = new Set([
  "method", "url", "status_code", "response_content_length",
  "response_time_ms", "response_content_type", "ip",
  "response_title", "source", "remarks",
]);

export default function HttpTrafficTable({ data }: Props) {
  const { theme } = useTheme();
  const methodColors = getMethodColors(theme);
  const statusColors = getStatusColors(theme);

  const [gridApi, setGridApi] = useState<GridApi | null>(null);
  const [searchText, setSearchText] = useState("");
  const [methodFilter, setMethodFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [contentTypeFilter, setContentTypeFilter] = useState<string>("all");
  const [expandedUuid, setExpandedUuid] = useState<string | null>(null);
  const [selectedHosts, setSelectedHosts] = useState<Set<string>>(new Set());
  const [visibleColumns, setVisibleColumns] = useState<Set<string>>(new Set(DEFAULT_COLUMNS));
  const [pageSize, setPageSize] = useState(100);
  const [currentPage, setCurrentPage] = useState(0);
  const [totalPages, setTotalPages] = useState(0);

  const syncPagination = useCallback((api: GridApi) => {
    setCurrentPage(api.paginationGetCurrentPage());
    setTotalPages(api.paginationGetTotalPages());
  }, []);

  const onGridReady = useCallback((params: GridReadyEvent) => {
    setGridApi(params.api);
    syncPagination(params.api);
  }, [syncPagination]);

  const hostCounts = useMemo(() => {
    const map = new Map<string, number>();
    for (const r of data) {
      map.set(r.hostname, (map.get(r.hostname) || 0) + 1);
    }
    return Array.from(map.entries())
      .sort((a, b) => b[1] - a[1])
      .map(([host, count]) => ({ host, count }));
  }, [data]);

  const methods = useMemo(() => {
    const s = new Set(data.map((r) => r.method));
    return Array.from(s).sort();
  }, [data]);

  const statusGroups = useMemo(() => {
    const s = new Set(data.map((r) => `${Math.floor(r.status_code / 100)}xx`));
    return Array.from(s).sort();
  }, [data]);

  const contentTypes = useMemo(() => {
    const s = new Set(data.map((r) => r.response_content_type ? r.response_content_type.split(";")[0].trim() : "").filter(Boolean));
    return Array.from(s).sort();
  }, [data]);

  const filteredData = useMemo(() => {
    let result = data;
    if (selectedHosts.size > 0) {
      result = result.filter((r) => selectedHosts.has(r.hostname));
    }
    if (methodFilter !== "all") {
      result = result.filter((r) => r.method === methodFilter);
    }
    if (statusFilter !== "all") {
      result = result.filter((r) => `${Math.floor(r.status_code / 100)}xx` === statusFilter);
    }
    if (contentTypeFilter !== "all") {
      result = result.filter((r) => {
        const ct = r.response_content_type ? r.response_content_type.split(";")[0].trim() : "";
        return ct === contentTypeFilter;
      });
    }
    return result;
  }, [data, selectedHosts, methodFilter, statusFilter, contentTypeFilter]);

  const allColumnDefs = useMemo<ColDef<HttpRecord>[]>(
    () => [
      {
        field: "method",
        headerName: "Method",
        width: 90,
        cellRenderer: ({ value }: { value: string }) => {
          const color = methodColors[value] || "#888";
          return <span className="inline-block text-xs font-sans font-bold" style={{ color }}>{value}</span>;
        },
      },
      {
        field: "url",
        headerName: "URL",
        flex: 1,
        minWidth: 300,
        cellClass: "text-xs",
      },
      {
        field: "status_code",
        headerName: "Status",
        width: 90,
        cellRenderer: ({ value }: { value: number }) => {
          const cat = `${Math.floor(value / 100)}xx`;
          const color = statusColors[cat] || "#888";
          return (
            <span className="inline-block px-2 py-0.5 text-xs font-sans font-semibold rounded" style={{ color, backgroundColor: `${color}15` }}>
              {value}
            </span>
          );
        },
      },
      {
        field: "response_content_length",
        headerName: "Size",
        width: 100,
        valueFormatter: (p) => formatBytes(p.value ?? 0),
      },
      {
        field: "response_time_ms",
        headerName: "Time",
        width: 80,
        valueFormatter: (p) => p.value != null ? `${p.value}ms` : "",
      },
      {
        field: "response_content_type",
        headerName: "Content-Type",
        width: 170,
        valueFormatter: (p) => p.value ? p.value.split(";")[0] : "",
      },
      { field: "hostname", headerName: "Host", width: 150 },
      { field: "response_title", headerName: "Title", width: 160 },
      { field: "source", headerName: "Source", width: 90 },
      { field: "uuid", headerName: "UUID", width: 280, cellClass: "text-xs" },
      { field: "scheme", headerName: "Scheme", width: 80 },
      { field: "port", headerName: "Port", width: 70 },
      { field: "ip", headerName: "IP", width: 130 },
      { field: "path", headerName: "Path", width: 200, cellClass: "text-xs" },
      { field: "http_version", headerName: "HTTP Version", width: 100 },
      { field: "request_content_length", headerName: "Req Size", width: 100, valueFormatter: (p) => formatBytes(p.value ?? 0) },
      { field: "request_hash", headerName: "Req Hash", width: 180, cellClass: "text-xs" },
      { field: "raw_request", headerName: "Raw Request", width: 200, cellClass: "text-xs" },
      { field: "status_phrase", headerName: "Status Phrase", width: 120 },
      { field: "response_http_version", headerName: "Resp HTTP Version", width: 120 },
      { field: "response_body", headerName: "Response Body", width: 200, cellClass: "text-xs" },
      { field: "response_hash", headerName: "Resp Hash", width: 180, cellClass: "text-xs" },
      { field: "raw_response", headerName: "Raw Response", width: 200, cellClass: "text-xs" },
      { field: "response_words", headerName: "Words", width: 80 },
      { field: "has_response", headerName: "Has Response", width: 110 },
      { field: "sent_at", headerName: "Sent At", width: 170 },
      { field: "received_at", headerName: "Received At", width: 170 },
      { field: "created_at", headerName: "Created At", width: 170 },
      { field: "remarks", headerName: "Remarks", width: 180, valueFormatter: (p) => Array.isArray(p.value) ? p.value.join(", ") : "" },
      { field: "risk_score", headerName: "Risk Score", width: 90 },
    ],
    [methodColors, statusColors]
  );

  const columnDefs = useMemo<ColDef<HttpRecord>[]>(
    () => allColumnDefs.filter((c) => c.field && visibleColumns.has(c.field)),
    [allColumnDefs, visibleColumns]
  );

  const onSearchChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const val = e.target.value;
      setSearchText(val);
      gridApi?.setGridOption("quickFilterText", val);
    },
    [gridApi]
  );

  const onExport = useCallback(() => {
    gridApi?.exportDataAsCsv({ fileName: "vigolium-http-traffic.csv" });
  }, [gridApi]);

  const onToggleHost = useCallback((host: string) => {
    setSelectedHosts((prev) => {
      const next = new Set(prev);
      if (next.has(host)) next.delete(host);
      else next.add(host);
      return next;
    });
  }, []);

  const onClearHosts = useCallback(() => {
    setSelectedHosts(new Set());
  }, []);

  const selectedRecord = expandedUuid !== null ? data.find((r) => r.uuid === expandedUuid) : null;

  const pageSizeOptions = [50, 100, 200, 500];

  const onPageSizeChange = useCallback((size: number) => {
    setPageSize(size);
    if (gridApi) {
      gridApi.setGridOption("paginationPageSize", size);
      syncPagination(gridApi);
    }
  }, [gridApi, syncPagination]);

  return (
    <div className="flex flex-col" style={{ height: "calc(100vh - 150px)", minHeight: 400 }}>
      <HostSitemap
        hosts={hostCounts}
        selectedHosts={selectedHosts}
        onToggleHost={onToggleHost}
        onClear={onClearHosts}
      />
      <div className="flex flex-wrap items-center gap-2 mb-2">
        <div className="relative flex-1 min-w-[200px] max-w-[50%]">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            type="text"
            value={searchText}
            onChange={onSearchChange}
            placeholder="Search URL, host..."
            className="w-full bg-cream border border-warm-border text-charcoal text-xs font-sans pl-9 pr-3 py-1.5 rounded-md focus:outline-none focus:border-terracotta/50 placeholder:text-text-muted"
          />
        </div>
        <FilterDropdown
          value={methodFilter}
          onChange={setMethodFilter}
          options={[{ value: "all", label: "All Methods" }, ...methods.map((m) => ({ value: m, label: m }))]}
        />
        <FilterDropdown
          value={statusFilter}
          onChange={setStatusFilter}
          options={[{ value: "all", label: "All Status" }, ...statusGroups.map((s) => ({ value: s, label: s }))]}
        />
        <FilterDropdown
          value={contentTypeFilter}
          onChange={setContentTypeFilter}
          options={[{ value: "all", label: "All Content-Types" }, ...contentTypes.map((ct) => ({ value: ct, label: ct }))]}
        />
        <div className="flex-1" />
        <span className="text-xs text-text-muted font-sans">
          {filteredData.length} of {data.length} records
        </span>
        {/* Pagination controls */}
        <div className="flex items-center gap-1.5">
          <select
            value={pageSize}
            onChange={(e) => onPageSizeChange(Number(e.target.value))}
            className="bg-cream border border-warm-border text-charcoal text-xs font-sans px-2 py-1.5 rounded-md focus:outline-none focus:border-terracotta/50"
          >
            {pageSizeOptions.map((s) => (
              <option key={s} value={s}>{s} / page</option>
            ))}
          </select>
          <button onClick={() => { gridApi?.paginationGoToFirstPage(); if (gridApi) syncPagination(gridApi); }} disabled={currentPage === 0} className="p-1.5 text-text-muted hover:text-charcoal disabled:opacity-30 disabled:cursor-not-allowed transition-colors rounded hover:bg-warm-border/30">
            <ChevronsLeft size={14} />
          </button>
          <button onClick={() => { gridApi?.paginationGoToPreviousPage(); if (gridApi) syncPagination(gridApi); }} disabled={currentPage === 0} className="p-1.5 text-text-muted hover:text-charcoal disabled:opacity-30 disabled:cursor-not-allowed transition-colors rounded hover:bg-warm-border/30">
            <ChevronLeft size={14} />
          </button>
          <span className="text-xs text-charcoal font-sans font-semibold px-1.5 tabular-nums">
            {totalPages > 0 ? currentPage + 1 : 0} / {totalPages}
          </span>
          <button onClick={() => { gridApi?.paginationGoToNextPage(); if (gridApi) syncPagination(gridApi); }} disabled={currentPage >= totalPages - 1} className="p-1.5 text-text-muted hover:text-charcoal disabled:opacity-30 disabled:cursor-not-allowed transition-colors rounded hover:bg-warm-border/30">
            <ChevronRight size={14} />
          </button>
          <button onClick={() => { gridApi?.paginationGoToLastPage(); if (gridApi) syncPagination(gridApi); }} disabled={currentPage >= totalPages - 1} className="p-1.5 text-text-muted hover:text-charcoal disabled:opacity-30 disabled:cursor-not-allowed transition-colors rounded hover:bg-warm-border/30">
            <ChevronsRight size={14} />
          </button>
        </div>
        <ColumnChooser
          allColumns={ALL_COLUMN_OPTIONS}
          visible={visibleColumns}
          onChange={setVisibleColumns}
          defaults={DEFAULT_COLUMNS}
        />
        <button
          onClick={onExport}
          className="flex items-center gap-1.5 text-xs font-sans font-semibold text-terracotta hover:text-charcoal transition-colors px-2.5 py-1.5 border border-warm-border rounded-md hover:border-terracotta/30"
        >
          <Download size={13} />
          CSV
        </button>
      </div>
      <div className="flex flex-row gap-1 flex-1 min-h-0">
        <div className="ag-theme-quartz border border-warm-border rounded-md overflow-hidden" style={{ width: selectedRecord ? "50%" : "100%", height: "100%" }}>
          <AgGridReact<HttpRecord>
            rowData={filteredData}
            columnDefs={columnDefs}
            onGridReady={onGridReady}
            pagination={true}
            paginationPageSize={pageSize}
            suppressPaginationPanel={true}
            onPaginationChanged={() => { if (gridApi) syncPagination(gridApi); }}
            animateRows={true}
            domLayout="normal"
            suppressCellFocus={true}
            onRowClicked={(e) => {
              const uuid = e.data?.uuid;
              if (uuid) setExpandedUuid(expandedUuid === uuid ? null : uuid);
            }}
            rowClass="cursor-pointer"
          />
        </div>
        {selectedRecord && (
          <div className="w-1/2 overflow-y-auto border border-warm-border rounded-md">
            <div className="flex items-center justify-between px-4 pt-3 pb-1 sticky top-0 bg-cream-dark/90 backdrop-blur-sm z-10">
              <span className="text-xs text-text-muted font-sans font-semibold uppercase tracking-wider">Record Detail</span>
              <button
                onClick={() => setExpandedUuid(null)}
                className="p-1 text-text-muted hover:text-charcoal transition-colors rounded hover:bg-warm-border/30"
                aria-label="Close detail panel"
              >
                <X size={14} />
              </button>
            </div>
            <RecordDetail record={selectedRecord} />
          </div>
        )}
      </div>
    </div>
  );
}
