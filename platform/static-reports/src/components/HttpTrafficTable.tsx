import { useState, useCallback, useMemo, useEffect } from "react";
import { AgGridReact } from "ag-grid-react";
import {
  AllCommunityModule,
  ModuleRegistry,
  type ColDef,
  type GridReadyEvent,
  type GridApi,
} from "ag-grid-community";
import { Download, Search, X, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, Copy, Check, Terminal, type LucideIcon } from "lucide-react";
import type { HttpRecord } from "../types";
import { useTheme } from "../utils/theme";
import { getMethodColors, getStatusColors, getSourceColor } from "../utils/chartTheme";
import { curlNeedsPathAsIs, curlEncodeTarget } from "../utils/curl";
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

function TrimNote({ note }: { note?: string | null }) {
  if (!note) return null;
  return (
    <div className="text-[11px] text-terracotta bg-terracotta/10 border border-terracotta/30 rounded px-2 py-1 whitespace-pre-wrap">
      ⚠ {note}
    </div>
  );
}

// The origin-form request target for the request line, Burp-style. record.path
// is the verbatim on-the-wire target (escaped path + query) parsed straight from
// the request line, so it preserves fuzz/bypass encodings — a crafted
// "/#/../demo.log" or "/%23/../x" stays intact. Parsing record.url with URL()
// silently drops the fragment (collapsing "/#/../demo.log" down to "/"), so only
// fall back to it when path is absent.
function requestTarget(record: HttpRecord): string {
  if (record.path) return record.path;
  try {
    const u = new URL(record.url);
    return (u.pathname || "/") + u.search;
  } catch {
    return "/";
  }
}

function flattenHeaders(headers: Record<string, string | string[]> | null | undefined): string[] {
  if (!headers) return [];
  const lines: string[] = [];
  for (const [k, v] of Object.entries(headers)) {
    const vals = Array.isArray(v) ? v : [v];
    for (const val of vals) lines.push(`${k}: ${val}`);
  }
  return lines;
}

// Build the raw HTTP request in Burp wire format. A full JSONL export carries
// raw_request verbatim; generated reports drop it, so reconstruct the message
// from the request line + headers + (trimmed) body.
function buildRawRequest(record: HttpRecord): string {
  const raw = decodeBase64(record.raw_request);
  if (raw) return raw;
  const version = record.http_version || "HTTP/1.1";
  const lines = [`${record.method} ${requestTarget(record)} ${version}`];
  const headerLines = flattenHeaders(record.request_headers);
  const hasHost = headerLines.some((l) => l.toLowerCase().startsWith("host:"));
  if (!hasHost && record.hostname) {
    const isDefaultPort = (record.scheme === "https" && record.port === 443) || (record.scheme === "http" && record.port === 80);
    lines.push(`Host: ${record.hostname}${record.port && !isDefaultPort ? `:${record.port}` : ""}`);
  }
  lines.push(...headerLines);
  let out = lines.join("\n");
  const body = decodeBase64(record.request_body);
  if (body) out += `\n\n${body}`;
  return out;
}

function buildRawResponse(record: HttpRecord): string {
  const raw = decodeBase64(record.raw_response);
  if (raw) return raw;
  const version = record.response_http_version || record.http_version || "HTTP/1.1";
  const lines = [`${version} ${record.status_code}${record.status_phrase ? ` ${record.status_phrase}` : ""}`];
  lines.push(...flattenHeaders(record.response_headers));
  let out = lines.join("\n");
  const body = decodeBase64(record.response_body);
  if (body) out += `\n\n${body}`;
  return out;
}

// Decode the request body, preferring the explicit request_body field and
// falling back to the body portion of a full raw_request when present.
function requestBodyText(record: HttpRecord): string {
  const direct = decodeBase64(record.request_body);
  if (direct) return direct;
  const raw = decodeBase64(record.raw_request);
  if (!raw) return "";
  const norm = raw.replace(/\r\n/g, "\n");
  const idx = norm.indexOf("\n\n");
  return idx >= 0 ? norm.slice(idx + 2) : "";
}

// POSIX single-quote: wrap in '...' and escape embedded single quotes.
function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

// Rebuild the request URL from scheme + authority + the verbatim wire target so
// bypass paths survive; used only when --path-as-is is in play, since record.url
// has already lost the fragment for those. Absolute-form targets pass through.
function curlTargetUrl(record: HttpRecord, target: string): string {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(target)) return curlEncodeTarget(target);
  const scheme = record.scheme || "https";
  const isDefaultPort = (scheme === "https" && record.port === 443) || (scheme === "http" && record.port === 80);
  const authority = `${record.hostname}${record.port && !isDefaultPort ? `:${record.port}` : ""}`;
  return `${scheme}://${authority}${curlEncodeTarget(target)}`;
}

// Build a copy-paste curl command for the request. Host/Content-Length are
// dropped since curl derives them; the method is only emitted when not GET.
// Bypass/fuzz targets (dot-segments or a literal "#") get --path-as-is and a
// URL rebuilt from the wire target so curl replays them without normalizing.
function toCurl(record: HttpRecord): string {
  const parts = ["curl"];
  const target = requestTarget(record);
  const pathAsIs = curlNeedsPathAsIs(target);
  if (pathAsIs) parts.push("--path-as-is");
  if (record.method && record.method.toUpperCase() !== "GET") {
    parts.push(`-X ${record.method.toUpperCase()}`);
  }
  parts.push(shellQuote(pathAsIs ? curlTargetUrl(record, target) : record.url));
  const headers = record.request_headers || {};
  for (const [k, v] of Object.entries(headers)) {
    const kl = k.toLowerCase();
    if (kl === "host" || kl === "content-length") continue;
    const vals = Array.isArray(v) ? v : [v];
    for (const val of vals) parts.push(`-H ${shellQuote(`${k}: ${val}`)}`);
  }
  const body = requestBodyText(record);
  if (body) parts.push(`--data-raw ${shellQuote(body)}`);
  return parts.join(" \\\n  ");
}

function CopyButton({ text, label = "Copy", icon: Icon = Copy }: { text: string; label?: string; icon?: LucideIcon }) {
  const [copied, setCopied] = useState(false);
  const onCopy = useCallback(() => {
    navigator.clipboard?.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    }).catch(() => {});
  }, [text]);
  return (
    <button
      onClick={onCopy}
      className="flex items-center gap-1 text-[10px] font-sans font-semibold text-text-muted hover:text-terracotta transition-colors px-1.5 py-0.5 border border-warm-border rounded hover:border-terracotta/30"
      aria-label={`Copy ${label === "Copy" ? "raw message" : label}`}
    >
      {copied ? <Check size={11} /> : <Icon size={11} />}
      {copied ? "Copied" : label}
    </button>
  );
}

// Render a raw HTTP message Burp-style: monospace, with the start line and
// header names emphasized and the body separated after the blank line. When
// `grow` is set the message fills the remaining height of a flex column
// instead of being capped, so the response can use the full panel.
function BurpMessage({ raw, grow }: { raw: string; grow?: boolean }) {
  const text = raw.replace(/\r\n/g, "\n");
  const sepIdx = text.indexOf("\n\n");
  const headerPart = sepIdx >= 0 ? text.slice(0, sepIdx) : text;
  const bodyPart = sepIdx >= 0 ? text.slice(sepIdx + 2) : "";
  const headerLines = headerPart.split("\n");
  return (
    <pre className={`text-[11px] leading-relaxed bg-cream border border-warm-border rounded p-3 overflow-x-auto whitespace-pre-wrap break-all text-charcoal-light overflow-y-auto font-mono ${grow ? "flex-1 min-h-0" : "max-h-[40vh]"}`}>
      {headerLines.map((line, i) => {
        if (i === 0) {
          return <div key={i} className="text-terracotta font-semibold">{line}</div>;
        }
        const ci = line.indexOf(":");
        if (ci > 0) {
          return (
            <div key={i}>
              <span className="text-charcoal font-semibold">{line.slice(0, ci)}</span>
              <span>{line.slice(ci)}</span>
            </div>
          );
        }
        return <div key={i}>{line}</div>;
      })}
      {bodyPart && <div className="mt-2 text-charcoal-light/90 border-t border-warm-border/60 pt-2">{bodyPart}</div>}
    </pre>
  );
}

function RecordDetail({ record }: { record: HttpRecord }) {
  const rawRequest = buildRawRequest(record);
  const rawResponse = buildRawResponse(record);
  const reqTrim = record.request_body_trimmed ? record.request_body_note : null;
  const respTrim = record.response_body_trimmed ? record.response_body_note : null;

  return (
    <div className="flex flex-col min-h-0 flex-1 p-4 gap-3 bg-cream-dark/50 border-t border-warm-border text-sm font-sans">
      <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-text-muted shrink-0">
        <span><strong className="text-charcoal">Status:</strong> {record.status_code}{record.status_phrase ? ` ${record.status_phrase}` : ""}</span>
        <span><strong className="text-charcoal">IP:</strong> {record.ip || "N/A"}</span>
        <span><strong className="text-charcoal">Scheme:</strong> {record.scheme}</span>
        <span><strong className="text-charcoal">Port:</strong> {record.port}</span>
        <span><strong className="text-charcoal">HTTP:</strong> {record.http_version}</span>
        <span><strong className="text-charcoal">Response Time:</strong> {record.response_time_ms}ms</span>
        <span><strong className="text-charcoal">Source:</strong> {record.source || "N/A"}</span>
        {record.response_title && <span><strong className="text-charcoal">Title:</strong> {record.response_title}</span>}
      </div>

      {/* Request — natural height, capped */}
      <div className="space-y-2 shrink-0">
        <div className="flex items-center justify-between">
          <span className="text-xs text-text-muted uppercase tracking-wider font-semibold">Request</span>
          <div className="flex items-center gap-3">
            <CopyButton text={rawRequest} />
            <CopyButton text={toCurl(record)} label="cURL" icon={Terminal} />
          </div>
        </div>
        <TrimNote note={reqTrim} />
        <BurpMessage raw={rawRequest} />
      </div>

      {/* Response — fills the remaining panel height */}
      <div className="flex flex-col min-h-0 flex-1 space-y-2">
        <div className="flex items-center justify-between shrink-0">
          <span className="text-xs text-text-muted uppercase tracking-wider font-semibold">Response</span>
          <CopyButton text={rawResponse} />
        </div>
        <TrimNote note={respTrim} />
        <BurpMessage raw={rawResponse} grow />
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

// Stable reference so AG Grid applies it once — makes column resizing explicit
// rather than relying on AG Grid v33's implicit defaults under the Theming API.
const DEFAULT_COL_DEF: ColDef<HttpRecord> = {
  resizable: true,
  sortable: true,
  minWidth: 60,
};

export default function HttpTrafficTable({ data }: Props) {
  const { theme } = useTheme();
  // Memoize so these color maps keep a stable reference across renders — otherwise
  // they churn `columnDefs`, making ag-grid-react re-apply column definitions every
  // render and reset user column-resizes (snap-back to the declared width).
  const methodColors = useMemo(() => getMethodColors(theme), [theme]);
  const statusColors = useMemo(() => getStatusColors(theme), [theme]);

  const [gridApi, setGridApi] = useState<GridApi | null>(null);
  const [searchText, setSearchText] = useState("");
  const [methodFilter, setMethodFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [contentTypeFilter, setContentTypeFilter] = useState<string>("all");
  const [sourceFilter, setSourceFilter] = useState<string>("all");
  const [expandedUuid, setExpandedUuid] = useState<string | null>(null);
  const [selectedHosts, setSelectedHosts] = useState<Set<string>>(new Set());
  const [visibleColumns, setVisibleColumns] = useState<Set<string>>(new Set(DEFAULT_COLUMNS));
  const [pageSize, setPageSize] = useState(100);
  const [currentPage, setCurrentPage] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [copiedCount, setCopiedCount] = useState<number | null>(null);
  const [displayedCount, setDisplayedCount] = useState(0);

  const syncPagination = useCallback((api: GridApi) => {
    setCurrentPage(api.paginationGetCurrentPage());
    setTotalPages(api.paginationGetTotalPages());
  }, []);

  // Rows currently shown after column filters + the search box quick filter
  // (across all pages) — drives the Copy URLs button's count.
  const onModelUpdated = useCallback((api: GridApi) => {
    setDisplayedCount(api.getDisplayedRowCount());
  }, []);

  const onGridReady = useCallback((params: GridReadyEvent) => {
    setGridApi(params.api);
    syncPagination(params.api);
    onModelUpdated(params.api);
  }, [syncPagination, onModelUpdated]);

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

  const sources = useMemo(() => {
    const s = new Set(data.map((r) => (r.source || "").trim()).filter(Boolean));
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
    if (sourceFilter !== "all") {
      result = result.filter((r) => (r.source || "").trim() === sourceFilter);
    }
    return result;
  }, [data, selectedHosts, methodFilter, statusFilter, contentTypeFilter, sourceFilter]);

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
      {
        field: "source",
        headerName: "Source",
        width: 110,
        cellRenderer: ({ value }: { value: string | null }) => {
          if (!value) return <span className="text-text-muted text-xs">—</span>;
          const color = getSourceColor(value, theme);
          return (
            <span className="inline-block px-2 py-0.5 text-xs font-sans font-semibold rounded" style={{ color, backgroundColor: `${color}1f` }}>
              {value}
            </span>
          );
        },
      },
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
    [methodColors, statusColors, theme]
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

  // Copy the URLs of every row in the current view (after search + filters +
  // sort, across all pages) to the clipboard, one per line.
  const onCopyUrls = useCallback(() => {
    if (!gridApi) return;
    const urls: string[] = [];
    gridApi.forEachNodeAfterFilterAndSort((node) => {
      const u = node.data?.url;
      if (u) urls.push(u);
    });
    navigator.clipboard?.writeText(urls.join("\n")).then(() => {
      setCopiedCount(urls.length);
      setTimeout(() => setCopiedCount(null), 1400);
    }).catch(() => {});
  }, [gridApi]);

  // Download the current view (search + filters + sort) as canonical vigolium
  // JSONL — one {"type":"http_record","data":...} envelope per line, so the
  // file re-loads into the report and re-ingests into vigolium.
  const onExportJsonl = useCallback(() => {
    if (!gridApi) return;
    const lines: string[] = [];
    gridApi.forEachNodeAfterFilterAndSort((node) => {
      if (node.data) lines.push(JSON.stringify({ type: "http_record", data: node.data }));
    });
    const blob = new Blob([lines.length ? `${lines.join("\n")}\n` : ""], { type: "application/x-ndjson" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "vigolium-http-traffic.jsonl";
    a.click();
    URL.revokeObjectURL(url);
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

  // Close the Record Detail panel on Escape.
  useEffect(() => {
    if (expandedUuid === null) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setExpandedUuid(null);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [expandedUuid]);

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
        <FilterDropdown
          value={sourceFilter}
          onChange={setSourceFilter}
          options={[{ value: "all", label: "All Sources" }, ...sources.map((s) => ({ value: s, label: s }))]}
        />
        <div className="flex-1" />
        <span className="text-xs text-text-muted font-sans">
          {filteredData.length} of {data.length} records
        </span>
        {/* Pagination controls */}
        <div className="flex items-center gap-1.5">
          <FilterDropdown
            value={String(pageSize)}
            onChange={(v) => onPageSizeChange(Number(v))}
            options={pageSizeOptions.map((s) => ({ value: String(s), label: `${s} / page` }))}
          />
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
          onClick={onCopyUrls}
          title="Copy the URLs of every row in the current table view (search + filters), one per line"
          className="flex items-center gap-1.5 text-xs font-sans font-semibold text-terracotta hover:text-charcoal transition-colors px-2.5 py-1.5 border border-warm-border rounded-md hover:border-terracotta/30"
        >
          {copiedCount !== null ? <Check size={13} /> : <Copy size={13} />}
          {copiedCount !== null ? `Copied ${copiedCount}` : `Copy URLs of current table (${displayedCount})`}
        </button>
        <button
          onClick={onExport}
          className="flex items-center gap-1.5 text-xs font-sans font-semibold text-terracotta hover:text-charcoal transition-colors px-2.5 py-1.5 border border-warm-border rounded-md hover:border-terracotta/30"
        >
          <Download size={13} />
          CSV
        </button>
        <button
          onClick={onExportJsonl}
          title="Download every row in the current table view (search + filters) as vigolium JSONL"
          className="flex items-center gap-1.5 text-xs font-sans font-semibold text-terracotta hover:text-charcoal transition-colors px-2.5 py-1.5 border border-warm-border rounded-md hover:border-terracotta/30"
        >
          <Download size={13} />
          JSONL
        </button>
      </div>
      <div className="flex flex-row gap-1 flex-1 min-h-0">
        <div className="ag-theme-quartz border border-warm-border rounded-md overflow-hidden" style={{ width: selectedRecord ? "50%" : "100%", height: "100%" }}>
          <AgGridReact<HttpRecord>
            rowData={filteredData}
            columnDefs={columnDefs}
            defaultColDef={DEFAULT_COL_DEF}
            onGridReady={onGridReady}
            pagination={true}
            paginationPageSize={pageSize}
            suppressPaginationPanel={true}
            onPaginationChanged={() => { if (gridApi) syncPagination(gridApi); }}
            onModelUpdated={(e) => onModelUpdated(e.api)}
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
          <div className="w-1/2 flex flex-col min-h-0 border border-warm-border rounded-md">
            <div className="flex items-center justify-between px-4 py-2 shrink-0 bg-cream-dark/90 backdrop-blur-sm">
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
