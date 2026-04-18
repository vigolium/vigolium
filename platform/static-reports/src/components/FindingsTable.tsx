import { useState, useCallback, useMemo, useEffect } from "react";
import { AgGridReact } from "ag-grid-react";
import {
  AllCommunityModule,
  ModuleRegistry,
  type ColDef,
  type GridReadyEvent,
  type GridApi,
} from "ag-grid-community";
import { marked } from "marked";
import { Download, Search, ChevronDown, ChevronRight, X, Copy, Check, Terminal, Eye, FileCode } from "lucide-react";
import type { Finding, HttpRecord } from "../types";

marked.setOptions({ breaks: false, gfm: true });
import { useTheme } from "../utils/theme";
import { getSeverityColors, getConfidenceColors, getChartColors } from "../utils/chartTheme";
import FilterDropdown from "./FilterDropdown";
import HostSitemap from "./HostSitemap";

ModuleRegistry.registerModules([AllCommunityModule]);

interface Props {
  data: Finding[];
  httpRecords: HttpRecord[];
}

// Deterministic hash of a string to pick a color index
function hashStr(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = Math.imul(31, h) + s.charCodeAt(i);
    h |= 0;
  }
  return Math.abs(h);
}

// Strip leading markdown heading markers (e.g. "## Title" → "Title")
function stripMarkdownHeading(s: string): string {
  return s.replace(/^#{1,6}\s*/, "");
}

// Syntax-highlight raw markdown for display
function highlightMarkdown(md: string): string {
  return md
    // code blocks (``` ... ```) — must come before inline rules
    .replace(/(```[\s\S]*?```)/g, '<span class="md-hl-code">$1</span>')
    // headings
    .replace(/^(#{1,6}\s+.*)$/gm, '<span class="md-hl-heading">$1</span>')
    // bold
    .replace(/(\*\*[^*]+\*\*)/g, '<span class="md-hl-bold">$1</span>')
    // inline code
    .replace(/(`[^`\n]+`)/g, '<span class="md-hl-inline-code">$1</span>')
    // list markers
    .replace(/^(\s*[-*]\s)/gm, '<span class="md-hl-list">$1</span>')
    .replace(/^(\s*\d+\.\s)/gm, '<span class="md-hl-list">$1</span>');
}

// Extract a plain-text summary from a markdown description for table display
function extractSummary(s: string): string {
  const stripped = s
    .replace(/^#{1,6}\s+.*\n+/, "") // remove leading heading
    .replace(/```[\s\S]*?```/g, "") // remove code blocks
    .replace(/[*_`~\[\]]/g, "")    // remove inline formatting
    .trim();
  const firstPara = stripped.split(/\n\n/)[0]?.replace(/\n/g, " ").trim() || "";
  return firstPara.length > 150 ? firstPara.slice(0, 150) + "..." : firstPara;
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  "n/a": 5,
};

// Convert a raw HTTP request string to a curl command
function rawRequestToCurl(raw: string): string {
  const lines = raw.split(/\r?\n/);
  if (lines.length === 0) return "";

  // Parse request line: METHOD PATH HTTP/VERSION
  const requestLine = lines[0].trim();
  const [method, path] = requestLine.split(/\s+/);
  if (!method || !path) return "";

  // Parse headers until empty line
  const headers: [string, string][] = [];
  let host = "";
  let i = 1;
  for (; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === "") {
      i++;
      break;
    }
    const colonIdx = line.indexOf(":");
    if (colonIdx > 0) {
      const name = line.slice(0, colonIdx).trim();
      const value = line.slice(colonIdx + 1).trim();
      if (name.toLowerCase() === "host") {
        host = value;
      } else {
        headers.push([name, value]);
      }
    }
  }

  // Remaining lines are the body
  const body = lines.slice(i).join("\n").trim();

  // Build URL — guess scheme from port or default to https
  const scheme = host.endsWith(":80") ? "http" : "https";
  const url = `${scheme}://${host}${path}`;

  const parts: string[] = ["curl"];
  if (method !== "GET") {
    parts.push(`-X '${method}'`);
  }
  parts.push(`'${url}'`);
  for (const [name, value] of headers) {
    parts.push(`-H '${name}: ${value}'`);
  }
  if (body) {
    parts.push(`-d '${body.replace(/'/g, "'\\''")}'`);
  }
  return parts.join(" \\\n  ");
}

function CopyButton({ text, label, icon: Icon }: { text: string; label: string; icon: typeof Copy }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [text]);

  return (
    <button
      onClick={handleCopy}
      className="flex items-center gap-1 text-[10px] font-sans font-semibold text-text-muted hover:text-terracotta transition-colors px-1.5 py-0.5 border border-warm-border rounded hover:border-terracotta/30"
      title={label}
    >
      {copied ? <Check size={10} /> : <Icon size={10} />}
      {copied ? "Copied" : label}
    </button>
  );
}

function DetailLabel({ children }: { children: React.ReactNode }) {
  return <span className="text-xs text-text-muted font-semibold">{children}</span>;
}

function DetailValue({ children, mono }: { children: React.ReactNode; mono?: boolean }) {
  return <span className={`text-xs text-charcoal-light ${mono ? "font-mono" : ""}`}>{children}</span>;
}

function EvidenceTabs({ items }: { items: string[] }) {
  const [active, setActive] = useState(0);

  return (
    <div className="space-y-1">
      <div className="flex items-center gap-1.5 flex-wrap">
        <DetailLabel>additional_evidence:</DetailLabel>
        <span className="text-[10px] text-text-muted">({items.length})</span>
        <div className="flex items-center gap-0.5">
          {items.map((_, i) => (
            <button
              key={i}
              onClick={() => setActive(i)}
              className={`text-[10px] font-mono px-1.5 py-0.5 rounded border transition-colors ${
                active === i
                  ? "border-terracotta text-terracotta bg-terracotta/5"
                  : "border-warm-border text-text-muted hover:border-terracotta/30"
              }`}
            >
              #{i + 1}
            </button>
          ))}
        </div>
        <CopyButton text={items[active]} label="Copy" icon={Copy} />
      </div>
      <pre className="text-[11px] bg-cream border border-warm-border rounded p-3 overflow-x-auto whitespace-pre-wrap text-charcoal-light overflow-y-auto max-h-[300px]">
        {items[active]}
      </pre>
    </div>
  );
}

function FindingDetail({ finding }: { finding: Finding }) {
  const { theme } = useTheme();
  const severityColors = getSeverityColors(theme);
  const confidenceColors = getConfidenceColors(theme);
  const sevColor = severityColors[finding.severity] || "#888";
  const confColor = confidenceColors[finding.confidence] || "#888";
  const [descTab, setDescTab] = useState<"rendered" | "raw">("rendered");

  const foundDate = (() => {
    try {
      return new Date(finding.found_at).toLocaleString();
    } catch {
      return finding.found_at;
    }
  })();

  return (
    <div className="p-4 bg-cream-dark/50 border-t border-warm-border space-y-3 text-sm font-sans">
      {/* Header: Finding #ID */}
      <div className="space-y-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm font-serif font-bold text-charcoal">Finding #{finding.id}</span>
          <span className="inline-block px-2 py-0.5 text-[10px] font-bold uppercase rounded" style={{ color: sevColor, backgroundColor: `${sevColor}18` }}>
            {finding.severity}
          </span>
          <span className="text-[10px] font-semibold capitalize" style={{ color: confColor }}>
            {finding.confidence}
          </span>
          {finding.status && finding.status !== "open" && (
            <span className="text-[10px] px-1.5 py-0.5 rounded border border-warm-border text-text-muted capitalize">{finding.status}</span>
          )}
        </div>
        <p className="text-xs text-charcoal-light font-semibold">{finding.module_short || finding.module_name}</p>
        {finding.module_short && finding.module_short !== finding.module_name && (
          <p className="text-[11px] text-text-muted line-clamp-2">{finding.module_name}</p>
        )}
      </div>

      {/* Description with Rendered / Raw tabs */}
      {finding.description && (
        <div>
          <div className="flex items-center gap-1 mb-1.5">
            <button
              onClick={() => setDescTab("rendered")}
              className={`flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded border transition-colors ${
                descTab === "rendered"
                  ? "border-terracotta text-terracotta bg-terracotta/5"
                  : "border-warm-border text-text-muted hover:border-terracotta/30"
              }`}
            >
              <Eye size={10} />
              Rendered
            </button>
            <button
              onClick={() => setDescTab("raw")}
              className={`flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded border transition-colors ${
                descTab === "raw"
                  ? "border-terracotta text-terracotta bg-terracotta/5"
                  : "border-warm-border text-text-muted hover:border-terracotta/30"
              }`}
            >
              <FileCode size={10} />
              Raw
            </button>
            <CopyButton text={finding.description} label="Copy" icon={Copy} />
          </div>
          {descTab === "rendered" ? (
            <div
              className="prose-finding text-xs text-charcoal-light"
              dangerouslySetInnerHTML={{ __html: marked.parse(finding.description) as string }}
            />
          ) : (
            <pre
              className="text-[11px] bg-cream border border-warm-border rounded p-3 overflow-x-auto whitespace-pre-wrap text-charcoal-light overflow-y-auto max-h-[500px]"
              dangerouslySetInnerHTML={{ __html: highlightMarkdown(finding.description) }}
            />
          )}
        </div>
      )}

      {/* Metadata rows */}
      <div className="space-y-1">
        {finding.module_id && (
          <div className="flex gap-2">
            <DetailLabel>module_id:</DetailLabel>
            <DetailValue mono>{finding.module_id}</DetailValue>
          </div>
        )}
        {finding.module_type && (
          <div className="flex gap-2">
            <DetailLabel>module_type:</DetailLabel>
            <DetailValue>{finding.module_type}</DetailValue>
          </div>
        )}
        {finding.finding_source && (
          <div className="flex gap-2">
            <DetailLabel>source:</DetailLabel>
            <DetailValue>{finding.finding_source}</DetailValue>
          </div>
        )}
        <div className="flex gap-2">
          <DetailLabel>finding_hash:</DetailLabel>
          <DetailValue mono>{finding.finding_hash}</DetailValue>
        </div>
        <div className="flex gap-2">
          <DetailLabel>found_at:</DetailLabel>
          <DetailValue>{foundDate}</DetailValue>
        </div>
        {finding.url && (
          <div className="flex gap-2">
            <DetailLabel>url:</DetailLabel>
            <DetailValue mono>{finding.url}</DetailValue>
          </div>
        )}
        {finding.cwe_id && (
          <div className="flex gap-2">
            <DetailLabel>cwe:</DetailLabel>
            <DetailValue>{finding.cwe_id}</DetailValue>
          </div>
        )}
        {finding.cvss_score !== undefined && finding.cvss_score > 0 && (
          <div className="flex gap-2">
            <DetailLabel>cvss:</DetailLabel>
            <DetailValue>{finding.cvss_score}</DetailValue>
          </div>
        )}
        {finding.repo_name && (
          <div className="flex gap-2">
            <DetailLabel>repo_name:</DetailLabel>
            <DetailValue mono>{finding.repo_name}</DetailValue>
          </div>
        )}
        {finding.source_file && (
          <div className="flex gap-2">
            <DetailLabel>source_file:</DetailLabel>
            <DetailValue mono>{finding.source_file}</DetailValue>
          </div>
        )}
        {finding.http_record_uuids && finding.http_record_uuids.length > 0 && (
          <div className="flex gap-2 flex-wrap">
            <DetailLabel>http_records:</DetailLabel>
            <div className="flex flex-wrap gap-1">
              {finding.http_record_uuids.map((uuid, i) => (
                <span key={i} className="text-[10px] font-mono text-terracotta">{uuid}</span>
              ))}
            </div>
          </div>
        )}
        {finding.tags && finding.tags.length > 0 && (
          <div className="flex gap-2 flex-wrap items-center">
            <DetailLabel>tags:</DetailLabel>
            <div className="flex flex-wrap gap-1">
              {finding.tags.map((t) => (
                <span key={t} className="text-[10px] px-1.5 py-0.5 rounded border border-warm-border text-charcoal-light">{t}</span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Matched At */}
      {finding.matched_at && finding.matched_at.length > 0 && (
        <div className="space-y-1">
          <DetailLabel>matched_at:</DetailLabel>
          <div className="flex flex-wrap gap-1.5 mt-0.5">
            {finding.matched_at.map((m, i) => (
              <span key={i} className="text-[11px] font-mono px-2 py-0.5 bg-cream border border-warm-border rounded text-charcoal-light break-all">
                {m}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Extracted Results */}
      {finding.extracted_results && finding.extracted_results.length > 0 && (
        <div className="space-y-1">
          <DetailLabel>extracted_results:</DetailLabel>
          <ul className="list-disc list-inside text-[11px] text-charcoal-light mt-0.5">
            {finding.extracted_results.map((r, i) => (
              <li key={i} className="break-all">{r}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Remediation */}
      {finding.remediation && (
        <div className="space-y-1">
          <DetailLabel>remediation:</DetailLabel>
          <p className="text-[11px] text-charcoal-light mt-0.5">{finding.remediation}</p>
        </div>
      )}

      {/* Request */}
      {finding.request && (
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <DetailLabel>request:</DetailLabel>
            <CopyButton text={finding.request} label="Copy" icon={Copy} />
            <CopyButton text={rawRequestToCurl(finding.request)} label="cURL" icon={Terminal} />
          </div>
          <pre className="text-[11px] bg-cream border border-warm-border rounded p-3 overflow-x-auto whitespace-pre-wrap text-charcoal-light overflow-y-auto max-h-[300px]">
            {finding.request}
          </pre>
        </div>
      )}

      {/* Response */}
      {finding.response && (
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <DetailLabel>response:</DetailLabel>
            <CopyButton text={finding.response} label="Copy" icon={Copy} />
          </div>
          <pre className="text-[11px] bg-cream border border-warm-border rounded p-3 overflow-x-auto whitespace-pre-wrap text-charcoal-light overflow-y-auto max-h-[300px]">
            {finding.response}
          </pre>
        </div>
      )}

      {/* Additional Evidence */}
      {finding.additional_evidence && finding.additional_evidence.length > 0 && (
        <EvidenceTabs items={finding.additional_evidence} />
      )}
    </div>
  );
}

export default function FindingsTable({ data, httpRecords }: Props) {
  const { theme } = useTheme();
  const severityColors = getSeverityColors(theme);
  const confidenceColors = getConfidenceColors(theme);

  // Extended color palette for tags: chart colors + cyan/purple from Brogrammer palette
  const tagPalette = useMemo(() => {
    const base = getChartColors(theme);
    return [...base, theme === "dark" ? "#2dc7c4" : "#0891b2", theme === "dark" ? "#e02c6d" : "#9333ea"];
  }, [theme]);

  const [gridApi, setGridApi] = useState<GridApi | null>(null);
  const [searchText, setSearchText] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [confidenceFilter, setConfidenceFilter] = useState<string>("all");
  const [moduleFilter, setModuleFilter] = useState<string>("all");
  const [sourceFilter, setSourceFilter] = useState<string>("all");
  const [tagFilter, setTagFilter] = useState<string>("all");
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [selectedHosts, setSelectedHosts] = useState<Set<string>>(new Set());

  const onGridReady = useCallback((params: GridReadyEvent) => {
    setGridApi(params.api);
  }, []);

  const hostCounts = useMemo(() => {
    const map = new Map<string, number>();
    for (const r of httpRecords) {
      map.set(r.hostname, (map.get(r.hostname) || 0) + 1);
    }
    return Array.from(map.entries())
      .sort((a, b) => b[1] - a[1])
      .map(([host, count]) => ({ host, count }));
  }, [httpRecords]);

  // Map hostname → set of http_record UUIDs for filtering findings by host
  const hostToUuids = useMemo(() => {
    const map = new Map<string, Set<string>>();
    for (const r of httpRecords) {
      let s = map.get(r.hostname);
      if (!s) {
        s = new Set();
        map.set(r.hostname, s);
      }
      s.add(r.uuid);
    }
    return map;
  }, [httpRecords]);

  const modules = useMemo(() => {
    const s = new Set(data.map((f) => f.module_short || f.module_name));
    return Array.from(s).sort();
  }, [data]);

  const sources = useMemo(() => {
    const s = new Set(data.map((f) => f.finding_source).filter(Boolean) as string[]);
    return Array.from(s).sort();
  }, [data]);

  const severities = useMemo(() => {
    const s = new Set(data.map((f) => f.severity));
    return Array.from(s).sort((a, b) => (SEVERITY_ORDER[a] ?? 99) - (SEVERITY_ORDER[b] ?? 99));
  }, [data]);

  const confidences = useMemo(() => {
    const s = new Set(data.map((f) => f.confidence));
    return Array.from(s).sort();
  }, [data]);

  const allTags = useMemo(() => {
    const s = new Set(data.flatMap((f) => f.tags ?? []));
    return Array.from(s).sort();
  }, [data]);

  const filteredData = useMemo(() => {
    let result = data;
    if (selectedHosts.size > 0) {
      const allowedUuids = new Set<string>();
      for (const host of selectedHosts) {
        const uuids = hostToUuids.get(host);
        if (uuids) {
          for (const u of uuids) allowedUuids.add(u);
        }
      }
      result = result.filter((f) =>
        f.http_record_uuids?.some((uuid) => allowedUuids.has(uuid))
      );
    }
    if (severityFilter !== "all") {
      result = result.filter((f) => f.severity === severityFilter);
    }
    if (confidenceFilter !== "all") {
      result = result.filter((f) => f.confidence === confidenceFilter);
    }
    if (moduleFilter !== "all") {
      result = result.filter((f) => (f.module_short || f.module_name) === moduleFilter);
    }
    if (sourceFilter !== "all") {
      result = result.filter((f) => f.finding_source === sourceFilter);
    }
    if (tagFilter !== "all") {
      result = result.filter((f) => f.tags?.includes(tagFilter));
    }
    return result;
  }, [data, selectedHosts, hostToUuids, severityFilter, confidenceFilter, moduleFilter, sourceFilter, tagFilter]);

  const columnDefs = useMemo<ColDef<Finding>[]>(
    () => [
      { field: "id", headerName: "#", width: 60 },
      {
        field: "severity",
        headerName: "Severity",
        width: 110,
        cellRenderer: ({ value }: { value: string }) => {
          const color = severityColors[value] || "#888";
          return (
            <span className="inline-block px-2 py-0.5 text-xs font-sans font-bold uppercase rounded" style={{ color, backgroundColor: `${color}18` }}>
              {value}
            </span>
          );
        },
        sort: "asc",
        comparator: (a: string, b: string) => (SEVERITY_ORDER[a] ?? 99) - (SEVERITY_ORDER[b] ?? 99),
      },
      {
        headerName: "Module",
        width: 200,
        valueGetter: ({ data }: { data: Finding | undefined }) =>
          data?.module_short || data?.module_name || "",
        cellClass: "text-xs",
      },
      {
        field: "description",
        headerName: "Description",
        flex: 1,
        minWidth: 250,
        cellClass: "text-xs",
        valueFormatter: ({ value }: { value: string | null }) =>
          value ? extractSummary(value) : "",
      },
      {
        field: "confidence",
        headerName: "Confidence",
        width: 110,
        cellRenderer: ({ value }: { value: string }) => {
          const color = confidenceColors[value] || "#888";
          return <span className="inline-block text-xs font-sans font-semibold capitalize" style={{ color }}>{value}</span>;
        },
      },
      {
        field: "finding_source",
        headerName: "Source",
        width: 110,
        cellClass: "text-xs capitalize",
      },
      {
        field: "repo_name",
        headerName: "Repository",
        width: 160,
        cellClass: "text-xs",
        cellRenderer: ({ value }: { value: string | null }) => {
          if (!value) return null;
          return <span className="text-xs font-mono text-charcoal-light truncate block" title={value}>{value}</span>;
        },
      },
      {
        field: "source_file",
        headerName: "Source File",
        width: 180,
        cellClass: "text-xs",
        cellRenderer: ({ value }: { value: string | null }) => {
          if (!value) return null;
          return <span className="text-xs font-mono text-charcoal-light truncate block" title={value}>{value}</span>;
        },
      },
      {
        field: "matched_at",
        headerName: "Location",
        width: 200,
        cellRenderer: ({ value }: { value: string[] }) => {
          if (!value || value.length === 0) return null;
          return (
            <span className="text-xs text-charcoal-light font-sans truncate block" title={value.join(", ")}>
              {value[0]}
              {value.length > 1 && <span className="text-text-muted"> +{value.length - 1}</span>}
            </span>
          );
        },
      },
      {
        field: "tags",
        headerName: "Tags",
        width: 180,
        cellRenderer: ({ value }: { value: string[] }) => {
          if (!value || value.length === 0) return null;
          return (
            <div className="flex flex-wrap gap-0.5">
              {value.slice(0, 4).map((t) => {
                const color = tagPalette[hashStr(t) % tagPalette.length];
                return (
                  <span key={t} className="inline-block px-1 py-px text-[9px] font-sans font-semibold rounded leading-tight" style={{ color, backgroundColor: `${color}15` }}>{t}</span>
                );
              })}
              {value.length > 4 && <span className="inline-block text-[9px] text-text-muted leading-tight">+{value.length - 4}</span>}
            </div>
          );
        },
      },
    ],
    [severityColors, confidenceColors, tagPalette]
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
    gridApi?.exportDataAsCsv({ fileName: "vigolium-findings.csv" });
  }, [gridApi]);

  const onExportJsonl = useCallback(() => {
    const jsonl = filteredData.map((f) => JSON.stringify(f)).join("\n");
    const blob = new Blob([jsonl], { type: "application/x-ndjson" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "vigolium-findings.jsonl";
    a.click();
    URL.revokeObjectURL(url);
  }, [filteredData]);

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

  useEffect(() => {
    if (expandedId === null) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") setExpandedId(null);
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [expandedId]);

  const selectedFinding = expandedId !== null ? data.find((f) => f.id === expandedId) : null;

  return (
    <div>
      {httpRecords.length > 0 && (
        <HostSitemap
          hosts={hostCounts}
          selectedHosts={selectedHosts}
          onToggleHost={onToggleHost}
          onClear={onClearHosts}
        />
      )}
      <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 mb-4">
        <div className="relative flex-1 min-w-[140px] sm:min-w-[200px] max-w-[50%]">
          <Search size={13} className="absolute left-2.5 sm:left-3 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            type="text"
            value={searchText}
            onChange={onSearchChange}
            placeholder="Search..."
            className="w-full bg-cream border border-warm-border text-charcoal text-[11px] sm:text-xs font-sans pl-8 sm:pl-9 pr-2 sm:pr-3 py-1 sm:py-1.5 rounded-md focus:outline-none focus:border-terracotta/50 placeholder:text-text-muted"
          />
        </div>
        <FilterDropdown
          value={severityFilter}
          onChange={setSeverityFilter}
          options={[{ value: "all", label: "All Severities" }, ...severities.map((s) => ({ value: s, label: s }))]}
          shortLabel="Severity"
        />
        <FilterDropdown
          value={confidenceFilter}
          onChange={setConfidenceFilter}
          options={[{ value: "all", label: "All Confidence" }, ...confidences.map((c) => ({ value: c, label: c }))]}
          shortLabel="Confidence"
        />
        <FilterDropdown
          value={moduleFilter}
          onChange={setModuleFilter}
          options={[{ value: "all", label: "All Modules" }, ...modules.map((m) => ({ value: m, label: m }))]}
          shortLabel="Modules"
        />
        <FilterDropdown
          value={sourceFilter}
          onChange={setSourceFilter}
          options={[{ value: "all", label: "All Sources" }, ...sources.map((s) => ({ value: s, label: s }))]}
          shortLabel="Sources"
        />
        <FilterDropdown
          value={tagFilter}
          onChange={setTagFilter}
          options={[{ value: "all", label: "All Tags" }, ...allTags.map((t) => ({ value: t, label: t }))]}
          shortLabel="Tags"
        />
        <div className="flex-1" />
        <span className="text-xs text-text-muted font-sans">
          {filteredData.length} of {data.length} findings
        </span>
        <button
          onClick={onExport}
          className="flex items-center gap-1.5 text-xs font-sans font-semibold text-terracotta hover:text-charcoal transition-colors px-2.5 py-1.5 border border-warm-border rounded-md hover:border-terracotta/30"
        >
          <Download size={13} />
          CSV
        </button>
        <button
          onClick={onExportJsonl}
          className="flex items-center gap-1.5 text-xs font-sans font-semibold text-terracotta hover:text-charcoal transition-colors px-2.5 py-1.5 border border-warm-border rounded-md hover:border-terracotta/30"
        >
          <Download size={13} />
          JSONL
        </button>
      </div>
      <div className="flex flex-row gap-1" style={{ height: "calc(100vh - 180px)", minHeight: 400 }}>
        <div className="ag-theme-quartz border border-warm-border rounded-md overflow-hidden" style={{ width: selectedFinding ? "50%" : "100%", height: "100%" }}>
          <AgGridReact<Finding>
            rowData={filteredData}
            columnDefs={columnDefs}
            onGridReady={onGridReady}
            pagination={true}
            paginationPageSize={50}
            paginationPageSizeSelector={[25, 50, 100]}
            animateRows={true}
            domLayout="normal"
            suppressCellFocus={true}
            onRowClicked={(e) => {
              const id = e.data?.id;
              if (id !== undefined) setExpandedId(expandedId === id ? null : id);
            }}
            rowClass="cursor-pointer"
          />
        </div>
        {selectedFinding && (
          <div className="w-1/2 overflow-y-auto border border-warm-border rounded-md">
            <div className="flex items-center justify-between px-4 pt-3 pb-1 sticky top-0 bg-cream-dark/90 backdrop-blur-sm z-10">
              <span className="text-xs text-text-muted font-sans font-semibold uppercase tracking-wider">Finding Detail</span>
              <button
                onClick={() => setExpandedId(null)}
                className="p-1 text-text-muted hover:text-charcoal transition-colors rounded hover:bg-warm-border/30"
                aria-label="Close detail panel"
              >
                <X size={14} />
              </button>
            </div>
            <FindingDetail finding={selectedFinding} />
          </div>
        )}
      </div>
    </div>
  );
}
