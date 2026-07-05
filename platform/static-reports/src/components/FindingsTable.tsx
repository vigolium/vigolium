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
import { Download, Search, ChevronDown, ChevronRight, X, Copy, Check, Terminal, Eye, FileCode, Link } from "lucide-react";
import type { Finding, HttpRecord } from "../types";

marked.setOptions({ breaks: false, gfm: true });
import { useTheme } from "../utils/theme";
import { getSeverityColors, getConfidenceColors, getChartColors } from "../utils/chartTheme";
import { sanitizeHtml, escapeHtml } from "../utils/sanitize";
import { curlNeedsPathAsIs, curlEncodeTarget } from "../utils/curl";
import FilterDropdown from "./FilterDropdown";
import HostSitemap from "./HostSitemap";
import ColumnChooser, { type ColumnOption } from "./ColumnChooser";

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

// Syntax-highlight raw markdown for display. The input is escaped first so an
// attacker-controlled `<script>` or `<img onerror>` in a finding description
// cannot reach the DOM via the regex-based <span> wrappers below.
function highlightMarkdown(md: string): string {
  return escapeHtml(md)
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

// Distinct color per module type so active/passive/whitebox stand out at a glance.
function getModuleTypeColor(type: string, theme: "light" | "dark"): string {
  const dark = theme === "dark";
  switch (type.toLowerCase()) {
    case "active":
      return dark ? "#5aa9e6" : "#1d6fb8"; // blue
    case "passive":
      return dark ? "#3fbf8f" : "#0f8a5f"; // green
    case "whitebox":
      return dark ? "#b98cf0" : "#7c3aed"; // purple
    default:
      return dark ? "#c9a16b" : "#a16207"; // amber fallback
  }
}

const ALL_COLUMN_OPTIONS: ColumnOption[] = [
  { field: "id", label: "#" },
  { field: "severity", label: "Severity" },
  { field: "module", label: "Module" },
  { field: "description", label: "Description" },
  { field: "confidence", label: "Confidence" },
  { field: "finding_source", label: "Source" },
  { field: "module_type", label: "Module Type" },
  { field: "repo_name", label: "Repository" },
  { field: "source_file", label: "Source File" },
  { field: "matched_at", label: "Location" },
  { field: "tags", label: "Tags" },
];

const DEFAULT_COLUMNS = new Set([
  "id", "severity", "module", "description", "confidence",
  "finding_source", "repo_name", "source_file", "matched_at", "tags",
]);

// Stable reference so AG Grid applies it once. resizable/sortable default to true
// in AG Grid v33, but this project never imports the legacy stylesheet and relies on
// the v33 Theming API, so we set them explicitly to guarantee column resizing works.
const DEFAULT_COL_DEF: ColDef<Finding> = {
  resizable: true,
  sortable: true,
  minWidth: 60,
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

  // Build URL — guess scheme from port or default to https. Encode a literal "#"
  // so curl keeps it in the path (else it is dropped as a fragment).
  const scheme = host.endsWith(":80") ? "http" : "https";
  const url = `${scheme}://${host}${curlEncodeTarget(path)}`;

  const parts: string[] = ["curl"];
  // Bypass/fuzz targets (dot-segments or a literal "#") need --path-as-is so curl
  // replays them without collapsing "/../" or "/./".
  if (curlNeedsPathAsIs(path)) {
    parts.push("--path-as-is");
  }
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

// Serialize a finding to a self-contained Markdown document for sharing.
function findingToMarkdown(f: Finding): string {
  const lines: string[] = [];
  const title = f.module_short || f.module_name || f.module_id || "Finding";
  lines.push(`# Finding #${f.id} — ${title}`, "");

  const meta: [string, string | number | null | undefined][] = [
    ["Severity", f.severity],
    ["Confidence", f.confidence],
    ["Status", f.status],
    ["Module", f.module_name ? `${f.module_name}${f.module_id ? ` (\`${f.module_id}\`)` : ""}` : f.module_id],
    ["Module Type", f.module_type],
    ["Source", f.finding_source],
    ["URL", f.url],
    ["CWE", f.cwe_id],
    ["CVSS", f.cvss_score && f.cvss_score > 0 ? f.cvss_score : null],
    ["Repository", f.repo_name],
    ["Source File", f.source_file],
    ["Found At", f.found_at],
    ["Finding Hash", f.finding_hash],
  ];
  for (const [k, v] of meta) {
    if (v !== null && v !== undefined && v !== "") lines.push(`- **${k}:** ${v}`);
  }
  if (f.tags && f.tags.length) lines.push(`- **Tags:** ${f.tags.join(", ")}`);
  if (f.http_record_uuids && f.http_record_uuids.length) lines.push(`- **HTTP Records:** ${f.http_record_uuids.join(", ")}`);

  if (f.description) lines.push("", "## Description", "", f.description.trim());
  if (f.remediation) lines.push("", "## Remediation", "", f.remediation.trim());
  if (f.matched_at && f.matched_at.length) {
    lines.push("", "## Matched At", "", ...f.matched_at.map((m) => `- ${m}`));
  }
  if (f.extracted_results && f.extracted_results.length) {
    lines.push("", "## Extracted Results", "", ...f.extracted_results.map((r) => `- ${r}`));
  }
  if (f.request) lines.push("", "## Request", "", "```http", f.request.trim(), "```");
  if (f.response) lines.push("", "## Response", "", "```http", f.response.trim(), "```");
  if (f.additional_evidence && f.additional_evidence.length) {
    lines.push("", "## Additional Evidence");
    f.additional_evidence.forEach((e, i) => lines.push("", `### Evidence ${i + 1}`, "", "```", String(e).trim(), "```"));
  }
  return lines.join("\n") + "\n";
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

// Toolbar button that copies the unique URLs of the current (filtered) table, one per line.
function CopyUrlsButton({ urls }: { urls: string[] }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(() => {
    if (urls.length === 0) return;
    navigator.clipboard.writeText(urls.join("\n")).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [urls]);

  return (
    <button
      onClick={handleCopy}
      disabled={urls.length === 0}
      className="flex items-center gap-1.5 text-xs font-sans font-semibold text-terracotta hover:text-charcoal transition-colors px-2.5 py-1.5 border border-warm-border rounded-md hover:border-terracotta/30 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:text-terracotta disabled:hover:border-warm-border"
      title="Copy URLs of current table"
    >
      {copied ? <Check size={13} /> : <Link size={13} />}
      {copied ? "Copied" : `Copy URLs (${urls.length})`}
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
  const [descTab, setDescTab] = useState<"rendered" | "raw">("raw");

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
              className="prose-finding"
              dangerouslySetInnerHTML={{ __html: sanitizeHtml(marked.parse(finding.description) as string) }}
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
          <div className="flex gap-2 items-center">
            <DetailLabel>module_type:</DetailLabel>
            {(() => {
              const color = getModuleTypeColor(finding.module_type, theme);
              return (
                <span
                  className="inline-block px-1.5 py-0.5 text-[10px] font-sans font-bold uppercase rounded"
                  style={{ color, backgroundColor: `${color}18` }}
                >
                  {finding.module_type}
                </span>
              );
            })()}
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
  // Memoize the color maps so they keep a stable reference across renders. Some of
  // these helpers (e.g. getConfidenceColors) build a fresh object on every call;
  // without memoization that churns `columnDefs`, which makes ag-grid-react re-apply
  // the column definitions on every render and reset user column-resizes (snap-back).
  const severityColors = useMemo(() => getSeverityColors(theme), [theme]);
  const confidenceColors = useMemo(() => getConfidenceColors(theme), [theme]);

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
  const [moduleTypeFilter, setModuleTypeFilter] = useState<string>("all");
  const [sourceFilter, setSourceFilter] = useState<string>("all");
  const [tagFilter, setTagFilter] = useState<string>("all");
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [selectedHosts, setSelectedHosts] = useState<Set<string>>(new Set());
  // Hide the Repository column entirely when no finding carries a repo name
  // (e.g. pure DAST scans), so the report doesn't show an all-blank column.
  const hasRepoData = useMemo(
    () => data.some((f) => f.repo_name && f.repo_name.trim() !== ""),
    [data]
  );
  const effectiveDefaults = useMemo(() => {
    if (hasRepoData) return DEFAULT_COLUMNS;
    const s = new Set(DEFAULT_COLUMNS);
    s.delete("repo_name");
    return s;
  }, [hasRepoData]);
  const columnOptions = useMemo(
    () => (hasRepoData ? ALL_COLUMN_OPTIONS : ALL_COLUMN_OPTIONS.filter((o) => o.field !== "repo_name")),
    [hasRepoData]
  );

  const [visibleColumns, setVisibleColumns] = useState<Set<string>>(() => {
    const hasRepo = data.some((f) => f.repo_name && f.repo_name.trim() !== "");
    const s = new Set(DEFAULT_COLUMNS);
    if (!hasRepo) s.delete("repo_name");
    return s;
  });
  const [displayedCount, setDisplayedCount] = useState(0);
  const [tableUrls, setTableUrls] = useState<string[]>([]);

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

  const moduleTypes = useMemo(() => {
    const s = new Set(data.map((f) => f.module_type).filter(Boolean) as string[]);
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
    if (moduleTypeFilter !== "all") {
      result = result.filter((f) => f.module_type === moduleTypeFilter);
    }
    if (sourceFilter !== "all") {
      result = result.filter((f) => f.finding_source === sourceFilter);
    }
    if (tagFilter !== "all") {
      result = result.filter((f) => f.tags?.includes(tagFilter));
    }
    return result;
  }, [data, selectedHosts, hostToUuids, severityFilter, confidenceFilter, moduleFilter, moduleTypeFilter, sourceFilter, tagFilter]);

  const allColumnDefs = useMemo<ColDef<Finding>[]>(
    () => [
      { colId: "id", field: "id", headerName: "#", width: 60 },
      {
        colId: "severity",
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
        colId: "module",
        headerName: "Module",
        width: 200,
        valueGetter: ({ data }: { data: Finding | undefined }) =>
          data?.module_short || data?.module_name || "",
        cellClass: "text-xs",
      },
      {
        colId: "description",
        field: "description",
        headerName: "Description",
        flex: 1,
        minWidth: 250,
        cellClass: "text-xs",
        valueFormatter: ({ value }: { value: string | null }) =>
          value ? extractSummary(value) : "",
      },
      {
        colId: "confidence",
        field: "confidence",
        headerName: "Confidence",
        width: 110,
        cellRenderer: ({ value }: { value: string }) => {
          const color = confidenceColors[value] || "#888";
          return <span className="inline-block text-xs font-sans font-semibold capitalize" style={{ color }}>{value}</span>;
        },
      },
      {
        colId: "finding_source",
        field: "finding_source",
        headerName: "Source",
        width: 110,
        cellClass: "text-xs capitalize",
      },
      {
        colId: "module_type",
        field: "module_type",
        headerName: "Module Type",
        width: 120,
        cellClass: "text-xs capitalize",
      },
      {
        colId: "repo_name",
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
        colId: "source_file",
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
        colId: "matched_at",
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
        colId: "tags",
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

  const columnDefs = useMemo<ColDef<Finding>[]>(
    () =>
      allColumnDefs.filter(
        (c) => c.colId && visibleColumns.has(c.colId) && (hasRepoData || c.colId !== "repo_name")
      ),
    [allColumnDefs, visibleColumns, hasRepoData]
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

  // Visible-row count and unique URLs are derived from the grid's post-filter rows so they
  // reflect BOTH the dropdown filters (baked into rowData) AND the search quick-filter.
  const recomputeVisible = useCallback((api: GridApi<Finding>) => {
    const seen = new Set<string>();
    const urls: string[] = [];
    let count = 0;
    api.forEachNodeAfterFilterAndSort((node) => {
      const f = node.data;
      if (!f) return;
      count++;
      for (const u of [f.url, ...(f.matched_at ?? [])]) {
        if (u && !seen.has(u)) {
          seen.add(u);
          urls.push(u);
        }
      }
    });
    setDisplayedCount(count);
    setTableUrls(urls);
  }, []);

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
        {moduleTypes.length > 0 && (
          <FilterDropdown
            value={moduleTypeFilter}
            onChange={setModuleTypeFilter}
            options={[{ value: "all", label: "All Module Types" }, ...moduleTypes.map((t) => ({ value: t, label: t }))]}
            shortLabel="Module Type"
          />
        )}
        <div className="flex-1" />
        <span className="text-xs text-text-muted font-sans">
          {displayedCount} of {data.length} findings
        </span>
        <ColumnChooser
          allColumns={columnOptions}
          visible={visibleColumns}
          onChange={setVisibleColumns}
          defaults={effectiveDefaults}
        />
        <CopyUrlsButton urls={tableUrls} />
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
            defaultColDef={DEFAULT_COL_DEF}
            onGridReady={onGridReady}
            onModelUpdated={(e) => recomputeVisible(e.api)}
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
            <div className="flex items-center justify-between px-4 py-2 sticky top-0 bg-cream-dark/90 backdrop-blur-sm z-10">
              <span className="text-xs text-text-muted font-sans font-semibold uppercase tracking-wider">Finding Detail</span>
              <div className="flex items-center gap-2">
                <CopyButton text={findingToMarkdown(selectedFinding)} label="Copy Markdown" icon={Copy} />
                <button
                  onClick={() => setExpandedId(null)}
                  className="p-1 text-text-muted hover:text-charcoal transition-colors rounded hover:bg-warm-border/30"
                  aria-label="Close detail panel"
                >
                  <X size={14} />
                </button>
              </div>
            </div>
            <FindingDetail finding={selectedFinding} />
          </div>
        )}
      </div>
    </div>
  );
}
