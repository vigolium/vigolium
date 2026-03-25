import { useState, useCallback, useMemo } from "react";
import { AgGridReact } from "ag-grid-react";
import {
  AllCommunityModule,
  ModuleRegistry,
  type ColDef,
  type GridReadyEvent,
  type GridApi,
} from "ag-grid-community";
import { Download, Search, ChevronDown, ChevronRight, X } from "lucide-react";
import type { Finding, HttpRecord } from "../types";
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

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function FindingDetail({ finding }: { finding: Finding }) {
  const [showReq, setShowReq] = useState(true);

  return (
    <div className="p-4 bg-cream-dark/50 border-t border-warm-border space-y-3 text-sm font-sans">
      {finding.description && (
        <p className="text-charcoal-light">{finding.description}</p>
      )}
      {finding.matched_at.length > 0 && (
        <div>
          <span className="text-xs text-text-muted uppercase tracking-wider font-semibold">Matched At</span>
          <div className="mt-1 flex flex-wrap gap-2">
            {finding.matched_at.map((m, i) => (
              <span key={i} className="text-xs px-2 py-1 bg-cream border border-warm-border rounded text-charcoal-light">
                {m}
              </span>
            ))}
          </div>
        </div>
      )}
      {finding.extracted_results.length > 0 && (
        <div>
          <span className="text-xs text-text-muted uppercase tracking-wider font-semibold">Extracted</span>
          <ul className="mt-1 list-disc list-inside text-xs text-charcoal-light">
            {finding.extracted_results.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </div>
      )}
      {(finding.request || finding.response) && (
        <div>
          <button
            onClick={() => setShowReq(!showReq)}
            className="flex items-center gap-1 text-xs text-terracotta font-semibold hover:text-charcoal transition-colors"
          >
            {showReq ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
            Request / Response
          </button>
          {showReq && (
            <div className="mt-2 space-y-3">
              {finding.request && (
                <div className="space-y-1">
                  <span className="text-xs text-text-muted uppercase tracking-wider font-semibold">Request</span>
                  <pre className="text-[11px] bg-cream border border-warm-border rounded p-3 overflow-x-auto whitespace-pre-wrap text-charcoal-light overflow-y-auto">
                    {finding.request}
                  </pre>
                </div>
              )}
              {finding.response && (
                <div className="space-y-1">
                  <span className="text-xs text-text-muted uppercase tracking-wider font-semibold">Response</span>
                  <pre className="text-[11px] bg-cream border border-warm-border rounded p-3 overflow-x-auto whitespace-pre-wrap text-charcoal-light overflow-y-auto">
                    {finding.response}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
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
    const s = new Set(data.map((f) => f.module_name));
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
        f.http_record_uuids.some((uuid) => allowedUuids.has(uuid))
      );
    }
    if (severityFilter !== "all") {
      result = result.filter((f) => f.severity === severityFilter);
    }
    if (confidenceFilter !== "all") {
      result = result.filter((f) => f.confidence === confidenceFilter);
    }
    if (moduleFilter !== "all") {
      result = result.filter((f) => f.module_name === moduleFilter);
    }
    if (tagFilter !== "all") {
      result = result.filter((f) => f.tags?.includes(tagFilter));
    }
    return result;
  }, [data, selectedHosts, hostToUuids, severityFilter, confidenceFilter, moduleFilter, tagFilter]);

  const columnDefs = useMemo<ColDef<Finding>[]>(
    () => [
      { field: "id", headerName: "#", width: 60, sort: "asc" },
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
        comparator: (a: string, b: string) => (SEVERITY_ORDER[a] ?? 99) - (SEVERITY_ORDER[b] ?? 99),
      },
      { field: "module_name", headerName: "Module", width: 200 },
      {
        field: "description",
        headerName: "Description",
        flex: 1,
        minWidth: 250,
        cellClass: "text-xs",
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
      <div className="flex flex-wrap items-center gap-2 mb-4">
        <div className="relative flex-1 min-w-[200px] max-w-[50%]">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            type="text"
            value={searchText}
            onChange={onSearchChange}
            placeholder="Search findings..."
            className="w-full bg-cream border border-warm-border text-charcoal text-xs font-sans pl-9 pr-3 py-1.5 rounded-md focus:outline-none focus:border-terracotta/50 placeholder:text-text-muted"
          />
        </div>
        <FilterDropdown
          value={severityFilter}
          onChange={setSeverityFilter}
          options={[{ value: "all", label: "All Severities" }, ...severities.map((s) => ({ value: s, label: s }))]}
        />
        <FilterDropdown
          value={confidenceFilter}
          onChange={setConfidenceFilter}
          options={[{ value: "all", label: "All Confidence" }, ...confidences.map((c) => ({ value: c, label: c }))]}
        />
        <FilterDropdown
          value={moduleFilter}
          onChange={setModuleFilter}
          options={[{ value: "all", label: "All Modules" }, ...modules.map((m) => ({ value: m, label: m }))]}
        />
        <FilterDropdown
          value={tagFilter}
          onChange={setTagFilter}
          options={[{ value: "all", label: "All Tags" }, ...allTags.map((t) => ({ value: t, label: t }))]}
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
      </div>
      <div className="flex flex-row gap-1" style={{ height: "calc(100vh - 260px)", minHeight: 400 }}>
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
