import { useMemo, useState, useEffect } from "react";
import { marked } from "marked";
import { Printer, ArrowUp } from "lucide-react";
import type { ExportData, Finding, ModuleRecord } from "../types";
import { computeSummary } from "../utils/parse";

marked.setOptions({ breaks: false, gfm: true });

interface Props {
  data: ExportData;
  scanDuration?: string;
  generatedAt?: string;
  vigoliumVersion?: string;
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

type SeverityKey = (typeof SEVERITY_ORDER)[number];

const SEVERITY_LABELS: Record<SeverityKey, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Informational",
};

const REPORT_SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#9ca3af",
};

function groupBySeverity(findings: Finding[]): Record<SeverityKey, Finding[]> {
  const groups: Record<SeverityKey, Finding[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
    info: [],
  };
  for (const f of findings) {
    const sev = f.severity.toLowerCase() as SeverityKey;
    if (groups[sev]) {
      groups[sev].push(f);
    } else {
      groups.info.push(f);
    }
  }
  return groups;
}

function FindingTitle(f: Finding): string {
  const name = f.module_short || f.module_name;
  if (f.url) {
    const truncated = f.url.length > 80 ? f.url.slice(0, 80) + "..." : f.url;
    return `${name} — ${truncated}`;
  }
  return name;
}

function scrollToId(id: string) {
  return (e: React.MouseEvent) => {
    e.preventDefault();
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
  };
}

function FindingBlock({ finding }: { finding: Finding }) {
  const sevColor = REPORT_SEVERITY_COLORS[finding.severity] || "#888";

  const descHtml = useMemo(() => {
    if (!finding.description) return "";
    return marked.parse(finding.description) as string;
  }, [finding.description]);

  return (
    <div
      id={`finding-${finding.id}`}
      className="bg-cream-dark border border-warm-border rounded mb-4 p-4 print:break-inside-avoid"
    >
      {/* Header */}
      <div className="flex items-baseline gap-2 flex-wrap mb-2">
        <span className="text-[13px] font-bold text-charcoal font-serif">#{finding.id}</span>
        <span
          className="inline-block px-2 py-0.5 text-[11px] font-bold uppercase rounded"
          style={{ color: sevColor, backgroundColor: `${sevColor}18` }}
        >
          {finding.severity}
        </span>
        <span className="text-xs text-text-muted">{finding.module_short || finding.module_name}</span>
      </div>

      {finding.url && (
        <div className="text-xs font-mono text-charcoal-light break-all mb-2">{finding.url}</div>
      )}

      {/* Description */}
      {descHtml && (
        <div
          className="prose-finding text-[13px] text-charcoal-light mb-3"
          dangerouslySetInnerHTML={{ __html: descHtml }}
        />
      )}

      {/* Metadata */}
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs mb-3">
        <dt className="font-semibold text-text-muted">Module</dt>
        <dd className="font-mono text-[11px] text-charcoal-light">{finding.module_id}</dd>
        {finding.confidence && (
          <>
            <dt className="font-semibold text-text-muted">Confidence</dt>
            <dd className="text-charcoal-light">{finding.confidence}</dd>
          </>
        )}
        {finding.cwe_id && (
          <>
            <dt className="font-semibold text-text-muted">CWE</dt>
            <dd className="text-charcoal-light">{finding.cwe_id}</dd>
          </>
        )}
        {finding.cvss_score !== undefined && finding.cvss_score > 0 && (
          <>
            <dt className="font-semibold text-text-muted">CVSS</dt>
            <dd className="text-charcoal-light">{finding.cvss_score.toFixed(1)}</dd>
          </>
        )}
        {finding.finding_hash && (
          <>
            <dt className="font-semibold text-text-muted">Hash</dt>
            <dd className="font-mono text-[11px] text-charcoal-light">{finding.finding_hash}</dd>
          </>
        )}
        {finding.found_at && (
          <>
            <dt className="font-semibold text-text-muted">Found</dt>
            <dd className="text-charcoal-light">{finding.found_at}</dd>
          </>
        )}
        {finding.source_file && (
          <>
            <dt className="font-semibold text-text-muted">Source File</dt>
            <dd className="font-mono text-[11px] text-charcoal-light">{finding.source_file}</dd>
          </>
        )}
        {finding.repo_name && (
          <>
            <dt className="font-semibold text-text-muted">Repository</dt>
            <dd className="font-mono text-[11px] text-charcoal-light">{finding.repo_name}</dd>
          </>
        )}
      </dl>

      {/* Tags */}
      {finding.tags && finding.tags.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-2">
          {finding.tags.map((t) => (
            <span key={t} className="text-[10px] font-semibold px-2 py-0.5 border border-warm-border rounded text-charcoal-light">
              {t}
            </span>
          ))}
        </div>
      )}

      {/* Matched At */}
      {finding.matched_at && finding.matched_at.length > 0 && (
        <div className="mb-2">
          <div className="text-[11px] font-bold uppercase tracking-wide text-text-muted mb-1">Matched At</div>
          {finding.matched_at.map((m, i) => (
            <code key={i} className="block text-xs break-all my-0.5">{m}</code>
          ))}
        </div>
      )}

      {/* Extracted Results */}
      {finding.extracted_results && finding.extracted_results.length > 0 && (
        <div className="mb-2">
          <div className="text-[11px] font-bold uppercase tracking-wide text-text-muted mb-1">Extracted Results</div>
          <ul className="list-disc list-inside text-xs text-charcoal-light">
            {finding.extracted_results.map((r, i) => (
              <li key={i} className="break-all">{r}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Remediation */}
      {finding.remediation && (
        <div className="bg-cream border border-warm-border rounded p-3 mt-3">
          <div className="text-[11px] font-bold uppercase text-terracotta mb-1">Remediation</div>
          <p className="text-xs text-charcoal-light">{finding.remediation}</p>
        </div>
      )}

      {/* Request */}
      {finding.request && (
        <div className="mt-3">
          <div className="text-[11px] font-bold uppercase tracking-wide text-text-muted mb-1">Request</div>
          <pre className="text-[11px] bg-cream border border-warm-border rounded p-3 whitespace-pre-wrap break-all overflow-x-auto max-h-[400px] overflow-y-auto text-charcoal-light print:max-h-none print:overflow-visible">
            {finding.request}
          </pre>
        </div>
      )}

      {/* Response */}
      {finding.response && (
        <div className="mt-3">
          <div className="text-[11px] font-bold uppercase tracking-wide text-text-muted mb-1">Response</div>
          <pre className="text-[11px] bg-cream border border-warm-border rounded p-3 whitespace-pre-wrap break-all overflow-x-auto max-h-[400px] overflow-y-auto text-charcoal-light print:max-h-none print:overflow-visible">
            {finding.response}
          </pre>
        </div>
      )}

      {/* Additional Evidence */}
      {finding.additional_evidence && finding.additional_evidence.length > 0 && (
        <div className="mt-3">
          {finding.additional_evidence.map((e, i) => (
            <div key={i}>
              <div className="text-[11px] font-bold uppercase tracking-wide text-text-muted mb-1 mt-2">
                Additional Evidence #{i + 1}
              </div>
              <pre className="text-[11px] bg-cream border border-warm-border rounded p-3 whitespace-pre-wrap break-all overflow-x-auto max-h-[400px] overflow-y-auto text-charcoal-light print:max-h-none print:overflow-visible">
                {e}
              </pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function SeveritySection({
  severity,
  findings,
}: {
  severity: SeverityKey;
  findings: Finding[];
}) {
  const sevColor = REPORT_SEVERITY_COLORS[severity] || "#888";

  if (findings.length === 0) return null;

  return (
    <div id={`severity-${severity}`} className="mb-8">
      <h2 className="text-xl font-bold text-charcoal border-b border-warm-border pb-2 mb-3 font-serif">
        <span
          className="inline-block px-2.5 py-0.5 text-[11px] font-bold uppercase rounded mr-2"
          style={{ color: sevColor, backgroundColor: `${sevColor}18` }}
        >
          {severity}
        </span>
        Findings ({findings.length})
      </h2>
      {findings.map((f) => (
        <FindingBlock key={f.id} finding={f} />
      ))}
    </div>
  );
}

function ModuleTable({ modules }: { modules: ModuleRecord[] }) {
  if (modules.length === 0) return null;

  return (
    <div>
      <h3 className="text-sm font-semibold text-charcoal mb-2 font-serif">Scanner Modules</h3>
      <table className="w-full text-xs border-collapse">
        <thead>
          <tr className="border-b border-warm-border">
            <th className="text-left py-1.5 px-2 font-semibold text-[11px] uppercase tracking-wide text-text-muted">ID</th>
            <th className="text-left py-1.5 px-2 font-semibold text-[11px] uppercase tracking-wide text-text-muted">Name</th>
            <th className="text-left py-1.5 px-2 font-semibold text-[11px] uppercase tracking-wide text-text-muted">Type</th>
            <th className="text-left py-1.5 px-2 font-semibold text-[11px] uppercase tracking-wide text-text-muted">Severity</th>
          </tr>
        </thead>
        <tbody>
          {modules.filter((m) => m.enabled).map((m) => (
            <tr key={m.id} className="border-b border-cream-dark even:bg-cream-dark/50">
              <td className="py-1 px-2 font-mono text-[11px]">{m.id}</td>
              <td className="py-1 px-2">{m.name}</td>
              <td className="py-1 px-2">{m.type}</td>
              <td className="py-1 px-2">{m.severity}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function ReportView({ data, scanDuration, generatedAt, vigoliumVersion }: Props) {

  const summary = useMemo(() => computeSummary(data), [data]);
  const groups = useMemo(() => groupBySeverity(data.findings), [data.findings]);

  const [showBackToTop, setShowBackToTop] = useState(false);

  useEffect(() => {
    const onScroll = () => setShowBackToTop(window.scrollY > 400);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const date = generatedAt || new Date().toLocaleDateString("en-US", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  let tocIndex = 0;

  return (
    <div className="py-8 px-4 report-view" id="report-top">
      {/* Header */}
      <div className="border-b-2 border-charcoal pb-4 mb-8">
        <div className="flex items-start justify-between gap-4">
          <h1 className="text-2xl font-bold text-charcoal font-serif">Vigolium Scan Report</h1>
          <button
            onClick={() => window.print()}
            className="no-print flex items-center gap-1.5 text-xs font-semibold text-terracotta hover:text-charcoal transition-colors px-3 py-1.5 border border-warm-border rounded-md hover:border-terracotta/30 shrink-0"
          >
            <Printer size={13} />
            Print / Export PDF
          </button>
        </div>
        <div className="flex flex-wrap gap-4 text-xs text-text-muted mt-1">
          <span>Generated: {date}</span>
          {summary.target !== "Unknown" && <span>Target: {summary.target}</span>}
          {scanDuration && <span>Duration: {scanDuration}</span>}
          {vigoliumVersion && <span>Vigolium {vigoliumVersion}</span>}
        </div>
      </div>

      {/* Executive Summary */}
      <div id="executive-summary" className="mb-8">
        <h2 className="text-xl font-bold text-charcoal border-b border-warm-border pb-2 mb-5 font-serif">Executive Summary</h2>

        <div className="grid grid-cols-3 sm:grid-cols-6 gap-3 mb-4">
          <div className="bg-cream-dark border border-warm-border rounded-md p-3 text-center">
            <div className="text-2xl font-bold text-charcoal">{summary.totalFindings}</div>
            <div className="text-[11px] font-semibold uppercase tracking-wide text-text-muted">Total</div>
          </div>
          {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
            <div key={sev} className="bg-cream-dark border border-warm-border rounded-md p-3 text-center">
              <div className="text-2xl font-bold" style={{ color: REPORT_SEVERITY_COLORS[sev] }}>
                {summary[`${sev}Count` as keyof typeof summary] as number}
              </div>
              <div className="text-[11px] font-semibold uppercase tracking-wide text-text-muted">{sev}</div>
            </div>
          ))}
        </div>

        {/* Severity bar */}
        {summary.totalFindings > 0 && (
          <div className="flex h-2 rounded overflow-hidden mb-4">
            {SEVERITY_ORDER.map((sev) => {
              const count = summary[`${sev}Count` as keyof typeof summary] as number;
              if (count === 0) return null;
              return (
                <span
                  key={sev}
                  style={{ flex: count, backgroundColor: REPORT_SEVERITY_COLORS[sev], minWidth: 2 }}
                />
              );
            })}
          </div>
        )}

        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-[13px]">
          {summary.target !== "Unknown" && (
            <>
              <dt className="font-semibold text-charcoal">Target</dt>
              <dd className="text-charcoal-light">{summary.target}</dd>
            </>
          )}
          <dt className="font-semibold text-charcoal">Generated</dt>
          <dd className="text-charcoal-light">{date}</dd>
          {scanDuration && (
            <>
              <dt className="font-semibold text-charcoal">Duration</dt>
              <dd className="text-charcoal-light">{scanDuration}</dd>
            </>
          )}
          <dt className="font-semibold text-charcoal">Total Requests</dt>
          <dd className="text-charcoal-light">{summary.totalRequests}</dd>
          <dt className="font-semibold text-charcoal">Active Modules</dt>
          <dd className="text-charcoal-light">{summary.activeModules}</dd>
          <dt className="font-semibold text-charcoal">Passive Modules</dt>
          <dd className="text-charcoal-light">{summary.passiveModules}</dd>
        </dl>
      </div>

      {/* Table of Contents */}
      <div className="bg-cream-dark border border-warm-border rounded-md p-5 mb-8">
        <h2 className="text-sm font-bold uppercase tracking-wide text-charcoal mb-3 font-serif">Table of Contents</h2>
        <ol className="space-y-2">
          <li>
            <a href="#executive-summary" onClick={scrollToId("executive-summary")} className="text-[13px] font-semibold text-charcoal hover:text-terracotta no-underline cursor-pointer">
              {++tocIndex}. Executive Summary
            </a>
          </li>
          {SEVERITY_ORDER.map((sev) => {
            const count = groups[sev].length;
            const color = REPORT_SEVERITY_COLORS[sev] || "#888";
            if (count === 0) return null;
            return (
              <li key={sev} className="rounded-md p-2" style={{ backgroundColor: `${color}06` }}>
                <a
                  href={`#severity-${sev}`}
                  onClick={scrollToId(`severity-${sev}`)}
                  className="text-[13px] font-semibold text-charcoal hover:text-terracotta no-underline cursor-pointer flex items-center gap-1.5"
                >
                  <span
                    className="inline-block px-1.5 py-px text-[10px] font-bold uppercase rounded"
                    style={{ color, backgroundColor: `${color}18` }}
                  >
                    {sev}
                  </span>
                  {++tocIndex}. {SEVERITY_LABELS[sev]} Findings
                  <span className="text-[11px] text-text-muted">({count})</span>
                </a>
                <ul className="pl-4 mt-1 space-y-0.5">
                  {groups[sev].map((f) => (
                    <li key={f.id} className="flex items-baseline gap-1.5">
                      <span className="text-[10px] font-bold shrink-0" style={{ color }}>#{f.id}</span>
                      <a
                        href={`#finding-${f.id}`}
                        onClick={scrollToId(`finding-${f.id}`)}
                        className="text-xs text-charcoal-light hover:text-terracotta no-underline cursor-pointer"
                      >
                        {FindingTitle(f)}
                      </a>
                    </li>
                  ))}
                </ul>
              </li>
            );
          })}
          <li>
            <a href="#appendix" onClick={scrollToId("appendix")} className="text-[13px] font-semibold text-charcoal hover:text-terracotta no-underline cursor-pointer">
              {++tocIndex}. Appendix
            </a>
          </li>
        </ol>
      </div>

      {/* Findings by Severity */}
      {SEVERITY_ORDER.map((sev) => (
        <SeveritySection
          key={sev}
          severity={sev}
          findings={groups[sev]}
        />
      ))}

      {/* Appendix */}
      <div id="appendix" className="mb-8">
        <h2 className="text-xl font-bold text-charcoal border-b border-warm-border pb-2 mb-5 font-serif">Appendix</h2>
        <ModuleTable modules={data.modules} />
      </div>

      {/* Footer */}
      <div className="mt-10 pt-4 border-t border-warm-border text-center text-[11px] text-text-muted">
        Generated by Vigolium{vigoliumVersion ? ` v${vigoliumVersion}` : ""} &mdash; {date}
      </div>

      {/* Back to top button */}
      {showBackToTop && (
        <button
          onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
          className="no-print fixed bottom-6 right-6 flex items-center gap-1.5 px-3 py-2 bg-charcoal text-cream text-xs font-semibold rounded-md shadow-lg hover:bg-charcoal-light transition-colors z-50"
        >
          <ArrowUp size={13} />
          Back to top
        </button>
      )}
    </div>
  );
}
