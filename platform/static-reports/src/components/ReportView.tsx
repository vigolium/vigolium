import { useMemo, useState, useEffect, useCallback } from "react";
import { marked } from "marked";
import { Code, Copy, Check, List } from "lucide-react";
import type { ExportData, Finding, ModuleRecord } from "../types";
import { computeSummary, severityCounts } from "../utils/parse";
import { sanitizeHtml } from "../utils/sanitize";
import Hero from "./Hero";
import SeverityDonut from "./SeverityDonut";

marked.setOptions({ breaks: false, gfm: true });

interface Props {
  data: ExportData;
  scanDuration?: string;
  generatedAt?: string;
  scanTarget?: string;
  vigoliumVersion?: string;
  reportTitle?: string;
  reportSharedURL?: string;
}

const DEFAULT_REPORT_SHARED_URL = "https://console.vigolium.com/shared/audit-reports/";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "suspect", "info"] as const;
type SeverityKey = (typeof SEVERITY_ORDER)[number];

const SEVERITY_LABELS: Record<SeverityKey, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  suspect: "Suspect",
  info: "Informational",
};

function sevKey(raw: string | undefined): SeverityKey {
  const v = (raw || "").toLowerCase();
  if (v === "critical" || v === "high" || v === "medium" || v === "low" || v === "suspect" || v === "info") {
    return v;
  }
  return "info";
}

function groupBySeverity(findings: Finding[]): Record<SeverityKey, Finding[]> {
  const groups: Record<SeverityKey, Finding[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
    suspect: [],
    info: [],
  };
  for (const f of findings) {
    groups[sevKey(f.severity)].push(f);
  }
  return groups;
}

function findingTitle(f: Finding): string {
  const name = f.module_short || f.module_name;
  if (f.url) {
    const truncated = f.url.length > 80 ? f.url.slice(0, 80) + "…" : f.url;
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

function highlightMarkdown(md: string): React.ReactNode[] {
  const lines = md.split("\n");
  const result: React.ReactNode[] = [];
  let inCodeBlock = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (i > 0) result.push("\n");

    if (line.startsWith("```")) {
      inCodeBlock = !inCodeBlock;
      result.push(<span key={i} className="md-fence">{line}</span>);
      continue;
    }
    if (inCodeBlock) {
      result.push(<span key={i} className="md-code-line">{line}</span>);
      continue;
    }

    if (/^#{1,6}\s/.test(line)) {
      result.push(<span key={i} className="md-heading">{line}</span>);
    } else if (/^\s*[-*]\s/.test(line)) {
      result.push(<span key={i}>{highlightInline(line, `li-${i}`)}</span>);
    } else if (/^\|/.test(line)) {
      result.push(<span key={i} className="md-table">{line}</span>);
    } else if (line.trim() === "") {
      result.push("");
    } else {
      result.push(<span key={i}>{highlightInline(line, `p-${i}`)}</span>);
    }
  }
  return result;
}

function highlightInline(text: string, keyPrefix: string): React.ReactNode[] {
  const parts: React.ReactNode[] = [];
  const re = /(\*\*[^*]+\*\*)|(`[^`]+`)/g;
  let last = 0;
  let match: RegExpExecArray | null;
  let idx = 0;
  while ((match = re.exec(text)) !== null) {
    if (match.index > last) parts.push(text.slice(last, match.index));
    if (match[1]) {
      parts.push(<span key={`${keyPrefix}-${idx}`} className="md-bold">{match[1]}</span>);
    } else if (match[2]) {
      parts.push(<span key={`${keyPrefix}-${idx}`} className="md-inline-code">{match[2]}</span>);
    }
    last = match.index + match[0].length;
    idx++;
  }
  if (last < text.length) parts.push(text.slice(last));
  return parts;
}

function findingToMarkdown(f: Finding): string {
  const sev = sevKey(f.severity);
  const lines: string[] = [];
  lines.push(`## #${f.id} — ${f.module_short || f.module_name}`);
  lines.push(`**Severity:** ${SEVERITY_LABELS[sev]}${f.confidence ? ` | **Confidence:** ${f.confidence}` : ""}`);
  if (f.url) lines.push(`**URL:** ${f.url}`);
  lines.push("");
  if (f.description) { lines.push("### Summary"); lines.push(f.description); lines.push(""); }
  if (f.module_id || f.cwe_id || (f.cvss_score ?? 0) > 0 || f.source_file || f.repo_name) {
    lines.push("### Metadata");
    if (f.module_id) lines.push(`- **Module:** \`${f.module_id}\``);
    if (f.cwe_id) lines.push(`- **CWE:** \`${f.cwe_id}\``);
    if (f.cvss_score !== undefined && f.cvss_score > 0) lines.push(`- **CVSS:** ${f.cvss_score.toFixed(1)}`);
    if (f.source_file) lines.push(`- **Source:** \`${f.source_file}\``);
    if (f.repo_name) lines.push(`- **Repository:** \`${f.repo_name}\``);
    if (f.found_at) lines.push(`- **Found:** ${f.found_at}`);
    lines.push("");
  }
  if (f.tags?.length) { lines.push("### Tags"); lines.push(f.tags.map(t => `\`${t}\``).join(", ")); lines.push(""); }
  if (f.matched_at?.length) { lines.push("### Matched At"); f.matched_at.forEach(m => lines.push(`- \`${m}\``)); lines.push(""); }
  if (f.extracted_results?.length) { lines.push("### Evidence"); f.extracted_results.forEach(r => lines.push(`- ${r}`)); lines.push(""); }
  if (f.remediation) { lines.push("### Remediation"); lines.push(f.remediation); lines.push(""); }
  if (f.request) { lines.push("### Request"); lines.push("```"); lines.push(f.request); lines.push("```"); lines.push(""); }
  if (f.response) { lines.push("### Response"); lines.push("```"); lines.push(f.response); lines.push("```"); lines.push(""); }
  if (f.additional_evidence?.length) {
    lines.push("### Additional Evidence");
    f.additional_evidence.forEach(e => { lines.push("```"); lines.push(e); lines.push("```"); });
    lines.push("");
  }
  return lines.join("\n");
}

function FindingCard({ finding }: { finding: Finding }) {
  const sev = sevKey(finding.severity);
  const [showRaw, setShowRaw] = useState(false);
  const [copied, setCopied] = useState(false);

  const descHtml = useMemo(() => {
    if (!finding.description) return "";
    return sanitizeHtml(marked.parse(finding.description) as string);
  }, [finding.description]);

  const rawMd = useMemo(() => findingToMarkdown(finding), [finding]);
  const rawHighlighted = useMemo(() => highlightMarkdown(rawMd), [rawMd]);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(rawMd).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [rawMd]);

  return (
    <article
      id={`f-${finding.id}`}
      className="finding"
      style={{ ["--fsev" as string]: `var(--sev-${sev})` }}
    >
      <div className="finding-head">
        <span className="idn">#{finding.id}</span>
        <span className="sev-pill" style={{ background: `var(--sev-${sev})` }}>
          {SEVERITY_LABELS[sev]}
        </span>
        <span className="slug">{finding.module_short || finding.module_name}</span>
        {finding.confidence && <span className="conf">{finding.confidence}</span>}
        <span style={{ flex: 1 }} />
        <span className="finding-actions no-print">
          <button
            className="finding-action-btn"
            onClick={() => setShowRaw(!showRaw)}
            title={showRaw ? "Show rendered" : "Show raw markdown"}
          >
            <Code size={13} />
          </button>
          <button
            className="finding-action-btn"
            onClick={handleCopy}
            title="Copy as markdown"
          >
            {copied ? <Check size={13} /> : <Copy size={13} />}
          </button>
        </span>
      </div>

      {showRaw ? (
        <pre className="finding-raw">{rawHighlighted}</pre>
      ) : (
        <>
          {finding.url && (
            <p style={{ fontSize: 12, color: "var(--v-text-muted)", wordBreak: "break-all", marginTop: 0 }}>
              {finding.url}
            </p>
          )}

          {descHtml && (
            <>
              <h4>Summary</h4>
              <div className="prose-finding" dangerouslySetInnerHTML={{ __html: descHtml }} />
            </>
          )}

          {(finding.module_id || finding.cwe_id || (finding.cvss_score ?? 0) > 0 || finding.source_file || finding.repo_name) && (
            <>
              <h4>Metadata</h4>
              <ul>
                <li>
                  <strong>Module:</strong> <code className="chip">{finding.module_id}</code>
                </li>
                {finding.cwe_id && (
                  <li>
                    <strong>CWE:</strong> <code className="chip">{finding.cwe_id}</code>
                  </li>
                )}
                {finding.cvss_score !== undefined && finding.cvss_score > 0 && (
                  <li>
                    <strong>CVSS:</strong> {finding.cvss_score.toFixed(1)}
                  </li>
                )}
                {finding.source_file && (
                  <li>
                    <strong>Source:</strong> <code className="chip">{finding.source_file}</code>
                  </li>
                )}
                {finding.repo_name && (
                  <li>
                    <strong>Repository:</strong> <code className="chip">{finding.repo_name}</code>
                  </li>
                )}
                {finding.found_at && (
                  <li>
                    <strong>Found:</strong> {finding.found_at}
                  </li>
                )}
              </ul>
            </>
          )}

          {finding.tags && finding.tags.length > 0 && (
            <>
              <h4>Tags</h4>
              <p>
                {finding.tags.map((t) => (
                  <code key={t} className="chip" style={{ marginRight: 4 }}>
                    {t}
                  </code>
                ))}
              </p>
            </>
          )}

          {finding.matched_at && finding.matched_at.length > 0 && (
            <>
              <h4>Matched At</h4>
              <ul>
                {finding.matched_at.map((m, i) => (
                  <li key={i}>
                    <code className="chip b">{m}</code>
                  </li>
                ))}
              </ul>
            </>
          )}

          {finding.extracted_results && finding.extracted_results.length > 0 && (
            <>
              <h4>Evidence</h4>
              <ul>
                {finding.extracted_results.map((r, i) => (
                  <li key={i} style={{ wordBreak: "break-all" }}>
                    {r}
                  </li>
                ))}
              </ul>
            </>
          )}

          {finding.remediation && (
            <>
              <h4>Remediation</h4>
              <p>{finding.remediation}</p>
            </>
          )}

          {finding.request && (
            <>
              <h4>Request</h4>
              <pre
                style={{
                  background: "var(--v-code-bg)",
                  border: "1px solid var(--v-border)",
                  borderRadius: 4,
                  padding: 12,
                  fontSize: 11,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                  maxHeight: 400,
                  overflowY: "auto",
                  color: "var(--v-text)",
                  margin: "6px 0",
                }}
              >
                {finding.request}
              </pre>
            </>
          )}

          {finding.response && (
            <>
              <h4>Response</h4>
              <pre
                style={{
                  background: "var(--v-code-bg)",
                  border: "1px solid var(--v-border)",
                  borderRadius: 4,
                  padding: 12,
                  fontSize: 11,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                  maxHeight: 400,
                  overflowY: "auto",
                  color: "var(--v-text)",
                  margin: "6px 0",
                }}
              >
                {finding.response}
              </pre>
            </>
          )}

          {finding.additional_evidence && finding.additional_evidence.length > 0 && (
            <>
              <h4>Additional Evidence</h4>
              {finding.additional_evidence.map((e, i) => (
                <pre
                  key={i}
                  style={{
                    background: "var(--v-code-bg)",
                    border: "1px solid var(--v-border)",
                    borderRadius: 4,
                    padding: 12,
                    fontSize: 11,
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-all",
                    maxHeight: 400,
                    overflowY: "auto",
                    color: "var(--v-text)",
                    margin: "6px 0",
                  }}
                >
                  {e}
                </pre>
              ))}
            </>
          )}
        </>
      )}
    </article>
  );
}

function ModuleTable({ modules }: { modules: ModuleRecord[] }) {
  const enabled = modules.filter((m) => m.enabled);
  if (enabled.length === 0) return null;

  return (
    <>
      <h4>Enabled scanner modules ({enabled.length})</h4>
      <table
        style={{
          width: "100%",
          borderCollapse: "collapse",
          fontSize: 11,
          marginTop: 6,
        }}
      >
        <thead>
          <tr style={{ borderBottom: "1px solid var(--v-border)" }}>
            {["ID", "Name", "Type", "Severity"].map((h) => (
              <th
                key={h}
                style={{
                  textAlign: "left",
                  padding: "6px 8px",
                  color: "var(--v-tertiary)",
                  textTransform: "uppercase",
                  letterSpacing: "0.06em",
                  fontSize: 10,
                }}
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {enabled.map((m) => (
            <tr key={m.id} style={{ borderBottom: "1px dashed var(--v-border)" }}>
              <td style={{ padding: "4px 8px" }}>
                <code className="chip">{m.id}</code>
              </td>
              <td style={{ padding: "4px 8px", color: "var(--v-text)" }}>{m.name}</td>
              <td style={{ padding: "4px 8px", color: "var(--v-text-muted)" }}>{m.type}</td>
              <td style={{ padding: "4px 8px", color: "var(--v-text-muted)" }}>{m.severity}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function FloatingToc({ groups, modules }: { groups: Record<SeverityKey, Finding[]>; modules: ModuleRecord[] }) {
  const [visible, setVisible] = useState(false);
  const [open, setOpen] = useState(true);

  useEffect(() => {
    const onScroll = () => {
      const tocEl = document.querySelector(".toc");
      if (!tocEl) return;
      const rect = tocEl.getBoundingClientRect();
      setVisible(rect.bottom < 0);
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  if (!visible) return null;

  let idx = 1;
  return (
    <nav className={`floating-toc no-print${open ? "" : " collapsed"}`}>
      <button className="floating-toc-toggle" onClick={() => setOpen(!open)}>
        <List size={14} />
        {open ? "TOC" : ""}
      </button>
      {open && (
        <ol>
          <li>
            <a href="#statistics" onClick={scrollToId("statistics")}>{idx++}. Summary</a>
          </li>
          {SEVERITY_ORDER.map((sev) => {
            const arr = groups[sev];
            if (arr.length === 0) return null;
            return (
              <li key={sev}>
                <a href={`#sec-${sev}`} onClick={scrollToId(`sec-${sev}`)} style={{ color: `var(--sev-${sev})` }}>
                  {idx++}. {SEVERITY_LABELS[sev]} ({arr.length})
                </a>
              </li>
            );
          })}
          {modules.length > 0 && (
            <li>
              <a href="#appendix" onClick={scrollToId("appendix")}>{idx++}. Appendix</a>
            </li>
          )}
        </ol>
      )}
    </nav>
  );
}

export default function ReportView({ data, scanDuration, generatedAt, scanTarget, vigoliumVersion, reportTitle, reportSharedURL }: Props) {
  const summary = useMemo(() => {
    const s = computeSummary(data);
    if (scanDuration) s.scanDuration = scanDuration;
    return s;
  }, [data, scanDuration]);

  const groups = useMemo(() => groupBySeverity(data.findings), [data.findings]);
  const counts = useMemo(() => severityCounts(data.findings), [data.findings]);
  const total = data.findings.length;

  const CONF_ORDER = ["certain", "firm", "tentative", "suspect"] as const;
  const CONF_LABEL: Record<string, string> = { certain: "Certain", firm: "Firm", tentative: "Tentative", suspect: "Suspect" };
  const crossTab = useMemo(() => {
    const matrix: Record<string, Record<string, number>> = {};
    for (const sev of SEVERITY_ORDER) {
      matrix[sev] = {};
      for (const c of CONF_ORDER) matrix[sev][c] = 0;
    }
    for (const f of data.findings) {
      const sev = (f.severity || "info").toLowerCase();
      const conf = (f.confidence || "").toLowerCase();
      const s = SEVERITY_ORDER.includes(sev as typeof SEVERITY_ORDER[number]) ? sev : "info";
      const c = conf === "certain" ? "certain" : conf === "firm" ? "firm" : conf === "tentative" ? "tentative" : "suspect";
      matrix[s][c]++;
    }
    return matrix;
  }, [data.findings]);

  const date = useMemo(() => {
    if (!generatedAt) {
      return new Date().toLocaleDateString(undefined, {
        weekday: "long",
        year: "numeric",
        month: "long",
        day: "numeric",
      });
    }
    const d = new Date(generatedAt);
    if (isNaN(d.getTime())) return generatedAt;
    return d.toLocaleDateString(undefined, {
      weekday: "long",
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  }, [generatedAt]);

  let tocIdx = 1;

  return (
    <div className="report-view" id="report-top">
      <FloatingToc groups={groups} modules={data.modules} />

      <Hero
        title={reportTitle || "Vigolium Scan Report"}
        eyebrow={<><span style={{ background: "var(--v-accent)", color: "var(--v-surface)", padding: "2px 8px" }}>FULL REPORT</span><span>SCAN REPORT</span></>}
        lede="Comprehensive findings with full context severity, details, and actionable remediation."
        action={{ label: "Print", icon: "print", onClick: () => window.print() }}
        secondaryAction={{
          label: "Raw Report URL",
          icon: "archive",
          href: reportSharedURL || DEFAULT_REPORT_SHARED_URL,
          highlight: !!reportSharedURL && reportSharedURL !== DEFAULT_REPORT_SHARED_URL,
        }}
        titleBlock={[
          { label: "Generated at", value: date },
          { label: "Target", value: scanTarget || summary.target },
          { label: "Total Findings", value: String(total) },
          { label: "Duration", value: summary.scanDuration === "N/A" ? <span style={{ color: "darkmagenta" }}>N/A</span> : <span style={{ color: "var(--v-info)" }}>{summary.scanDuration}</span> },
          { label: "Status", value: <span style={{ color: "var(--v-success)" }}>● COMPLETED</span> },
        ]}
      />

      <section id="statistics">
        <h2 className="sec-title">Executive Summary</h2>
        <div className="stats-grid stats-grid--compact">
          <div className="card span-6">
            <h3>Severity distribution</h3>
            <div className="donut-wrap" style={{ gap: 20 }}>
              <SeverityDonut counts={counts} size={150} />
              <div className="donut-legend" style={{ flex: 1 }}>
                {SEVERITY_ORDER.map((k) => {
                  const v = counts[k] || 0;
                  const pct = total ? Math.round((v / total) * 100) : 0;
                  return (
                    <div key={k} className="row">
                      <i style={{ background: `var(--sev-${k})` }} />
                      <span className="lbl">{SEVERITY_LABELS[k]}</span>
                      <span className="val">{v}</span>
                      <span className="pct">{pct}%</span>
                    </div>
                  );
                })}
              </div>
            </div>
            <div style={{ marginTop: "auto" }}>
              <div className="severity-bar">
                {SEVERITY_ORDER.map((k) => {
                  const v = counts[k] || 0;
                  if (!v || !total) return null;
                  return <span key={k} style={{ width: `${(v / total) * 100}%`, background: `var(--sev-${k})` }} />;
                })}
              </div>
            </div>
          </div>

          <div className="card span-6">
            <h3>Severity &times; Confidence</h3>
            <div style={{ overflowX: "auto" }}>
              <table className="cross-tab">
                <thead>
                  <tr>
                    <th className="cross-tab-corner">
                      <span className="cross-tab-corner-bl">Severity</span>
                      <span className="cross-tab-corner-tr">Confidence</span>
                    </th>
                    {CONF_ORDER.map((c) => (
                      <th key={c}>{CONF_LABEL[c]}</th>
                    ))}
                    <th>Total</th>
                  </tr>
                </thead>
                <tbody>
                  {SEVERITY_ORDER.map((sev) => {
                    const row = crossTab[sev];
                    const rowTotal = CONF_ORDER.reduce((s, c) => s + (row[c] || 0), 0);
                    return (
                      <tr key={sev}>
                        <td className="cross-tab-sev" style={{ color: `var(--sev-${sev})` }}>
                          {SEVERITY_LABELS[sev]}
                        </td>
                        {CONF_ORDER.map((c) => {
                          const v = row[c] || 0;
                          const intensity = total > 0 ? Math.min(v / total, 1) : 0;
                          return (
                            <td
                              key={c}
                              className="cross-tab-cell"
                              style={{
                                background: v > 0
                                  ? `color-mix(in srgb, var(--sev-${sev}) ${Math.max(12, Math.round(intensity * 100 + 15))}%, transparent)`
                                  : undefined,
                              }}
                            >
                              {v}
                            </td>
                          );
                        })}
                        <td className="cross-tab-total">{rowTotal}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </section>

      <div className="toc">
        <div className="toc-title">Table of Contents</div>
        <ol>
          <li>
            <div className="sec-line">
              <a href="#statistics" onClick={scrollToId("statistics")}>
                {tocIdx++}. Executive Summary
              </a>
            </div>
          </li>
          {SEVERITY_ORDER.map((sev) => {
            const arr = groups[sev];
            if (arr.length === 0) return null;
            return (
              <li key={sev}>
                <div className="sec-line">
                  <span className="sev-tag" style={{ color: `var(--sev-${sev})` }}>
                    {SEVERITY_LABELS[sev]}
                  </span>
                  <a href={`#sec-${sev}`} onClick={scrollToId(`sec-${sev}`)}>
                    {tocIdx++}. {SEVERITY_LABELS[sev]} Findings ({arr.length})
                  </a>
                </div>
                <ul className="findings-list">
                  {arr.map((f) => (
                    <li key={f.id}>
                      <span className="fid">#{f.id}</span>
                      <a
                        href={`#f-${f.id}`}
                        onClick={scrollToId(`f-${f.id}`)}
                        style={{ color: `var(--sev-${sev})` }}
                      >
                        {findingTitle(f)}
                      </a>
                    </li>
                  ))}
                </ul>
              </li>
            );
          })}
          {data.modules.length > 0 && (
            <li>
              <div className="sec-line">
                <a href="#appendix" onClick={scrollToId("appendix")}>
                  {tocIdx++}. Appendix
                </a>
              </div>
            </li>
          )}
        </ol>
      </div>

      <section id="findings-sections">
        {SEVERITY_ORDER.map((sev) => {
          const arr = groups[sev];
          if (arr.length === 0) return null;
          return (
            <section key={sev} id={`sec-${sev}`}>
              <div className="sev-section">
                <span className="pill" style={{ background: `var(--sev-${sev})` }}>
                  {SEVERITY_LABELS[sev]}
                </span>
                <h2>Findings ({arr.length})</h2>
              </div>
              {arr.map((f) => (
                <FindingCard key={f.id} finding={f} />
              ))}
            </section>
          );
        })}
      </section>

      {data.modules.length > 0 && (
        <section id="appendix" style={{ marginTop: 42 }}>
          <h2 className="sec-title">Appendix</h2>
          <div className="card span-12">
            <ModuleTable modules={data.modules} />
          </div>
        </section>
      )}

      <div className="footer">
        <span>&gt; vigolium scan report · self-contained · schema v1</span>
        <span>
          generated by {vigoliumVersion ? `vigolium-report@${vigoliumVersion}` : "vigolium-report"} · {date}
        </span>
      </div>
    </div>
  );
}
