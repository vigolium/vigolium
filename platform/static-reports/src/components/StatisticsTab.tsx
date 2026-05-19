import { useMemo } from "react";
import type { ExportData, Finding } from "../types";
import {
  computeSummary,
  findingsByModule,
  httpByContentType,
  httpByMethod,
  httpByStatusCodeExact,
  severityCounts,
} from "../utils/parse";
import Hero from "./Hero";
import SeverityDonut from "./SeverityDonut";

interface Props {
  data: ExportData;
  scanDuration?: string;
  generatedAt?: string;
  reportTitle?: string;
  scanTarget?: string;
  reportSharedURL?: string;
}

const DEFAULT_REPORT_SHARED_URL = "https://console.vigolium.com/shared/audit-reports/";

const SEV_ORDER = ["critical", "high", "medium", "low", "suspect", "info", "n/a"] as const;

function sevCssVar(k: string): string {
  return `var(--sev-${k === "n/a" ? "na" : k})`;
}

const SEV_LABEL: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  suspect: "Suspect",
  info: "Info",
  "n/a": "N/A",
};

const CONF_ORDER = ["certain", "firm", "tentative", "suspect"] as const;
const CONF_LABEL: Record<string, string> = {
  certain: "Certain",
  firm: "Firm",
  tentative: "Tentative",
  suspect: "Suspect",
};

const METHOD_VARS: Record<string, string> = {
  GET: "var(--m-get)",
  POST: "var(--m-post)",
  PUT: "var(--m-put)",
  PATCH: "var(--m-patch)",
  DELETE: "var(--m-delete)",
  HEAD: "var(--m-head)",
  OPTIONS: "var(--m-options)",
};

// Distinct, theme-aware palette so each content-type chip reads differently.
const CT_PALETTE = [
  "var(--m-post)",
  "var(--m-get)",
  "var(--m-options)",
  "var(--m-patch)",
  "var(--m-put)",
  "var(--sev-suspect)",
  "var(--m-delete)",
  "var(--m-head)",
] as const;

function statusCodeColor(status: string): string {
  switch (status.charAt(0)) {
    case "2": return "var(--v-success)";
    case "3": return "var(--v-info)";
    case "4": return "var(--v-accent-2)";
    case "5": return "var(--v-error)";
    default: return "var(--v-text-muted)";
  }
}

function buildCrossTab(findings: Finding[]) {
  const matrix: Record<string, Record<string, number>> = {};
  for (const sev of SEV_ORDER) {
    matrix[sev] = {};
    for (const conf of CONF_ORDER) matrix[sev][conf] = 0;
  }
  for (const f of findings) {
    const sev = (f.severity || "info").toLowerCase();
    const conf = (f.confidence || "").toLowerCase();
    const s = SEV_ORDER.includes(sev as typeof SEV_ORDER[number]) ? sev : "info";
    const c = conf === "certain" ? "certain" : conf === "firm" ? "firm" : conf === "tentative" ? "tentative" : "suspect";
    matrix[s][c]++;
  }
  return matrix;
}

function formatDate(value?: string): string {
  if (!value) {
    return new Date().toLocaleDateString(undefined, {
      weekday: "long", year: "numeric", month: "long", day: "numeric",
    });
  }
  const parsed = new Date(value);
  if (isNaN(parsed.getTime())) return value;
  return parsed.toLocaleDateString(undefined, {
    weekday: "long", year: "numeric", month: "long", day: "numeric",
  });
}

export default function StatisticsTab({ data, scanDuration, generatedAt, reportTitle, scanTarget, reportSharedURL }: Props) {
  const summary = useMemo(() => {
    const s = computeSummary(data);
    if (scanDuration) s.scanDuration = scanDuration;
    return s;
  }, [data, scanDuration]);

  const counts = useMemo(() => severityCounts(data.findings), [data.findings]);
  const total = data.findings.length;

  const crossTab = useMemo(() => buildCrossTab(data.findings), [data.findings]);

  const modules = useMemo(() => findingsByModule(data.findings).slice(0, 12), [data.findings]);
  const modMax = Math.max(1, ...modules.map((m) => m.count));

  const methods = useMemo(() => httpByMethod(data.httpRecords), [data.httpRecords]);
  const statusCodes = useMemo(() => httpByStatusCodeExact(data.httpRecords), [data.httpRecords]);
  const contentTypes = useMemo(() => httpByContentType(data.httpRecords).slice(0, 8), [data.httpRecords]);
  const methodsTotal = data.httpRecords.length;

  const activeSevs = SEV_ORDER.filter((s) => (counts[s] || 0) > 0);

  return (
    <>
      <Hero
        title="Scan metrics & distributions."
        metaTitle={reportTitle || "Vigolium Scan Report"}
        eyebrow={<><span style={{ background: "var(--v-accent)", color: "var(--v-surface)", padding: "2px 8px" }}>STATISTICS</span><span>METRICS</span></>}
        lede={summary.scanDuration && summary.scanDuration !== "N/A"
          ? `Severity, confidence, and HTTP traffic distribution across the ${summary.scanDuration} sweep window.`
          : "Severity, confidence, and HTTP traffic distribution across the scan window."}
        action={{ label: "Print", icon: "print", onClick: () => window.print() }}
        secondaryAction={{
          label: "Raw Report URL",
          icon: "archive",
          href: reportSharedURL || DEFAULT_REPORT_SHARED_URL,
          highlight: !!reportSharedURL && reportSharedURL !== DEFAULT_REPORT_SHARED_URL,
        }}
        titleBlock={[
          { label: "Generated at", value: formatDate(generatedAt) },
          { label: "Target", value: scanTarget || summary.target },
          { label: "Total Findings", value: String(total) },
          { label: "Duration", value: summary.scanDuration === "N/A" ? <span style={{ color: "darkmagenta" }}>N/A</span> : <span style={{ color: "var(--v-info)" }}>{summary.scanDuration}</span> },
          { label: "Status", value: <span style={{ color: "var(--v-success)" }}>● COMPLETED</span> },
        ]}
      />

      <div className="stats-grid">
        {/* Donut + legend + severity bar */}
        <div className="card span-6">
          <h3>Severity distribution</h3>
          <div className="donut-wrap" style={{ gap: 20 }}>
            <SeverityDonut counts={counts} size={150} />
            <div className="donut-legend" style={{ flex: 1 }}>
              {SEV_ORDER.map((k) => {
                const v = counts[k] || 0;
                const pct = total ? Math.round((v / total) * 100) : 0;
                return (
                  <div key={k} className="row">
                    <i style={{ background: sevCssVar(k) }} />
                    <span className="lbl">{SEV_LABEL[k]}</span>
                    <span className="val">{v}</span>
                    <span className="pct">{pct}%</span>
                  </div>
                );
              })}
            </div>
          </div>
          <div style={{ marginTop: "auto" }}>
            <div className="severity-bar">
              {SEV_ORDER.map((k) => {
                const v = counts[k] || 0;
                if (!v || !total) return null;
                return <span key={k} style={{ width: `${(v / total) * 100}%`, background: sevCssVar(k) }} />;
              })}
            </div>
          </div>
        </div>

        {/* Severity × Confidence cross-tab */}
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
                {SEV_ORDER.map((sev) => {
                  const row = crossTab[sev];
                  const rowTotal = CONF_ORDER.reduce((s, c) => s + (row[c] || 0), 0);
                  return (
                    <tr key={sev}>
                      <td className="cross-tab-sev" style={{ color: sevCssVar(sev) }}>
                        {SEV_LABEL[sev]}
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
                                ? `color-mix(in srgb, ${sevCssVar(sev)} ${Math.max(12, Math.round(intensity * 100 + 15))}%, transparent)`
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

        {/* Top modules */}
        <div className="card span-6">
          <h3>Top modules by finding count</h3>
          {modules.length > 0 ? (
            <div className="mod-list">
              {modules.map((m) => (
                <div key={m.module} className="mod-row">
                  <span className="name" title={m.module}>
                    {m.module}
                  </span>
                  <span className="bar">
                    <i style={{ width: `${(m.count / modMax) * 100}%` }} />
                  </span>
                  <span className="n">{m.count}</span>
                </div>
              ))}
            </div>
          ) : (
            <p style={{ color: "var(--v-text-muted)", fontSize: 11 }}>No findings yet.</p>
          )}
        </div>

        {/* HTTP distribution */}
        <div className="card span-6">
          <h3>HTTP distribution</h3>
          {methodsTotal > 0 ? (
            <>
              <div className="dist-block">
                <span className="dist-label">By method</span>
                <div className="method-grid">
                  {methods.map((m) => (
                    <div
                      key={m.method}
                      className="method-chip"
                      style={{ color: METHOD_VARS[m.method] || "var(--v-text-muted)" }}
                    >
                      <span>{m.method}</span>
                      <span className="v">{m.count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="dist-block">
                <span className="dist-label">By status code</span>
                <div className="method-grid">
                  {statusCodes.map((s) => (
                    <div
                      key={s.status}
                      className="method-chip"
                      style={{ color: statusCodeColor(s.status) }}
                    >
                      <span>{s.status}</span>
                      <span className="v">{s.count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="dist-block">
                <span className="dist-label">By content type</span>
                <div className="ct-list">
                  {contentTypes.map((c, i) => (
                    <div
                      key={c.type}
                      className="method-chip"
                      style={{ color: CT_PALETTE[i % CT_PALETTE.length] }}
                    >
                      <span title={c.type}>{c.type}</span>
                      <span className="v">{c.count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ marginTop: 12, fontSize: 10, color: "var(--v-text-muted)" }}>
                Across {methodsTotal.toLocaleString()} captured request
                {methodsTotal === 1 ? "" : "s"}
              </div>
            </>
          ) : (
            <p style={{ color: "var(--v-text-muted)", fontSize: 11 }}>
              No HTTP traffic captured.
            </p>
          )}
        </div>
      </div>
    </>
  );
}
