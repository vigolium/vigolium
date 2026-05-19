import type { ScanSummary } from "../types";
import { useTheme } from "../utils/theme";
import { getSeverityColors } from "../utils/chartTheme";

interface Props {
  summary: ScanSummary;
}

export default function SummaryCards({ summary }: Props) {
  const { theme } = useTheme();
  const sevColors = getSeverityColors(theme);
  const severityCards = [
    { label: "Critical", count: summary.criticalCount, color: sevColors.critical },
    { label: "High", count: summary.highCount, color: sevColors.high },
    { label: "Medium", count: summary.mediumCount, color: sevColors.medium },
    { label: "Low", count: summary.lowCount, color: sevColors.low },
    { label: "Info", count: summary.infoCount, color: sevColors.info },
  ];

  return (
    <div className="space-y-6">
      {/* Top row: high-level stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-6">
        <div className="border-b-2 border-terracotta pb-3">
          <div className="font-serif text-3xl font-bold text-charcoal tracking-tight">
            {summary.totalFindings}
          </div>
          <div className="mt-1 text-xs font-sans text-text-muted uppercase tracking-widest font-semibold">
            Findings
          </div>
        </div>
        <div className="border-b-2 border-terracotta pb-3">
          <div className="font-serif text-3xl font-bold text-charcoal tracking-tight">
            {summary.totalRequests.toLocaleString()}
          </div>
          <div className="mt-1 text-xs font-sans text-text-muted uppercase tracking-widest font-semibold">
            HTTP Records
          </div>
        </div>
        <div className="border-b-2 border-terracotta pb-3">
          <div className="font-serif text-3xl font-bold text-charcoal tracking-tight">
            {summary.uniqueDomains}
          </div>
          <div className="mt-1 text-xs font-sans text-text-muted uppercase tracking-widest font-semibold">
            Domains
          </div>
        </div>
        <div className="border-b-2 border-terracotta pb-3">
          <div className="font-serif text-3xl font-bold text-charcoal tracking-tight">
            {summary.activeModules + summary.passiveModules}
          </div>
          <div className="mt-1 text-xs font-sans text-text-muted uppercase tracking-widest font-semibold">
            Modules
          </div>
        </div>
        <div className="border-b-2 border-terracotta pb-3">
          <div className="font-serif text-3xl font-bold text-charcoal tracking-tight">
            {summary.scanDuration}
          </div>
          <div className="mt-1 text-xs font-sans text-text-muted uppercase tracking-widest font-semibold">
            Duration
          </div>
        </div>
      </div>

      {/* Severity breakdown row */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-5 md:gap-4">
        {severityCards.map(({ label, count, color }) => (
          <div
            key={label}
            className="flex min-w-0 flex-col items-start gap-1 rounded-md border border-warm-border px-3 py-3 sm:px-4 md:flex-row md:items-center md:gap-3"
          >
            <div
              className="text-2xl leading-none font-serif font-bold"
              style={{ color: count > 0 ? color : theme === "dark" ? "#4a4641" : "#ccc" }}
            >
              {count}
            </div>
            <div className="min-w-0 text-[10px] leading-tight font-sans font-semibold uppercase tracking-[0.16em] text-text-muted sm:text-xs md:tracking-wider">
              {label}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
