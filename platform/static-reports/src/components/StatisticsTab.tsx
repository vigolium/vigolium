import type { ExportData } from "../types";
import {
  computeSummary,
  findingsBySeverity,
  findingsByModule,
  findingsByModuleWithSeverity,
  httpByStatusCode,
  httpByContentType,
} from "../utils/parse";
import { useTheme } from "../utils/theme";
import { getSeverityColors, getColors } from "../utils/chartTheme";
import SummaryCards from "./SummaryCards";
import SectionTitle from "./SectionTitle";
import DecorativeRule from "./DecorativeRule";
import BarChartComponent from "./BarChart";
import PieChartComponent from "./PieChart";
import type { ModuleFindingSummary } from "../utils/parse";

interface Props {
  data: ExportData;
  scanDuration?: string;
}

const MAX_BARS = 15;

function HorizontalBarList({ data, color }: { data: { label: string; count: number }[]; color: string }) {
  const visible = data.slice(0, MAX_BARS);
  const remaining = data.length - visible.length;
  const maxCount = Math.max(...data.map((d) => d.count), 1);

  return (
    <div>
      <div className="space-y-0.5">
        {visible.map((row) => (
          <div key={row.label} className="flex items-center gap-2">
            <span className="text-[11px] text-charcoal-light w-[240px] shrink-0 text-right truncate" title={row.label}>
              {row.label}
            </span>
            <div className="w-[280px] shrink-0 h-[14px] bg-warm-border/20 rounded-sm overflow-hidden">
              <div
                className="h-full rounded-sm"
                style={{
                  width: `${Math.max((row.count / maxCount) * 100, 8)}%`,
                  backgroundColor: color,
                  opacity: 0.75,
                }}
              />
            </div>
            <span className="text-[11px] text-text-muted w-[20px] shrink-0 text-right">{row.count}</span>
          </div>
        ))}
      </div>
      {remaining > 0 && (
        <div className="text-[10px] text-text-muted text-right pt-1">
          +{remaining} more
        </div>
      )}
    </div>
  );
}

function ModuleBarChart({ data }: { data: ModuleFindingSummary[] }) {
  const { theme } = useTheme();
  const severityColors = getSeverityColors(theme);

  const visible = data.slice(0, MAX_BARS);
  const remaining = data.length - visible.length;
  const maxCount = Math.max(...data.map((d) => d.count), 1);

  return (
    <div>
      <div className="space-y-0.5">
        {visible.map((row) => {
          const color = severityColors[row.severity] || "#888";
          return (
            <div key={row.module} className="flex items-center gap-2">
              <span className="text-[11px] text-charcoal-light w-[240px] shrink-0 text-right truncate" title={row.module}>
                {row.module}
              </span>
              <div className="w-[280px] shrink-0 h-[14px] bg-warm-border/20 rounded-sm overflow-hidden">
                <div
                  className="h-full rounded-sm"
                  style={{
                    width: `${Math.max((row.count / maxCount) * 100, 8)}%`,
                    backgroundColor: color,
                    opacity: 0.75,
                  }}
                />
              </div>
              <span className="text-[11px] text-text-muted w-[20px] shrink-0 text-right">{row.count}</span>
            </div>
          );
        })}
      </div>
      {remaining > 0 && (
        <div className="text-[10px] text-text-muted text-right pt-1">
          +{remaining} more
        </div>
      )}
    </div>
  );
}

export default function StatisticsTab({ data, scanDuration }: Props) {
  const { theme } = useTheme();
  const summary = computeSummary(data);
  if (scanDuration) summary.scanDuration = scanDuration;
  const severityData = findingsBySeverity(data.findings);
  const moduleData = findingsByModule(data.findings);
  const moduleDetailData = findingsByModuleWithSeverity(data.findings);
  const statusData = httpByStatusCode(data.httpRecords);
  const contentTypeData = httpByContentType(data.httpRecords);

  // Use horizontal bars when there are many items (vertical bar chart becomes unreadable)
  const useModuleTable = moduleData.length > 15;
  const useContentTypeHBars = contentTypeData.length > 15;

  return (
    <div className="space-y-10">
      <section>
        <SectionTitle>At a Glance</SectionTitle>
        <SummaryCards summary={summary} />
      </section>

      <DecorativeRule variant="ornamental" />

      <section>
        <SectionTitle>Findings Analysis</SectionTitle>
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">
          <div className="lg:col-span-3">
            <h3 className="text-sm font-sans font-semibold text-text-muted uppercase tracking-widest mb-4">
              Findings by Module
            </h3>
            {useModuleTable ? (
              <ModuleBarChart data={moduleDetailData} />
            ) : (
              <BarChartComponent
                data={moduleData.map((d) => ({ endpoint: d.module, count: d.count }))}
              />
            )}
          </div>
          <div className="lg:col-span-2">
            <h3 className="text-sm font-sans font-semibold text-text-muted uppercase tracking-widest mb-4">
              Severity Distribution
            </h3>
            <PieChartComponent
              data={severityData.map((d) => ({ status: d.severity, count: d.count }))}
              colorMap="severity"
            />
          </div>
        </div>
      </section>

      {data.httpRecords.length > 0 && (
        <>
          <DecorativeRule variant="ornamental" />
          <section>
            <SectionTitle>HTTP Traffic Overview</SectionTitle>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              <div>
                <h3 className="text-sm font-sans font-semibold text-text-muted uppercase tracking-widest mb-4">
                  Status Code Distribution
                </h3>
                <PieChartComponent
                  data={statusData}
                  colorMap="status"
                />
              </div>
              <div>
                <h3 className="text-sm font-sans font-semibold text-text-muted uppercase tracking-widest mb-4">
                  Content Types
                </h3>
                {useContentTypeHBars ? (
                  <HorizontalBarList
                    data={contentTypeData.map((d) => ({ label: d.type, count: d.count }))}
                    color={getColors(theme).terracotta}
                  />
                ) : (
                  <BarChartComponent
                    data={contentTypeData.map((d) => ({ endpoint: d.type, count: d.count }))}
                  />
                )}
              </div>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
