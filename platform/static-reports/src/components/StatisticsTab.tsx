import type { ExportData } from "../types";
import {
  computeSummary,
  findingsBySeverity,
  findingsByModule,
  httpByStatusCode,
  httpByContentType,
} from "../utils/parse";
import SummaryCards from "./SummaryCards";
import SectionTitle from "./SectionTitle";
import DecorativeRule from "./DecorativeRule";
import BarChartComponent from "./BarChart";
import PieChartComponent from "./PieChart";

interface Props {
  data: ExportData;
  scanDuration?: string;
}

export default function StatisticsTab({ data, scanDuration }: Props) {
  const summary = computeSummary(data);
  if (scanDuration) summary.scanDuration = scanDuration;
  const severityData = findingsBySeverity(data.findings);
  const moduleData = findingsByModule(data.findings);
  const statusData = httpByStatusCode(data.httpRecords);
  const contentTypeData = httpByContentType(data.httpRecords);

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
            <BarChartComponent
              data={moduleData.map((d) => ({ endpoint: d.module, count: d.count }))}
            />
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
                <BarChartComponent
                  data={contentTypeData.map((d) => ({ endpoint: d.type, count: d.count }))}
                />
              </div>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
