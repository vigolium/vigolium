'use client';

import { useStats, useScanStatus, useCancelScan, useServerInfo, useFindings, useHttpRecords, useScans, useOASTInteractions } from '@/api/hooks';
import PageShell from './PageShell';
import SummaryCards from './SummaryCards';
import SeverityChart from './SeverityChart';
import ScanStatus from './ScanStatus';
import ServerInfo from './ServerInfo';
import ScanHistoryTable from './ScanHistoryTable';
import FindingsChart from './FindingsChart';
import HttpRecordsChart from './HttpRecordsChart';

export default function DashboardPage() {
  const { data: stats } = useStats();
  const { data: serverInfo } = useServerInfo();
  const { data: scanStatus } = useScanStatus();
  const cancelScan = useCancelScan();
  const { data: findingsData } = useFindings({ limit: 500 });
  const { data: recordsData } = useHttpRecords({ limit: 500 });
  const { data: scansData } = useScans({ limit: 100 });
  const { data: oastData } = useOASTInteractions({ limit: 1 });

  return (
    <PageShell>
      {/* Row 1: Summary stats bar (full width) */}
      <div className="v-card-enter v-stagger-1">
        <SummaryCards stats={stats} serverInfo={serverInfo} />
      </div>

      {/* Row 2: SeverityChart + ScanStatus + ServerInfo (3 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-2">
        <div className="v-card-enter v-stagger-2 h-full">
          <SeverityChart stats={stats} />
        </div>
        <div className="v-card-enter v-stagger-3 h-full">
          <ScanStatus
            scanStatus={scanStatus}
            stats={stats}
            onCancel={() => cancelScan.mutate()}
            isCancelPending={cancelScan.isPending}
            scansData={scansData?.data}
            oastTotal={oastData?.total}
          />
        </div>
        <div className="v-card-enter v-stagger-4 h-full">
          <ServerInfo serverInfo={serverInfo} />
        </div>
      </div>

      {/* Row 3: FindingsChart + HttpRecordsChart (2 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
        <div className="v-card-enter v-stagger-5 h-full">
          <FindingsChart findings={findingsData?.data} />
        </div>
        <div className="v-card-enter v-stagger-5 h-full">
          <HttpRecordsChart records={recordsData?.data} />
        </div>
      </div>

      {/* Row 4: ScanHistoryTable (full width) */}
      <div className="v-card-enter v-stagger-6">
        <ScanHistoryTable />
      </div>
    </PageShell>
  );
}
