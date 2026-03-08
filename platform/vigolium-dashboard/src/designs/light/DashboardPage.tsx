'use client';

import { useStats, useScanStatus, useTriggerScan, useCancelScan, useServerInfo, useFindings, useHttpRecords, useScans, useOASTInteractions } from '@/api/hooks';
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
  const triggerScan = useTriggerScan();
  const cancelScan = useCancelScan();
  const { data: findingsData } = useFindings({ limit: 500 });
  const { data: recordsData } = useHttpRecords({ limit: 500 });
  const { data: scansData } = useScans({ limit: 100 });
  const { data: oastData } = useOASTInteractions({ limit: 1 });

  return (
    <PageShell>
      {/* Row 1: Summary stats bar (full width) */}
      <SummaryCards stats={stats} serverInfo={serverInfo} />

      {/* Row 2: SeverityChart + ScanStatus + ServerInfo (3 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-2">
        <SeverityChart stats={stats} />
        <ScanStatus
          scanStatus={scanStatus}
          stats={stats}
          onTrigger={() => triggerScan.mutate({})}
          onCancel={() => cancelScan.mutate()}
          isTriggerPending={triggerScan.isPending}
          isCancelPending={cancelScan.isPending}
          scansData={scansData?.data}
          oastTotal={oastData?.total}
        />
        <ServerInfo serverInfo={serverInfo} />
      </div>

      {/* Row 3: FindingsChart + HttpRecordsChart (2 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
        <FindingsChart findings={findingsData?.data} />
        <HttpRecordsChart records={recordsData?.data} />
      </div>

      {/* Row 4: ScanHistoryTable (full width) */}
      <ScanHistoryTable />
    </PageShell>
  );
}
