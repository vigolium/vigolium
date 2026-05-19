import { useMemo } from 'react';
import type { ScanStatusResponse, StatsResponse, Scan } from '@/api/types';
import Link from '@/components/shared/DemoAwareLink';

interface Props {
  scanStatus?: ScanStatusResponse;
  stats?: StatsResponse;
  onCancel: () => void;
  isCancelPending: boolean;
  scansData?: Scan[];
  oastTotal?: number;
}

export default function ScanStatus({
  scanStatus,
  stats,
  onCancel,
  isCancelPending,
  scansData,
  oastTotal,
}: Props) {
  const running = scanStatus?.running ?? false;
  const active = stats?.modules?.active;
  const passive = stats?.modules?.passive;
  const loading = !stats && !scanStatus;

  const scanCounts = useMemo(() => {
    if (!scansData) return null;
    const counts: Record<string, number> = {};
    for (const s of scansData) {
      counts[s.status] = (counts[s.status] || 0) + 1;
    }
    return counts;
  }, [scansData]);

  if (loading) {
    return (
      <div className="border border-[#bbc3c4] bg-[#f6edda] p-3 h-full">
        <div className="text-[#0078c8] text-xs font-bold mb-2">SCAN CONTROL</div>
        <div className="space-y-1.5">
          <div className="grid grid-cols-2 gap-x-4 gap-y-1">
            <span className="v-skeleton h-3 w-32" />
            <span className="v-skeleton h-3 w-32" />
          </div>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1">
            <span className="v-skeleton h-3 w-40" />
            <span className="v-skeleton h-3 w-20" />
          </div>
          <div className="flex items-center gap-2 pt-1">
            <span className="v-skeleton h-5 w-28" />
            <span className="v-skeleton h-5 w-32" />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="border border-[#bbc3c4] bg-[#f6edda] p-3 v-fade-in h-full">
      <div className="text-[#0078c8] text-xs font-bold mb-2">SCAN CONTROL</div>
      <div className="text-xs space-y-2">
        {running && (
          <>
            <div className="flex items-center gap-2">
              <span className="text-[#708e8e]">STATUS:</span>
              <span className="text-[#00b368]">SCANNING...</span>
            </div>
            {scanStatus?.message && (
              <div className="text-[#708e8e] text-[11px] truncate">{scanStatus.message}</div>
            )}
            {scanStatus?.scan_uuid && (
              <div className="flex items-center gap-2">
                <span className="text-[#708e8e]">SCAN_ID:</span>
                <span className="text-[#004d57] truncate">{scanStatus.scan_uuid}</span>
              </div>
            )}
          </>
        )}

        {/* Module stats */}
        {stats && (
          <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-[#708e8e]">
            {active && (
              <div>Active Modules: <span className="text-[#005661]">{active.enabled}/{active.total}</span></div>
            )}
            {passive && (
              <div>Passive Modules: <span className="text-[#005661]">{passive.enabled}/{passive.total}</span></div>
            )}
          </div>
        )}

        {/* Scan & OAST stats */}
        {(scanCounts || oastTotal !== undefined) && (
          <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-[#708e8e]">
            {scanCounts && (
              <div>Scans: running: <span className="text-[#00b368]">{scanCounts['running'] || 0}</span> completed: <span className="text-[#005661]">{scanCounts['completed'] || 0}</span> failed: <span className="text-[#e34e1c]">{scanCounts['failed'] || 0}</span></div>
            )}
            {oastTotal !== undefined && (
              <div>OAST: <span className="text-[#005661]">{oastTotal}</span></div>
            )}
          </div>
        )}

        <div className="flex items-center gap-2 pt-1">
          {running ? (
            <button
              onClick={onCancel}
              disabled={isCancelPending}
              className="border border-[#e34e1c] text-[#e34e1c] hover:bg-[#e34e1c]/10 px-2 py-0.5 text-xs transition-colors disabled:opacity-40"
            >
              {isCancelPending ? '[...]' : '[CANCEL]'}
            </button>
          ) : (
            <>
              <Link
                href="/scan"
                className="border border-[#0078c8] text-[#0078c8] hover:bg-[#0078c8]/10 px-2 py-0.5 text-xs transition-colors"
              >
                [START NEW SCAN]
              </Link>
              <Link
                href="/ingest"
                className="border border-[#00b368] text-[#00b368] hover:bg-[#00b368]/10 px-2 py-0.5 text-xs transition-colors"
              >
                [INGEST MORE TRAFFIC]
              </Link>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
