import { useMemo } from 'react';
import type { ScanStatusResponse, StatsResponse, Scan } from '@/api/types';
import Link from '@/components/shared/DemoAwareLink';

interface Props {
  scanStatus?: ScanStatusResponse;
  stats?: StatsResponse;
  onTrigger: () => void;
  onCancel: () => void;
  isTriggerPending: boolean;
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

  const scanCounts = useMemo(() => {
    if (!scansData) return null;
    const counts: Record<string, number> = {};
    for (const s of scansData) {
      counts[s.status] = (counts[s.status] || 0) + 1;
    }
    return counts;
  }, [scansData]);

  return (
    <div className="border border-[#2e2b26] bg-[#1c1b19] p-3">
      <div className="text-[#7fd962] text-xs font-bold mb-2">SCAN CONTROL</div>
      <div className="text-xs space-y-2">
        {running && (
          <>
            <div className="flex items-center gap-2">
              <span className="text-[#918175]">STATUS:</span>
              <span className="text-[#98bc37]">SCANNING...</span>
            </div>
            {scanStatus?.message && (
              <div className="text-[#918175] text-[11px] truncate">{scanStatus.message}</div>
            )}
            {scanStatus?.scan_id && (
              <div className="flex items-center gap-2">
                <span className="text-[#918175]">SCAN_ID:</span>
                <span className="text-[#baa67f] truncate">{scanStatus.scan_id}</span>
              </div>
            )}
          </>
        )}

        {/* Module stats */}
        {stats && (
          <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-[#918175]">
            {active && (
              <div>Active Modules: <span className="text-[#fce8c3]">{active.enabled}/{active.total}</span></div>
            )}
            {passive && (
              <div>Passive Modules: <span className="text-[#fce8c3]">{passive.enabled}/{passive.total}</span></div>
            )}
          </div>
        )}

        {/* Scan & OAST stats */}
        {(scanCounts || oastTotal !== undefined) && (
          <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-[#918175]">
            {scanCounts && (
              <div>Scans: running: <span className="text-[#98bc37]">{scanCounts['running'] || 0}</span> completed: <span className="text-[#fce8c3]">{scanCounts['completed'] || 0}</span> failed: <span className="text-[#ef2f27]">{scanCounts['failed'] || 0}</span></div>
            )}
            {oastTotal !== undefined && (
              <div>OAST: <span className="text-[#fce8c3]">{oastTotal}</span></div>
            )}
          </div>
        )}

        <div className="flex items-center gap-2 pt-1">
          {running ? (
            <button
              onClick={onCancel}
              disabled={isCancelPending}
              className="border border-[#ef2f27] text-[#ef2f27] hover:bg-[#ef2f27]/10 px-2 py-0.5 text-xs transition-colors disabled:opacity-40"
            >
              {isCancelPending ? '[...]' : '[CANCEL]'}
            </button>
          ) : (
            <>
              <Link
                href="/scan"
                className="border border-[#98bc37] text-[#98bc37] hover:bg-[#98bc37]/10 px-2 py-0.5 text-xs transition-colors"
              >
                [START NEW SCAN]
              </Link>
              <Link
                href="/ingest"
                className="border border-[#68a8e4] text-[#68a8e4] hover:bg-[#68a8e4]/10 px-2 py-0.5 text-xs transition-colors"
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
