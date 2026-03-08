'use client';

import { useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { useScans, useDeleteScan, useStopScan, usePauseScan, useResumeScan, useScanLogs } from '@/api/hooks';
import { useToast } from '@/contexts/ToastContext';
import type { ScansQueryParams, Scan, ScanLog } from '@/api/types';
import { formatDate } from '@/lib/formatters';

const HISTORY_PAGE_SIZE = 20;

function StatusBadge({ status }: { status: string }) {
  const color =
    status === 'running' ? '#98bc37' :
    status === 'paused' ? '#f2c55c' :
    status === 'completed' ? '#7fd962' :
    status === 'failed' ? '#ef2f27' :
    '#918175';
  return (
    <span className="text-xs font-bold uppercase" style={{ color }}>
      {status}
    </span>
  );
}

function ScanDetailPanel({ scan, onClose }: { scan: Scan; onClose: () => void }) {
  const { data } = useScanLogs(scan.uuid, { limit: 200 }, scan.status === 'running');
  const logs = data?.logs ?? [];

  const levelColor = (level: string) => {
    if (level === 'warn') return '#f2c55c';
    if (level === 'error') return '#ef2f27';
    return '#918175';
  };

  return (
    <div className="border-l border-[#2e2b26] flex flex-col h-full min-h-0">
      {/* Header */}
      <div className="px-3 py-1.5 border-b border-[#2e2b26] flex items-center justify-between shrink-0">
        <span className="text-[#7fd962] text-xs font-bold">SCAN DETAILS</span>
        <button onClick={onClose} className="text-[10px] text-[#918175] hover:text-[#fce8c3]">[close]</button>
      </div>

      {/* Scan metadata */}
      <div className="px-3 py-2 text-xs border-b border-[#2e2b26] shrink-0 space-y-1">
        <div className="text-[#fce8c3] break-all">
          <span className="text-[#918175]">uuid:</span> {scan.uuid}
        </div>
        <div className="flex flex-wrap gap-x-4 gap-y-0.5">
          <span><span className="text-[#918175]">status:</span> <span className="text-[#fce8c3]">{scan.status}</span></span>
          <span><span className="text-[#918175]">name:</span> <span className="text-[#fce8c3]">{scan.name || '-'}</span></span>
          <span><span className="text-[#918175]">mode:</span> <span className="text-[#fce8c3]">{scan.scan_mode || '-'}</span></span>
          <span><span className="text-[#918175]">source:</span> <span className="text-[#fce8c3]">{scan.scan_source || '-'}</span></span>
          <span><span className="text-[#918175]">findings:</span> <span className="text-[#fce8c3]">{scan.total_findings}</span></span>
          <span><span className="text-[#918175]">processed:</span> <span className="text-[#fce8c3]">{scan.processed_count}</span></span>
        </div>
        <div className="flex flex-wrap gap-x-4 gap-y-0.5">
          <span><span className="text-[#918175]">started:</span> <span className="text-[#fce8c3]">{scan.started_at ? formatDate(scan.started_at) : '-'}</span></span>
          <span><span className="text-[#918175]">finished:</span> <span className="text-[#fce8c3]">{scan.finished_at ? formatDate(scan.finished_at) : '-'}</span></span>
          <span><span className="text-[#918175]">created:</span> <span className="text-[#fce8c3]">{scan.created_at ? formatDate(scan.created_at) : '-'}</span></span>
        </div>
        {scan.modules && (
          <div className="break-all">
            <span className="text-[#918175]">modules:</span> <span className="text-[#fce8c3]">{scan.modules}</span>
          </div>
        )}
      </div>

      {/* Logs header */}
      <div className="px-3 py-1.5 border-b border-[#2e2b26] shrink-0">
        <span className="text-[#7fd962] text-xs font-bold">LOGS</span>
        <span className="text-[#403d38] text-[10px] ml-2">{logs.length} entries</span>
      </div>

      {/* Logs */}
      <div className="bg-[#141310] overflow-y-auto font-mono text-[11px] leading-relaxed flex-1 min-h-0">
        {logs.length === 0 ? (
          <div className="px-3 py-2 text-[#403d38]">no logs</div>
        ) : (
          logs.map((log: ScanLog) => (
            <div key={log.id} className="px-3 py-0.5 hover:bg-[#1c1b19] flex gap-2">
              <span className="text-[#403d38] shrink-0">{new Date(log.created_at).toLocaleTimeString()}</span>
              <span className="shrink-0 uppercase font-bold" style={{ color: levelColor(log.level) }}>{log.level.padEnd(5)}</span>
              {log.phase && <span className="text-[#98bc37] shrink-0">[{log.phase}]</span>}
              <span className="text-[#fce8c3]">{log.message}</span>
              {log.metadata && <span className="text-[#403d38]">{log.metadata}</span>}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function ScanActions({ scan, onStop, onDelete, onPause, onResume }: { scan: Scan; onStop: (uuid: string) => void; onDelete: (uuid: string) => void; onPause: (uuid: string) => void; onResume: (uuid: string) => void }) {
  const [confirmDel, setConfirmDel] = useState(false);

  return (
    <div className="flex items-center gap-1">
      {scan.status === 'running' && (
        <>
          <button
            onClick={(e) => { e.stopPropagation(); onPause(scan.uuid); }}
            className="text-[10px] text-[#f2c55c] hover:underline"
          >
            [pause]
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); onStop(scan.uuid); }}
            className="text-[10px] text-[#ef2f27] hover:underline"
          >
            [stop]
          </button>
        </>
      )}
      {scan.status === 'paused' && (
        <>
          <button
            onClick={(e) => { e.stopPropagation(); onResume(scan.uuid); }}
            className="text-[10px] text-[#98bc37] hover:underline"
          >
            [resume]
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); onStop(scan.uuid); }}
            className="text-[10px] text-[#ef2f27] hover:underline"
          >
            [stop]
          </button>
        </>
      )}
      {!confirmDel ? (
        <button
          onClick={(e) => { e.stopPropagation(); setConfirmDel(true); }}
          className="text-[10px] text-[#918175] hover:text-[#ef2f27]"
        >
          [del]
        </button>
      ) : (
        <span className="flex items-center gap-1">
          <button
            onClick={(e) => { e.stopPropagation(); onDelete(scan.uuid); setConfirmDel(false); }}
            className="text-[10px] text-[#ef2f27] hover:underline"
          >
            [confirm]
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); setConfirmDel(false); }}
            className="text-[10px] text-[#918175] hover:underline"
          >
            [cancel]
          </button>
        </span>
      )}
    </div>
  );
}

export default function ScanHistoryTable() {
  const [historyParams, setHistoryParams] = useState<ScansQueryParams>({ limit: HISTORY_PAGE_SIZE, offset: 0 });
  const [expandedScanUuid, setExpandedScanUuid] = useState<string | null>(null);

  const { data: scansData, isLoading: scansLoading, refetch, isFetching } = useScans(historyParams);
  const deleteScan = useDeleteScan();
  const stopScan = useStopScan();
  const pauseScan = usePauseScan();
  const resumeScan = useResumeScan();
  const { toast } = useToast();

  const selectedScan = expandedScanUuid ? scansData?.data?.find((s) => s.uuid === expandedScanUuid) ?? null : null;
  const historyPage = Math.floor((historyParams.offset || 0) / HISTORY_PAGE_SIZE) + 1;
  const historyTotalPages = Math.ceil((scansData?.total || 0) / HISTORY_PAGE_SIZE);

  return (
    <div className="border border-[#2e2b26] bg-[#1c1b19] overflow-hidden">
      <div className="px-3 py-1.5 border-b border-[#2e2b26]">
        <div className="flex items-center gap-1.5">
          <span className="text-[#7fd962] text-xs font-bold">SCAN HISTORY</span>
          <button onClick={() => refetch()} className="text-[#918175] hover:text-[#7fd962] transition-colors" title="Refresh">
            <RefreshCw className={`w-3 h-3 ${isFetching ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      <div className="flex" style={{ minHeight: selectedScan ? 420 : undefined }}>
        {/* Table */}
        <div className={`overflow-x-auto ${selectedScan ? 'w-1/2' : 'w-full'}`}>
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[#2e2b26]">
                <th className="text-left px-3 py-1.5 text-[#918175] text-[10px] uppercase font-normal">STATUS</th>
                <th className="text-left px-3 py-1.5 text-[#918175] text-[10px] uppercase font-normal">NAME</th>
                <th className="text-left px-3 py-1.5 text-[#918175] text-[10px] uppercase font-normal">MODE / SOURCE</th>
                <th className="text-right px-3 py-1.5 text-[#918175] text-[10px] uppercase font-normal">FINDINGS</th>
                <th className="text-right px-3 py-1.5 text-[#918175] text-[10px] uppercase font-normal">PROCESSED</th>
                <th className="text-left px-3 py-1.5 text-[#918175] text-[10px] uppercase font-normal">STARTED</th>
                <th className="text-left px-3 py-1.5 text-[#918175] text-[10px] uppercase font-normal">ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {scansLoading && (
                <tr>
                  <td colSpan={7} className="px-3 py-4 text-center text-[#918175]">loading...</td>
                </tr>
              )}
              {!scansLoading && (!scansData?.data || scansData.data.length === 0) && (
                <tr>
                  <td colSpan={7} className="px-3 py-4 text-center text-[#403d38]">no scans</td>
                </tr>
              )}
              {scansData?.data?.map((scan) => (
                <tr
                  key={scan.uuid}
                  onClick={() => setExpandedScanUuid((prev) => prev === scan.uuid ? null : scan.uuid)}
                  className={`border-b border-[#2e2b26]/50 hover:bg-[#272520] transition-colors cursor-pointer ${expandedScanUuid === scan.uuid ? 'bg-[#272520]' : ''}`}
                >
                  <td className="px-3 py-1.5"><StatusBadge status={scan.status} /></td>
                  <td className="px-3 py-1.5 text-[#fce8c3]">{scan.name || scan.uuid.slice(0, 8)}</td>
                  <td className="px-3 py-1.5 text-[#918175]">{[scan.scan_mode, scan.scan_source].filter(Boolean).join(' / ') || '-'}</td>
                  <td className="px-3 py-1.5 text-right text-[#fce8c3]">{scan.total_findings}</td>
                  <td className="px-3 py-1.5 text-right text-[#fce8c3]">{scan.processed_count}</td>
                  <td className="px-3 py-1.5 text-[#918175]">{formatDate(scan.started_at)}</td>
                  <td className="px-3 py-1.5">
                    <ScanActions
                      scan={scan}
                      onStop={(uuid) => stopScan.mutate(uuid, { onError: (err) => toast((err as Error).message, 'error') })}
                      onDelete={(uuid) => deleteScan.mutate(uuid, { onError: (err) => toast((err as Error).message, 'error') })}
                      onPause={(uuid) => pauseScan.mutate(uuid, { onError: (err) => toast((err as Error).message, 'error') })}
                      onResume={(uuid) => resumeScan.mutate(uuid, { onError: (err) => toast((err as Error).message, 'error') })}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Detail panel on the right */}
        {selectedScan && (
          <div className="w-1/2">
            <ScanDetailPanel scan={selectedScan} onClose={() => setExpandedScanUuid(null)} />
          </div>
        )}
      </div>

      {(scansData?.total || 0) > HISTORY_PAGE_SIZE && (
        <div className="flex items-center justify-between px-3 py-1 border-t border-[#2e2b26] text-xs text-[#918175]">
          <span>
            {(historyParams.offset || 0) + 1}-{Math.min((historyParams.offset || 0) + HISTORY_PAGE_SIZE, scansData?.total || 0)}/{scansData?.total || 0}
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setHistoryParams((p) => ({ ...p, offset: ((p.offset || 0) - HISTORY_PAGE_SIZE) }))}
              disabled={historyPage <= 1}
              className="hover:text-[#7fd962] disabled:opacity-30 px-1"
            >
              {'<'}
            </button>
            <span className="px-1">{historyPage}/{historyTotalPages}</span>
            <button
              onClick={() => setHistoryParams((p) => ({ ...p, offset: ((p.offset || 0) + HISTORY_PAGE_SIZE) }))}
              disabled={historyPage >= historyTotalPages}
              className="hover:text-[#7fd962] disabled:opacity-30 px-1"
            >
              {'>'}
            </button>
          </div>
        </div>
      )}

      {(deleteScan.isError || stopScan.isError || pauseScan.isError || resumeScan.isError) && (
        <div className="px-3 py-1 text-xs text-[#ef2f27]">
          error: {((deleteScan.error || stopScan.error || pauseScan.error || resumeScan.error) as Error)?.message}
        </div>
      )}
    </div>
  );
}
