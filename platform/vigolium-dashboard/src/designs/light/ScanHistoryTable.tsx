'use client';

import { useState, useMemo } from 'react';
import { RefreshCw, Terminal, Filter, Layers } from 'lucide-react';
import { useScans, useDeleteScan, useStopScan, usePauseScan, useResumeScan, useScanLogs, useAgentSessions } from '@/api/hooks';
import { useToast } from '@/contexts/ToastContext';
import type { ScansQueryParams, Scan, ScanLog, ScanLogsQueryParams, AgentSession, AgentSessionsQueryParams } from '@/api/types';
import { formatDuration, truncate } from '@/lib/formatters';
import { formatDate } from '@/lib/formatters';

const HISTORY_PAGE_SIZE = 5;

const LOG_LEVELS = ['all', 'trace', 'info', 'warn', 'error'] as const;
const LOG_PHASES = ['all', 'config', 'heuristics', 'harvest', 'spidering', 'discovery', 'seed', 'spa', 'sast', 'dynamic-assessment'] as const;

function StatusBadge({ status }: { status: string }) {
  const color =
    status === 'running' ? '#00b368' :
    status === 'paused' ? '#b8860b' :
    status === 'completed' ? '#0078c8' :
    status === 'failed' ? '#e34e1c' :
    '#708e8e';
  return (
    <span className="text-xs font-bold uppercase" style={{ color }}>
      {status}
    </span>
  );
}

function tryParseJson(s: string): Record<string, unknown> | null {
  try { return JSON.parse(s); } catch { return null; }
}

function ScanDetailPanel({ scan, onClose }: { scan: Scan; onClose: () => void }) {
  const [levelFilter, setLevelFilter] = useState<string>('all');
  const [phaseFilter, setPhaseFilter] = useState<string>('all');

  const logParams = useMemo<ScanLogsQueryParams>(() => {
    const p: ScanLogsQueryParams = { limit: 500 };
    if (levelFilter !== 'all') p.level = levelFilter;
    if (phaseFilter !== 'all') p.phase = phaseFilter;
    return p;
  }, [levelFilter, phaseFilter]);

  const { data } = useScanLogs(scan.uuid, logParams, scan.status === 'running');
  const logs = data?.logs ?? [];

  const levelColor = (level: string) => {
    if (level === 'trace') return '#708e8e';
    if (level === 'warn') return '#b8860b';
    if (level === 'error') return '#e34e1c';
    return '#0078c8';
  };

  const configLog = logs.find(l => l.phase === 'config' && l.metadata);
  const configData = configLog?.metadata ? tryParseJson(configLog.metadata) : null;

  return (
    <div className="border-l border-[#bbc3c4] flex flex-col h-full min-h-0">
      {/* Header */}
      <div className="px-3 py-1.5 border-b border-[#bbc3c4] flex items-center justify-between shrink-0">
        <span className="text-[#0078c8] text-xs font-bold">SCAN DETAILS</span>
        <button onClick={onClose} className="text-[10px] text-[#708e8e] hover:text-[#005661]">[close]</button>
      </div>

      {/* Scan metadata */}
      <div className="px-3 py-2 text-xs border-b border-[#bbc3c4] shrink-0 space-y-1">
        <div className="text-[#005661] break-all">
          <span className="text-[#708e8e]">uuid:</span> {scan.uuid}
        </div>
        <div className="flex flex-wrap gap-x-4 gap-y-0.5">
          <span><span className="text-[#708e8e]">status:</span> <span className="text-[#005661]">{scan.status}</span></span>
          <span><span className="text-[#708e8e]">name:</span> <span className="text-[#005661]">{scan.name || '-'}</span></span>
          <span><span className="text-[#708e8e]">mode:</span> <span className="text-[#005661]">{scan.scan_mode || '-'}</span></span>
          <span><span className="text-[#708e8e]">source:</span> <span className="text-[#005661]">{scan.scan_source || '-'}</span></span>
          <span><span className="text-[#708e8e]">findings:</span> <span className="text-[#005661]">{scan.total_findings}</span></span>
          <span><span className="text-[#708e8e]">processed:</span> <span className="text-[#005661]">{scan.processed_count}</span></span>
        </div>
        <div className="flex flex-wrap gap-x-4 gap-y-0.5">
          <span><span className="text-[#708e8e]">started:</span> <span className="text-[#005661]">{scan.started_at ? formatDate(scan.started_at) : '-'}</span></span>
          <span><span className="text-[#708e8e]">finished:</span> <span className="text-[#005661]">{scan.finished_at ? formatDate(scan.finished_at) : '-'}</span></span>
          <span><span className="text-[#708e8e]">created:</span> <span className="text-[#005661]">{scan.created_at ? formatDate(scan.created_at) : '-'}</span></span>
        </div>
        {scan.modules && (
          <div className="break-all">
            <span className="text-[#708e8e]">modules:</span> <span className="text-[#005661]">{scan.modules}</span>
          </div>
        )}
      </div>

      {/* Config snapshot (collapsible) */}
      {configData && (
        <details className="border-b border-[#bbc3c4] shrink-0">
          <summary className="px-3 py-1.5 cursor-pointer text-[#0078c8] text-xs font-bold hover:bg-[#ede4d1] flex items-center gap-1.5">
            <Filter className="w-3 h-3" />CONFIG SNAPSHOT
          </summary>
          <div className="px-3 py-2 bg-[#eee8d5] text-xs font-mono grid grid-cols-2 gap-x-4 gap-y-0.5">
            {Object.entries(configData).map(([k, v]) => (
              <div key={k}>
                <span className="text-[#708e8e]">{k}: </span>
                <span className="text-[#005661]">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
              </div>
            ))}
          </div>
        </details>
      )}

      {/* Logs header + filters */}
      <div className="px-3 py-1.5 border-b border-[#bbc3c4] shrink-0 space-y-1">
        <div className="flex items-center justify-between">
          <span className="text-[#0078c8] text-xs font-bold flex items-center gap-1.5">
            <Terminal className="w-3 h-3" />LOGS
            <span className="text-[#bbc3c4] font-normal text-[10px] ml-0.5">{data?.total ?? logs.length} entries</span>
          </span>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[#708e8e] text-[10px]">level:</span>
          <div className="flex gap-0.5">
            {LOG_LEVELS.map(l => (
              <button
                key={l}
                onClick={() => setLevelFilter(l)}
                className={`px-1.5 py-0 text-[10px] border transition-colors ${
                  levelFilter === l
                    ? 'border-[#0078c8] text-[#0078c8] bg-[#0078c8]/10'
                    : 'border-[#bbc3c4] text-[#708e8e] hover:border-[#708e8e]'
                }`}
              >
                {l}
              </button>
            ))}
          </div>
          <span className="text-[#708e8e] text-[10px] ml-1">phase:</span>
          <div className="flex gap-0.5 flex-wrap">
            {LOG_PHASES.map(p => (
              <button
                key={p}
                onClick={() => setPhaseFilter(p)}
                className={`px-1.5 py-0 text-[10px] border transition-colors ${
                  phaseFilter === p
                    ? 'border-[#00b368] text-[#00b368] bg-[#00b368]/10'
                    : 'border-[#bbc3c4] text-[#708e8e] hover:border-[#708e8e]'
                }`}
              >
                {p}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Logs */}
      <div className="bg-[#eee8d5] overflow-y-auto font-mono text-[11px] leading-relaxed flex-1 min-h-0">
        {logs.length === 0 ? (
          <div className="px-3 py-2 text-[#bbc3c4]">no logs</div>
        ) : levelFilter === 'trace' ? (
          /* Terminal-style rendering for trace logs */
          logs.map((log: ScanLog) => (
            <div key={log.id} className="px-3 py-0 hover:bg-[#f6edda] text-[#005661] whitespace-pre-wrap">
              {log.message}
            </div>
          ))
        ) : (
          logs.map((log: ScanLog) => (
            <div key={log.id} className="px-3 py-0.5 hover:bg-[#f6edda] flex gap-2">
              <span className="text-[#bbc3c4] shrink-0">{new Date(log.created_at).toLocaleTimeString()}</span>
              <span className="shrink-0 uppercase font-bold w-[3.5ch]" style={{ color: levelColor(log.level) }}>{log.level}</span>
              {log.phase && <span className="text-[#00b368] shrink-0">[{log.phase}]</span>}
              <span className="text-[#005661] break-all">{log.message}</span>
              {log.metadata && log.phase !== 'config' && <span className="text-[#bbc3c4] break-all">{log.metadata}</span>}
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
            className="text-[10px] text-[#b8860b] hover:underline"
          >
            [pause]
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); onStop(scan.uuid); }}
            className="text-[10px] text-[#e34e1c] hover:underline"
          >
            [stop]
          </button>
        </>
      )}
      {scan.status === 'paused' && (
        <>
          <button
            onClick={(e) => { e.stopPropagation(); onResume(scan.uuid); }}
            className="text-[10px] text-[#00b368] hover:underline"
          >
            [resume]
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); onStop(scan.uuid); }}
            className="text-[10px] text-[#e34e1c] hover:underline"
          >
            [stop]
          </button>
        </>
      )}
      {!confirmDel ? (
        <button
          onClick={(e) => { e.stopPropagation(); setConfirmDel(true); }}
          className="text-[10px] text-[#708e8e] hover:text-[#e34e1c]"
        >
          [del]
        </button>
      ) : (
        <span className="flex items-center gap-1">
          <button
            onClick={(e) => { e.stopPropagation(); onDelete(scan.uuid); setConfirmDel(false); }}
            className="text-[10px] text-[#e34e1c] hover:underline"
          >
            [confirm]
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); setConfirmDel(false); }}
            className="text-[10px] text-[#708e8e] hover:underline"
          >
            [cancel]
          </button>
        </span>
      )}
    </div>
  );
}

function SessionStatusBadge({ status }: { status: string }) {
  const color = status === 'completed' ? '#00b368' : status === 'error' ? '#e34e1c' : status === 'running' ? '#0078c8' : '#708e8e';
  return <span className="text-xs font-bold" style={{ color }}>{status}</span>;
}

export default function ScanHistoryTable() {
  const [historyParams, setHistoryParams] = useState<ScansQueryParams>({ limit: HISTORY_PAGE_SIZE, offset: 0 });
  const [sessionsParams, setSessionsParams] = useState<AgentSessionsQueryParams>({ limit: HISTORY_PAGE_SIZE, offset: 0 });

  const { data: scansData, isLoading: scansLoading, refetch, isFetching } = useScans(historyParams);
  const { data: sessionsData } = useAgentSessions(sessionsParams);
  const deleteScan = useDeleteScan();
  const stopScan = useStopScan();
  const pauseScan = usePauseScan();
  const resumeScan = useResumeScan();
  const { toast } = useToast();

  const historyPage = Math.floor((historyParams.offset || 0) / HISTORY_PAGE_SIZE) + 1;
  const historyTotalPages = Math.ceil((scansData?.total || 0) / HISTORY_PAGE_SIZE);

  const sessionsPage = Math.floor((sessionsParams.offset || 0) / HISTORY_PAGE_SIZE) + 1;
  const sessionsTotalPages = Math.ceil((sessionsData?.total || 0) / HISTORY_PAGE_SIZE);

  return (
    <div className="space-y-2">
      {/* Scan History */}
      <div className="border border-[#bbc3c4] bg-[#f6edda] overflow-hidden">
        <div className="px-3 py-1.5 border-b border-[#bbc3c4]">
          <div className="flex items-center gap-1.5">
            <span className="text-[#0078c8] text-xs font-bold">SCAN HISTORY</span>
            <button onClick={() => refetch()} className="text-[#708e8e] hover:text-[#0078c8] transition-colors" title="Refresh">
              <RefreshCw className={`w-3 h-3 ${isFetching ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[#bbc3c4]">
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">STATUS</th>
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">NAME</th>
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">MODE / SOURCE</th>
                <th className="text-right px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">FINDINGS</th>
                <th className="text-right px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">PROCESSED</th>
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">STARTED</th>
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {scansLoading && (
                <tr>
                  <td colSpan={7} className="px-3 py-4 text-center text-[#708e8e]">loading...</td>
                </tr>
              )}
              {!scansLoading && (!scansData?.data || scansData.data.length === 0) && (
                <tr>
                  <td colSpan={7} className="px-3 py-4 text-center text-[#bbc3c4]">no scans</td>
                </tr>
              )}
              {scansData?.data?.map((scan) => (
                <tr
                  key={scan.uuid}
                  className="border-b border-[#bbc3c4]/50 hover:bg-[#ede4d1] transition-colors"
                >
                  <td className="px-3 py-1.5"><StatusBadge status={scan.status} /></td>
                  <td className="px-3 py-1.5 text-[#005661]">{scan.name || scan.uuid.slice(0, 8)}</td>
                  <td className="px-3 py-1.5 text-[#708e8e]">{[scan.scan_mode, scan.scan_source].filter(Boolean).join(' / ') || '-'}</td>
                  <td className="px-3 py-1.5 text-right text-[#005661]">{scan.total_findings}</td>
                  <td className="px-3 py-1.5 text-right text-[#005661]">{scan.processed_count}</td>
                  <td className="px-3 py-1.5 text-[#708e8e]">{formatDate(scan.started_at)}</td>
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

        {(scansData?.total || 0) > HISTORY_PAGE_SIZE && (
          <div className="flex items-center justify-between px-3 py-1 border-t border-[#bbc3c4] text-xs text-[#708e8e]">
            <span>
              {(historyParams.offset || 0) + 1}-{Math.min((historyParams.offset || 0) + HISTORY_PAGE_SIZE, scansData?.total || 0)}/{scansData?.total || 0}
            </span>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setHistoryParams((p) => ({ ...p, offset: ((p.offset || 0) - HISTORY_PAGE_SIZE) }))}
                disabled={historyPage <= 1}
                className="hover:text-[#0078c8] disabled:opacity-30 px-1"
              >
                {'<'}
              </button>
              <span className="px-1">{historyPage}/{historyTotalPages}</span>
              <button
                onClick={() => setHistoryParams((p) => ({ ...p, offset: ((p.offset || 0) + HISTORY_PAGE_SIZE) }))}
                disabled={historyPage >= historyTotalPages}
                className="hover:text-[#0078c8] disabled:opacity-30 px-1"
              >
                {'>'}
              </button>
            </div>
          </div>
        )}

        {(deleteScan.isError || stopScan.isError || pauseScan.isError || resumeScan.isError) && (
          <div className="px-3 py-1 text-xs text-[#e34e1c]">
            error: {((deleteScan.error || stopScan.error || pauseScan.error || resumeScan.error) as Error)?.message}
          </div>
        )}
      </div>

      {/* Agent Sessions */}
      <div className="border border-[#bbc3c4] bg-[#f6edda] overflow-hidden">
        <div className="px-3 py-1.5 border-b border-[#bbc3c4]">
          <span className="text-[#0078c8] text-xs font-bold inline-flex items-center gap-1.5">
            <Layers className="w-3 h-3" />AGENT SESSIONS
            {sessionsData?.total != null && <span className="text-[#708e8e] font-normal ml-1">({sessionsData.total})</span>}
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[#bbc3c4]">
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">STATUS</th>
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">UUID</th>
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">MODE</th>
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">AGENT</th>
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">TARGET</th>
                <th className="text-right px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">FINDINGS</th>
                <th className="text-right px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">SAVED</th>
                <th className="text-right px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">DURATION</th>
                <th className="text-left px-3 py-1.5 text-[#708e8e] text-[10px] uppercase font-normal">COMPLETED</th>
              </tr>
            </thead>
            <tbody>
              {sessionsData?.data && sessionsData.data.length > 0 ? (
                sessionsData.data.map((s: AgentSession) => (
                  <tr key={s.uuid} className="border-b border-[#bbc3c4]/50 hover:bg-[#ede4d1] transition-colors">
                    <td className="px-3 py-1.5"><SessionStatusBadge status={s.status} /></td>
                    <td className="px-3 py-1.5 text-[#0078c8] font-mono">{s.uuid.slice(0, 8)}</td>
                    <td className="px-3 py-1.5 text-[#708e8e]">{s.mode}</td>
                    <td className="px-3 py-1.5 text-[#005661]">{s.agent_name || '—'}</td>
                    <td className="px-3 py-1.5 text-[#005661]">{s.target_url ? truncate(s.target_url, 40) : '—'}</td>
                    <td className="px-3 py-1.5 text-right text-[#005661]">{s.finding_count}</td>
                    <td className="px-3 py-1.5 text-right text-[#00b368]">{s.saved_count}</td>
                    <td className="px-3 py-1.5 text-right text-[#005661]">{formatDuration(s.duration_ms)}</td>
                    <td className="px-3 py-1.5 text-[#708e8e]">{s.completed_at ? formatDate(s.completed_at) : '—'}</td>
                  </tr>
                ))
              ) : (
                <tr><td colSpan={9} className="px-3 py-4 text-center text-[#bbc3c4]">no sessions</td></tr>
              )}
            </tbody>
          </table>
        </div>

        {(sessionsData?.total || 0) > HISTORY_PAGE_SIZE && (
          <div className="flex items-center justify-between px-3 py-1 border-t border-[#bbc3c4] text-xs text-[#708e8e]">
            <span>
              {(sessionsParams.offset || 0) + 1}-{Math.min((sessionsParams.offset || 0) + HISTORY_PAGE_SIZE, sessionsData?.total || 0)}/{sessionsData?.total || 0}
            </span>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setSessionsParams((p) => ({ ...p, offset: ((p.offset || 0) - HISTORY_PAGE_SIZE) }))}
                disabled={sessionsPage <= 1}
                className="hover:text-[#0078c8] disabled:opacity-30 px-1"
              >
                {'<'}
              </button>
              <span className="px-1">{sessionsPage}/{sessionsTotalPages}</span>
              <button
                onClick={() => setSessionsParams((p) => ({ ...p, offset: ((p.offset || 0) + HISTORY_PAGE_SIZE) }))}
                disabled={sessionsPage >= sessionsTotalPages}
                className="hover:text-[#0078c8] disabled:opacity-30 px-1"
              >
                {'>'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
