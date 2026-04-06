'use client';

import React, { useState, useMemo, useRef, useCallback } from 'react';
import { Copy, Check, Upload, Loader2, Zap, Scale, Layers } from 'lucide-react';
import { zipSync } from 'fflate';
import { useScanURL, useScanRequest, useRunScan, useUploadRepo, useScans, useDeleteScan, useStopScan, usePauseScan, useResumeScan, useScanLogs } from '@/api/hooks';
import type { ScanURLRequest, ScanRequestRequest, RunScanRequest, ScansQueryParams, Scan, ScanLog } from '@/api/types';
import { formatDate } from '@/lib/formatters';
import PageShell from './PageShell';
import Dropdown from './Dropdown';
import GitHubRepoPicker from './GitHubRepoPicker';

/* ─── types & constants ─── */

type ScanMode = 'full_scan' | 'url' | 'raw_request' | 'repo_scan';

const MODE_LABELS: Record<ScanMode, string> = {
  full_scan: 'FULL SCAN',
  url: 'URL SCAN',
  raw_request: 'RAW REQUEST',
  repo_scan: 'REPO SCAN',
};

const MODE_BADGE_COLORS: Record<ScanMode, string> = {
  full_scan: '#00b368',
  url: '#00b368',
  raw_request: '#0078c8',
  repo_scan: '#c49000',
};

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const;
const STRATEGIES = ['lite', 'balanced', 'deep'] as const;
const PHASES = ['', 'discovery', 'spidering', 'audit'] as const;
const SCOPE_ORIGINS = ['', 'all', 'relaxed', 'balanced', 'strict'] as const;
const HEURISTICS = ['', 'none', 'basic', 'advanced'] as const;
const HISTORY_PAGE_SIZE = 20;

interface HeaderRow { key: string; value: string; }

const STRATEGY_META: Record<string, { title: string; desc: string; Icon: typeof Zap }> = {
  lite:     { title: 'Quick',    desc: 'Fast surface-level scan for common issues',                Icon: Zap },
  balanced: { title: 'Balanced', desc: 'Thorough scan with smart defaults',                       Icon: Scale },
  deep:     { title: 'Deep',     desc: 'Exhaustive scan with full discovery and verification',     Icon: Layers },
};

/* ─── auto-detect mode from input ─── */

function detectMode(input: string): ScanMode {
  const trimmed = input.trim();
  if (!trimmed) return 'full_scan';

  const firstLine = trimmed.split('\n')[0].trim();

  // Raw HTTP request detection
  if (/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\//.test(firstLine)) {
    return 'raw_request';
  }

  const lines = trimmed.split('\n').map(l => l.trim()).filter(Boolean);

  // Single line checks
  if (lines.length === 1) {
    // GitHub / git repo URL
    if (firstLine.includes('github.com/') || firstLine.endsWith('.git')) {
      return 'repo_scan';
    }
    // Single URL — keep full_scan as default
    if (/^https?:\/\//i.test(firstLine)) {
      return 'full_scan';
    }
  }

  // Multiple lines = targets list
  return 'full_scan';
}

/* ─── StatusBadge (light) ─── */

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

/* ─── ScanDetailPanel (light) ─── */

function ScanDetailPanel({ scan, onClose }: { scan: Scan; onClose: () => void }) {
  const { data } = useScanLogs(scan.uuid, { limit: 200 }, scan.status === 'running');
  const logs = data?.logs ?? [];
  const [modulesCopied, setModulesCopied] = useState(false);

  const statusColor = (s: string) =>
    s === 'running' ? '#00b368' :
    s === 'paused' ? '#b8860b' :
    s === 'completed' ? '#0078c8' :
    s === 'failed' || s === 'cancelled' ? '#e34e1c' : '#005661';

  const levelColor = (level: string) => {
    if (level === 'warn') return '#b8860b';
    if (level === 'error') return '#e34e1c';
    return '#708e8e';
  };

  return (
    <div className="border-l border-[#bbc3c4] flex flex-col h-full min-h-0">
      <div className="px-3 py-1.5 border-b border-[#bbc3c4] flex items-center justify-between shrink-0">
        <span className="text-[#0078c8] text-xs font-bold">SCAN DETAILS</span>
        <button onClick={onClose} className="text-[10px] text-[#708e8e] hover:text-[#005661]">[close]</button>
      </div>
      <div className="px-3 py-2 text-xs border-b border-[#bbc3c4] shrink-0 space-y-1">
        <div className="text-[#005661] break-all">
          <span className="text-[#708e8e]">uuid:</span> {scan.uuid}
        </div>
        {scan.project_uuid && (
          <div className="text-[#005661] break-all">
            <span className="text-[#708e8e]">project_uuid:</span> {scan.project_uuid}
          </div>
        )}
        <div className="flex flex-wrap gap-x-4 gap-y-0.5">
          <span><span className="text-[#708e8e]">status:</span> <span className="font-bold uppercase" style={{ color: statusColor(scan.status) }}>{scan.status}</span></span>
          <span><span className="text-[#708e8e]">name:</span> <span className="text-[#005661]">{scan.name || '-'}</span></span>
          <span><span className="text-[#708e8e]">mode:</span> <span className="text-[#0078c8]">{scan.scan_mode || '-'}</span></span>
          <span><span className="text-[#708e8e]">source:</span> <span className="text-[#005661] font-semibold">{scan.scan_source || '-'}</span></span>
          <span><span className="text-[#708e8e]">findings:</span> <span style={{ color: scan.total_findings > 0 ? '#b8860b' : '#708e8e' }}>{scan.total_findings}</span></span>
          <span><span className="text-[#708e8e]">processed:</span> <span className="text-[#00b368]">{scan.processed_count}</span></span>
        </div>
        <div className="flex flex-wrap gap-x-4 gap-y-0.5">
          <span><span className="text-[#708e8e]">started:</span> <span className="text-[#005661]">{scan.started_at ? formatDate(scan.started_at) : '-'}</span></span>
          <span><span className="text-[#708e8e]">finished:</span> <span className="text-[#005661]">{scan.finished_at ? formatDate(scan.finished_at) : '-'}</span></span>
          <span><span className="text-[#708e8e]">created:</span> <span className="text-[#005661]">{scan.created_at ? formatDate(scan.created_at) : '-'}</span></span>
        </div>
        {scan.modules && (
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[#708e8e]">modules:</span>
              <span className="text-[#0078c8] text-[10px]">{scan.modules === 'all' ? 'all' : scan.modules.split(',').length + ' modules'}</span>
              <button
                onClick={() => { navigator.clipboard.writeText(scan.modules!); setModulesCopied(true); setTimeout(() => setModulesCopied(false), 1500); }}
                className="px-1.5 py-0.5 text-[10px] border border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]"
              >
                {modulesCopied ? <><Check size={10} className="inline-block mr-0.5 -mt-px" />copied!</> : <><Copy size={10} className="inline-block mr-0.5 -mt-px" />copy</>}
              </button>
            </div>
            <textarea readOnly rows={3} value={scan.modules} className="mt-0.5 w-full bg-[#f0f4f4] border border-[#bbc3c4] text-[#005661] text-xs p-1.5 resize-none focus:outline-none" />
          </div>
        )}
      </div>
      <div className="px-3 py-1.5 border-b border-[#bbc3c4] shrink-0">
        <span className="text-[#0078c8] text-xs font-bold">LOGS</span>
        <span className="text-[#bbc3c4] text-[10px] ml-2">{logs.length} entries</span>
      </div>
      <div className="bg-[#f0f4f4] overflow-y-auto font-mono text-[11px] leading-relaxed flex-1 min-h-0">
        {logs.length === 0 ? (
          <div className="px-3 py-2 text-[#bbc3c4]">no logs</div>
        ) : (
          logs.map((log: ScanLog) => (
            <div key={log.id} className="px-3 py-0.5 hover:bg-[#e8eeee] flex gap-2">
              <span className="text-[#708e8e] shrink-0">{new Date(log.created_at).toLocaleTimeString()}</span>
              <span className="shrink-0 uppercase font-bold" style={{ color: levelColor(log.level) }}>{log.level.padEnd(5)}</span>
              {log.phase && <span className="text-[#00b368] shrink-0">[{log.phase}]</span>}
              <span className="text-[#005661]">{log.message}</span>
              {log.metadata && <span className="text-[#708e8e]">{log.metadata}</span>}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

/* ─── ScanActions (light) ─── */

function ScanActions({ scan, onStop, onDelete, onPause, onResume }: { scan: Scan; onStop: (uuid: string) => void; onDelete: (uuid: string) => void; onPause: (uuid: string) => void; onResume: (uuid: string) => void }) {
  const [confirmDel, setConfirmDel] = useState(false);
  return (
    <div className="flex items-center gap-1">
      {scan.status === 'running' && (
        <>
          <button onClick={(e) => { e.stopPropagation(); onPause(scan.uuid); }} className="text-[10px] text-[#b8860b] hover:underline">[pause]</button>
          <button onClick={(e) => { e.stopPropagation(); onStop(scan.uuid); }} className="text-[10px] text-[#e34e1c] hover:underline">[stop]</button>
        </>
      )}
      {scan.status === 'paused' && (
        <>
          <button onClick={(e) => { e.stopPropagation(); onResume(scan.uuid); }} className="text-[10px] text-[#00b368] hover:underline">[resume]</button>
          <button onClick={(e) => { e.stopPropagation(); onStop(scan.uuid); }} className="text-[10px] text-[#e34e1c] hover:underline">[stop]</button>
        </>
      )}
      {!confirmDel ? (
        <button onClick={() => setConfirmDel(true)} className="text-[10px] text-[#708e8e] hover:text-[#e34e1c]">[del]</button>
      ) : (
        <span className="flex items-center gap-1">
          <button onClick={() => { onDelete(scan.uuid); setConfirmDel(false); }} className="text-[10px] text-[#e34e1c] hover:underline">[confirm]</button>
          <button onClick={() => setConfirmDel(false)} className="text-[10px] text-[#708e8e] hover:underline">[cancel]</button>
        </span>
      )}
    </div>
  );
}

/* ─── Main page ─── */

export default function ScanPage() {
  /* ── consolidated state ── */
  const [input, setInput] = useState('');
  const [modeOverride, setModeOverride] = useState<ScanMode | null>(null);
  const [strategy, setStrategy] = useState<string>('balanced');
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [overrideOpen, setOverrideOpen] = useState(false);

  // Advanced shared fields
  const [modules, setModules] = useState('');
  const [moduleTags, setModuleTags] = useState('');
  const [headers, setHeaders] = useState<HeaderRow[]>([{ key: '', value: '' }]);
  const [concurrency, setConcurrency] = useState('');
  const [timeout, setTimeout_] = useState('');
  const [maxPerHost, setMaxPerHost] = useState('');
  const [rateLimit, setRateLimit] = useState('');
  const [maxDuration, setMaxDuration] = useState('');
  const [scopeOrigin, setScopeOrigin] = useState('');
  const [heuristics, setHeuristics] = useState('');
  const [scanProfile, setScanProfile] = useState('');
  const [dryRun, setDryRun] = useState(false);
  const [noPassive, setNoPassive] = useState(false);

  // URL mode fields
  const [method, setMethod] = useState('GET');
  const [body, setBody] = useState('');

  // Repo mode fields
  const [repoPath, setRepoPath] = useState('');
  const [repoUrl, setRepoUrl] = useState('');

  // Stored records fields

  // Upload state
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [compressing, setCompressing] = useState(false);
  const dragCounter = useRef(0);

  // Scan history state
  const [historyParams, setHistoryParams] = useState<ScansQueryParams>({ limit: HISTORY_PAGE_SIZE, offset: 0 });
  const [expandedScanUuid, setExpandedScanUuid] = useState<string | null>(null);

  /* ── hooks ── */
  const scanURL = useScanURL();
  const scanRequest = useScanRequest();
  const runScan = useRunScan();
  const uploadRepo = useUploadRepo();
  const { data: scansData, isLoading: scansLoading } = useScans(historyParams);
  const deleteScan = useDeleteScan();
  const stopScan = useStopScan();
  const pauseScan = usePauseScan();
  const resumeScan = useResumeScan();

  /* ── derived ── */
  const detectedMode = useMemo(() => detectMode(input), [input]);
  const activeMode: ScanMode = modeOverride ?? detectedMode;

  const mutation =
    activeMode === 'url' ? scanURL :
    activeMode === 'raw_request' ? scanRequest :
    runScan;

  const isSubmitting = mutation.isPending;

  const selectedScan = expandedScanUuid ? scansData?.data?.find((s) => s.uuid === expandedScanUuid) ?? null : null;
  const historyPage = Math.floor((historyParams.offset || 0) / HISTORY_PAGE_SIZE) + 1;
  const historyTotalPages = Math.ceil((scansData?.total || 0) / HISTORY_PAGE_SIZE);

  /* ── header helpers ── */
  const addHeader = () => setHeaders((prev) => [...prev, { key: '', value: '' }]);
  const removeHeader = (i: number) => setHeaders((prev) => prev.filter((_, idx) => idx !== i));
  const updateHeader = (i: number, field: 'key' | 'value', val: string) =>
    setHeaders((prev) => prev.map((h, idx) => (idx === i ? { ...h, [field]: val } : h)));

  function buildHeadersObj(rows: HeaderRow[]): Record<string, string> | undefined {
    const obj: Record<string, string> = {};
    for (const h of rows) {
      if (h.key.trim()) obj[h.key.trim()] = h.value;
    }
    return Object.keys(obj).length > 0 ? obj : undefined;
  }

  /* ── file upload / drag-drop ── */
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    doUpload(file);
    e.target.value = '';
  };

  const doUpload = useCallback((file: File) => {
    uploadRepo.mutate(file, {
      onSuccess: (data) => { setRepoPath(data.source); },
    });
  }, [uploadRepo]);

  const readEntryRecursive = (entry: FileSystemEntry): Promise<{ path: string; file: File }[]> => {
    return new Promise((resolve) => {
      if (entry.isFile) {
        (entry as FileSystemFileEntry).file((f) => resolve([{ path: entry.fullPath.replace(/^\//, ''), file: f }]));
      } else {
        const reader = (entry as FileSystemDirectoryEntry).createReader();
        const results: { path: string; file: File }[] = [];
        const readBatch = () => {
          reader.readEntries(async (entries) => {
            if (entries.length === 0) { resolve(results); return; }
            for (const e of entries) {
              results.push(...await readEntryRecursive(e));
            }
            readBatch();
          });
        };
        readBatch();
      }
    });
  };

  const compressAndUpload = useCallback(async (items: DataTransferItemList) => {
    const entries: FileSystemEntry[] = [];
    for (let i = 0; i < items.length; i++) {
      const entry = items[i].webkitGetAsEntry?.();
      if (entry) entries.push(entry);
    }
    if (entries.length === 0) return;

    if (entries.length === 1 && entries[0].isFile) {
      const item = items[0];
      const file = item.getAsFile();
      if (file && /\.(zip|tar|tar\.gz|tgz)$/i.test(file.name)) {
        doUpload(file);
        return;
      }
    }

    setCompressing(true);
    try {
      const allFiles: { path: string; file: File }[] = [];
      for (const entry of entries) {
        allFiles.push(...await readEntryRecursive(entry));
      }
      if (allFiles.length === 0) { setCompressing(false); return; }

      const zipData: Record<string, Uint8Array> = {};
      for (const { path, file } of allFiles) {
        const buf = await file.arrayBuffer();
        zipData[path] = new Uint8Array(buf);
      }
      const zipped = zipSync(zipData);
      const zipFile = new File([new Uint8Array(zipped) as BlobPart], 'repo.zip', { type: 'application/zip' });
      setCompressing(false);
      doUpload(zipFile);
    } catch {
      setCompressing(false);
    }
  }, [doUpload]);

  const onDragEnter = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
    dragCounter.current++;
    setDragging(true);
  }, []);
  const onDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
    dragCounter.current--;
    if (dragCounter.current === 0) setDragging(false);
  }, []);
  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
  }, []);
  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
    dragCounter.current = 0;
    setDragging(false);
    if (uploadRepo.isPending) return;
    const items = e.dataTransfer.items;
    if (items && items.length > 0) {
      compressAndUpload(items);
    } else {
      const file = e.dataTransfer.files?.[0];
      if (file) doUpload(file);
    }
  }, [compressAndUpload, doUpload, uploadRepo.isPending]);

  /* ── submit handler ── */
  const handleSubmit = () => {
    const hdrs = buildHeadersObj(headers);

    switch (activeMode) {
      case 'url': {
        const req: ScanURLRequest = { url: input.trim() };
        if (method !== 'GET') req.method = method;
        if (body) req.body = body;
        req.headers = hdrs;
        if (modules) req.modules = modules;
        if (noPassive) req.no_passive = true;
        scanURL.mutate(req);
        break;
      }
      case 'raw_request': {
        let encoded = input;
        try { atob(input); } catch { encoded = btoa(input); }
        const req: ScanRequestRequest = { raw_request: encoded };
        if (modules) req.modules = modules;
        if (noPassive) req.no_passive = true;
        scanRequest.mutate(req);
        break;
      }
      case 'repo_scan': {
        const req: RunScanRequest = {};
        if (repoPath) req.source = repoPath;
        else if (input.trim()) req.repo_url = input.trim();
        if (repoUrl) req.repo_url = repoUrl;
        req.strategy = 'whitebox';
        if (modules) req.modules = modules.split(',').map(s => s.trim()).filter(Boolean);
        if (moduleTags) req.module_tags = moduleTags.split(',').map(s => s.trim()).filter(Boolean);
        if (dryRun) req.dry_run = true;
        if (concurrency) req.concurrency = parseInt(concurrency);
        if (timeout) req.timeout = timeout;
        if (maxPerHost) req.max_per_host = parseInt(maxPerHost);
        if (rateLimit) req.rate_limit = parseInt(rateLimit);
        if (maxDuration) req.scanning_max_duration = maxDuration;
        if (heuristics) req.heuristics_check = heuristics;
        if (scanProfile) req.scanning_profile = scanProfile;
        req.headers = hdrs;
        runScan.mutate(req);
        break;
      }
      case 'full_scan':
      default: {
        const targets = input.split('\n').map(s => s.trim()).filter(Boolean);
        const req: RunScanRequest = {};
        if (targets.length > 0) req.targets = targets;
        if (strategy) req.strategy = strategy;
        const intensityMap: Record<string, string> = { lite: 'quick', balanced: 'balanced', deep: 'deep' };
        req.intensity = intensityMap[strategy] || 'balanced';
        if (modules) req.modules = modules.split(',').map(s => s.trim()).filter(Boolean);
        if (moduleTags) req.module_tags = moduleTags.split(',').map(s => s.trim()).filter(Boolean);
        if (repoPath) req.source = repoPath;
        if (repoUrl) req.repo_url = repoUrl;
        if (dryRun) req.dry_run = true;
        if (concurrency) req.concurrency = parseInt(concurrency);
        if (timeout) req.timeout = timeout;
        if (maxPerHost) req.max_per_host = parseInt(maxPerHost);
        if (rateLimit) req.rate_limit = parseInt(rateLimit);
        if (maxDuration) req.scanning_max_duration = maxDuration;
        if (scopeOrigin) req.scope_origin = scopeOrigin;
        if (heuristics) req.heuristics_check = heuristics;
        if (scanProfile) req.scanning_profile = scanProfile;
        req.headers = hdrs;
        runScan.mutate(req);
        break;
      }
    }
  };

  const canSubmit =
    activeMode === 'url' ? !!input.trim() :
    activeMode === 'raw_request' ? !!input.trim() :
    activeMode === 'repo_scan' ? !!(input.trim() || repoPath || repoUrl) :
    true; // full_scan can run with empty targets (server defaults)

  /* ── style classes ── */
  const inputClass = "w-full bg-white border border-[#bbc3c4] text-[#005661] text-xs px-2 py-1 focus:outline-none focus:border-[#0078c8]/50";
  const textareaClass = `${inputClass} font-mono resize-y whitespace-pre-wrap break-all`;

  return (
    <PageShell>
      {/* ════════════════════════════════════════ NEW SCAN ════════════════════════════════════════ */}
      <div className="border border-[#bbc3c4] bg-white">
        <div className="px-3 py-1.5 border-b border-[#bbc3c4]">
          <span className="text-[#0078c8] text-xs font-bold">NEW SCAN</span>
        </div>

        <div className="p-4 space-y-4">
          {/* 1. Main input with detected mode badge */}
          <div>
            <div className="flex items-center gap-1.5 mb-0.5">
              <label className="text-[#708e8e] text-xs">Target</label>
              <span className="text-[10px]" style={{ color: MODE_BADGE_COLORS[detectedMode] }}>
                (type: {MODE_LABELS[detectedMode].toLowerCase()})
              </span>
              {modeOverride && modeOverride !== detectedMode && (
                <>
                  <span className="text-[10px] text-[#708e8e]">-&gt;</span>
                  <span className="text-[10px]" style={{ color: '#c49000' }}>
                    (type: {MODE_LABELS[modeOverride].toLowerCase()})
                  </span>
                  <button onClick={() => setModeOverride(null)} className="text-[10px] text-[#708e8e] hover:text-[#005661]">[auto]</button>
                </>
              )}
              <div className="relative">
                <button
                  onClick={() => setOverrideOpen(v => !v)}
                  className="text-[10px] text-[#708e8e] hover:text-[#005661] border border-[#bbc3c4] px-1.5 py-0.5"
                >
                  override {overrideOpen ? '\u25B4' : '\u25BE'}
                </button>
              {overrideOpen && (
                <div className="absolute top-full left-0 mt-0.5 bg-white border border-[#bbc3c4] shadow-sm z-10 min-w-[140px]">
                  <button
                    onClick={() => { setModeOverride(null); setOverrideOpen(false); }}
                    className={`block w-full text-left px-2 py-1 text-[10px] hover:bg-[#e8eeee] ${modeOverride === null ? 'text-[#00b368] font-bold' : 'text-[#005661]'}`}
                  >
                    AUTO DETECT
                  </button>
                  {(Object.keys(MODE_LABELS) as ScanMode[]).map(m => (
                    <button
                      key={m}
                      onClick={() => { setModeOverride(m); setOverrideOpen(false); }}
                      className={`block w-full text-left px-2 py-1 text-[10px] hover:bg-[#e8eeee] ${modeOverride === m ? 'text-[#00b368] font-bold' : 'text-[#005661]'}`}
                    >
                      {MODE_LABELS[m]}
                    </button>
                  ))}
                </div>
              )}
            </div>
            </div>
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              rows={Math.max(4, Math.min(30, input.split('\n').length + 1))}
              placeholder="Paste URL, targets, raw HTTP request, or repo URL..."
              className={`${textareaClass} text-sm`}
            />
          </div>

          {/* 3. Strategy presets (shown for full_scan) */}
          {activeMode === 'full_scan' && (
            <div className="grid grid-cols-3 gap-0">
              {STRATEGIES.map(s => {
                const meta = STRATEGY_META[s];
                const selected = strategy === s;
                const { Icon } = meta;
                return (
                  <button
                    key={s}
                    onClick={() => setStrategy(s)}
                    className={`border px-3 py-2 text-center transition-colors ${
                      selected
                        ? 'border-[#4a9aba] bg-[#4a9aba]/10'
                        : 'border-[#bbc3c4] hover:border-[#708e8e] hover:bg-[#ede4d1]/50'
                    }`}
                  >
                    <div className="flex items-center justify-center gap-1.5 mb-0.5">
                      <Icon className={`w-3 h-3 ${selected ? 'text-[#4a9aba]' : 'text-[#708e8e]'}`} />
                      <span className={`text-xs font-bold ${selected ? 'text-[#3d7a8f]' : 'text-[#005661]'}`}>{meta.title}</span>
                    </div>
                    <p className="text-[10px] text-[#708e8e] leading-tight">{meta.desc}</p>
                  </button>
                );
              })}
            </div>
          )}

          {/* 4. Scan button + toggles */}
          <div className="flex items-center gap-3">
            <button
              onClick={handleSubmit}
              disabled={!canSubmit || isSubmitting}
              className="text-xs px-6 py-2 border border-[#0078c8] text-[#0078c8] bg-[#0078c8]/10 hover:bg-[#0078c8]/20 shadow-[inset_0_0_18px_rgba(0,120,200,0.15)] hover:shadow-[inset_0_0_28px_rgba(0,120,200,0.25)] disabled:opacity-50 transition-colors font-bold"
            >
              {isSubmitting ? (
                <span className="flex items-center gap-1.5">
                  <Loader2 className="w-3 h-3 animate-spin" />
                  SCANNING...
                </span>
              ) : (
                'SCAN'
              )}
            </button>
            <button
              onClick={() => setDryRun(!dryRun)}
              className={`px-2 py-1 text-xs border transition-colors shrink-0 ${dryRun ? 'border-[#b8860b]/50 text-[#b8860b] bg-[#b8860b]/10' : 'border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]'}`}
            >
              DRY_RUN: {dryRun ? 'ON' : 'OFF'}
            </button>
            {(activeMode === 'url' || activeMode === 'raw_request') && (
              <button
                onClick={() => setNoPassive(!noPassive)}
                className={`px-2 py-1 text-xs border transition-colors shrink-0 ${noPassive ? 'border-[#e34e1c]/50 text-[#e34e1c] bg-[#e34e1c]/10' : 'border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]'}`}
              >
                NO_PASSIVE: {noPassive ? 'ON' : 'OFF'}
              </button>
            )}
            <button onClick={() => setAdvancedOpen(v => !v)} className={`px-2 py-1 text-xs border transition-colors shrink-0 ${advancedOpen ? 'border-[#e34e1c]/50 text-[#e34e1c] bg-[#e34e1c]/10' : 'border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]'}`}>ADVANCED</button>
          </div>

          {advancedOpen && (
            <div className="space-y-3 pl-4 border-l-2 border-[#bbc3c4]">
              {/* URL mode: method + body */}
              {activeMode === 'url' && (
                <>
                  <div className="flex gap-2 items-end">
                    <div className="w-28">
                      <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">METHOD</label>
                      <Dropdown value={method} onChange={setMethod} options={METHODS.map(m => ({ value: m, label: m }))} />
                    </div>
                    <div className="flex-1">
                      <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">BODY (optional)</label>
                      <input type="text" value={body} onChange={(e) => setBody(e.target.value)} placeholder='{"key": "value"}' className={inputClass} />
                    </div>
                  </div>
                </>
              )}

              {/* Source upload + repo fields (repo_scan or full_scan for SAST) */}
              {(activeMode === 'repo_scan' || activeMode === 'full_scan') && (
                <>
                  <div
                    onDragEnter={onDragEnter} onDragLeave={onDragLeave} onDragOver={onDragOver} onDrop={onDrop}
                    className={`border border-dashed p-4 text-center transition-colors ${compressing || uploadRepo.isPending ? '' : 'cursor-pointer'} ${dragging ? 'border-[#3b82f6] bg-[#3b82f6]/10' : 'border-[#bbc3c4] hover:border-[#3b82f6]/50'}`}
                    onClick={() => { if (!compressing && !uploadRepo.isPending) fileInputRef.current?.click(); }}
                  >
                    <input ref={fileInputRef} type="file" accept=".zip,.tar.gz,.tgz,.tar" onChange={handleFileUpload} className="hidden" />
                    {compressing || uploadRepo.isPending ? (
                      <>
                        <Loader2 className="w-5 h-5 mx-auto mb-1.5 text-[#3b82f6] animate-spin" />
                        <p className="text-xs text-[#005661]">{compressing ? 'Compressing folder...' : 'Uploading...'}</p>
                      </>
                    ) : (
                      <>
                        <Upload className="w-5 h-5 mx-auto mb-1.5 text-[#3b82f6]/70" />
                        <p className="text-xs text-[#005661]">
                          {dragging ? 'Drop here to upload' : 'Click or drag & drop archive or folder'}
                        </p>
                      </>
                    )}
                    <p className="text-[10px] text-[#708e8e] mt-1">.zip, .tar.gz, .tgz, .tar -- or drop a folder (auto-zipped) -- max 500 MB</p>
                    {uploadRepo.isSuccess && (
                      <p className="text-[10px] text-[#00b368] mt-1">uploaded -- source path set</p>
                    )}
                    {uploadRepo.isError && (
                      <p className="text-[10px] text-[#e34e1c] mt-1">upload failed: {(uploadRepo.error as Error).message}</p>
                    )}
                  </div>
                  {activeMode === 'repo_scan' && (
                    <div>
                      <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">GITHUB REPO</label>
                      <GitHubRepoPicker onSelect={(url) => { setRepoUrl(url); setRepoPath(''); }} selectedRepo={repoUrl.includes('x-access-token') ? repoUrl.replace(/https:\/\/x-access-token:[^@]+@github\.com\//, '').replace('.git', '') : undefined} />
                    </div>
                  )}
                  <div className="flex gap-2">
                    <div className="flex-1">
                      <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">SOURCE (local / uploaded)</label>
                      <input type="text" value={repoPath} onChange={(e) => { setRepoPath(e.target.value); if (e.target.value) setRepoUrl(''); }} placeholder="/path/to/repo" className={inputClass} />
                    </div>
                    <div className="flex-1">
                      <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">REPO URL (git URL)</label>
                      <input type="text" value={repoUrl} onChange={(e) => { setRepoUrl(e.target.value); if (e.target.value) setRepoPath(''); }} placeholder="https://github.com/org/repo" className={inputClass} />
                    </div>
                  </div>
                </>
              )}


              {/* Shared advanced fields: modules, tuning, headers */}
              <div className="flex gap-2">
                <div className="flex-1">
                  <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">MODULES <span className="normal-case font-normal">(blank = all)</span></label>
                  <input type="text" value={modules} onChange={(e) => setModules(e.target.value)} placeholder="xss_scanner,sqli_error_based" className={inputClass} />
                </div>
                <div className="flex-1">
                  <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">MODULE_TAGS <span className="normal-case font-normal">(blank = all)</span></label>
                  <input type="text" value={moduleTags} onChange={(e) => setModuleTags(e.target.value)} placeholder="xss,light" className={inputClass} />
                </div>
              </div>

              {(activeMode === 'full_scan' || activeMode === 'repo_scan') && (
                <>
                  <div className="flex gap-2">
                    <div className="flex-1">
                      <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">CONCURRENCY</label>
                      <input type="number" value={concurrency} onChange={(e) => setConcurrency(e.target.value)} placeholder="10" className={inputClass} />
                    </div>
                    <div className="flex-1">
                      <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">TIMEOUT</label>
                      <input type="text" value={timeout} onChange={(e) => setTimeout_(e.target.value)} placeholder="30s" className={inputClass} />
                    </div>
                    <div className="flex-1">
                      <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">MAX_PER_HOST</label>
                      <input type="number" value={maxPerHost} onChange={(e) => setMaxPerHost(e.target.value)} placeholder="5" className={inputClass} />
                    </div>
                    <div className="flex-1">
                      <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">RATE_LIMIT</label>
                      <input type="number" value={rateLimit} onChange={(e) => setRateLimit(e.target.value)} placeholder="100" className={inputClass} />
                    </div>
                    <div className="flex-1">
                      <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">MAX_DURATION</label>
                      <input type="text" value={maxDuration} onChange={(e) => setMaxDuration(e.target.value)} placeholder="30m" className={inputClass} />
                    </div>
                  </div>
                  <div className="flex gap-2">
                    {activeMode === 'full_scan' && (
                      <div className="w-36">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">SCOPE_ORIGIN</label>
                        <Dropdown value={scopeOrigin} onChange={setScopeOrigin} options={SCOPE_ORIGINS.map(s => ({ value: s, label: s || '(default)' }))} />
                      </div>
                    )}
                    <div className="w-36">
                      <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">HEURISTICS</label>
                      <Dropdown value={heuristics} onChange={setHeuristics} options={HEURISTICS.map(h => ({ value: h, label: h || '(default)' }))} />
                    </div>
                    <div className="flex-1">
                      <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">SCANNING_PROFILE</label>
                      <input type="text" value={scanProfile} onChange={(e) => setScanProfile(e.target.value)} placeholder="profile name" className={inputClass} />
                    </div>
                  </div>
                </>
              )}

              {/* Headers */}
              <div>
                <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">HEADERS</label>
                <div className="space-y-1">
                  {headers.map((h, i) => (
                    <div key={i} className="flex gap-1 items-center">
                      <input type="text" value={h.key} onChange={(e) => updateHeader(i, 'key', e.target.value)} placeholder="Header-Name" className={`${inputClass} flex-1`} />
                      <input type="text" value={h.value} onChange={(e) => updateHeader(i, 'value', e.target.value)} placeholder="value" className={`${inputClass} flex-1`} />
                      <button onClick={() => removeHeader(i)} className="text-[#708e8e] hover:text-[#e34e1c] text-xs px-1">x</button>
                    </div>
                  ))}
                  <button onClick={addHeader} className="text-xs text-[#708e8e] hover:text-[#0078c8]">[+ header]</button>
                </div>
              </div>
            </div>
          )}

          {/* 6. Result display */}
          {mutation.isSuccess && mutation.data && (
            <div className="border border-[#bbc3c4] p-2 text-xs flex items-center gap-4 flex-wrap">
              <span className="text-[#0078c8] font-bold">RESULT</span>
              <span><span className="text-[#708e8e]">scan_id:</span> <span className="text-[#005661]">{mutation.data.scan_id}</span></span>
              <span><span className="text-[#708e8e]">status:</span> <span className="text-[#005661]">{mutation.data.status}</span></span>
              {mutation.data.scan_mode && <span><span className="text-[#708e8e]">mode:</span> <span className="text-[#005661]">{mutation.data.scan_mode}</span></span>}
              {mutation.data.targets_count != null && <span><span className="text-[#708e8e]">targets:</span> <span className="text-[#005661]">{mutation.data.targets_count}</span></span>}
              {mutation.data.records_to_scan != null && <span><span className="text-[#708e8e]">records:</span> <span className="text-[#005661]">{mutation.data.records_to_scan}</span></span>}
              {mutation.data.source && <span><span className="text-[#708e8e]">source:</span> <span className="text-[#005661]">{mutation.data.source}</span></span>}
              {mutation.data.message && <span><span className="text-[#708e8e]">msg:</span> <span className="text-[#005661]">{mutation.data.message}</span></span>}
            </div>
          )}
          {mutation.isError && (
            <div className="text-xs text-[#e34e1c]">error: {(mutation.error as Error).message}</div>
          )}
        </div>
      </div>

      {/* ════════════════════════════════════════ SCAN HISTORY ════════════════════════════════════════ */}
      <div className="border border-[#bbc3c4] bg-white overflow-hidden mt-3">
        <div className="px-3 py-1.5 border-b border-[#bbc3c4]">
          <span className="text-[#0078c8] text-xs font-bold">SCAN HISTORY</span>
        </div>
        <div className="flex" style={{ minHeight: selectedScan ? 420 : undefined }}>
          <div className={`overflow-x-auto ${selectedScan ? 'w-1/2' : 'w-full'}`}>
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
                {scansLoading && <tr><td colSpan={7} className="px-3 py-4 text-center text-[#708e8e]">loading...</td></tr>}
                {!scansLoading && (!scansData?.data || scansData.data.length === 0) && <tr><td colSpan={7} className="px-3 py-4 text-center text-[#bbc3c4]">no scans</td></tr>}
                {scansData?.data?.map((scan) => (
                  <tr key={scan.uuid} onClick={() => setExpandedScanUuid((prev) => prev === scan.uuid ? null : scan.uuid)} className={`border-b border-[#bbc3c4]/50 hover:bg-[#e8eeee] transition-colors cursor-pointer ${expandedScanUuid === scan.uuid ? 'bg-[#e8eeee]' : ''}`}>
                    <td className="px-3 py-1.5"><StatusBadge status={scan.status} /></td>
                    <td className="px-3 py-1.5 text-[#005661]">{scan.name || scan.uuid.slice(0, 8)}</td>
                    <td className="px-3 py-1.5 text-[#708e8e]">{[scan.scan_mode, scan.scan_source].filter(Boolean).join(' / ') || '-'}</td>
                    <td className="px-3 py-1.5 text-right text-[#005661]">{scan.total_findings}</td>
                    <td className="px-3 py-1.5 text-right text-[#005661]">{scan.processed_count}</td>
                    <td className="px-3 py-1.5 text-[#708e8e]">{formatDate(scan.started_at)}</td>
                    <td className="px-3 py-1.5">
                      <ScanActions scan={scan} onStop={(uuid) => stopScan.mutate(uuid)} onDelete={(uuid) => deleteScan.mutate(uuid)} onPause={(uuid) => pauseScan.mutate(uuid)} onResume={(uuid) => resumeScan.mutate(uuid)} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {selectedScan && <div className="w-1/2"><ScanDetailPanel scan={selectedScan} onClose={() => setExpandedScanUuid(null)} /></div>}
        </div>
        {(scansData?.total || 0) > HISTORY_PAGE_SIZE && (
          <div className="flex items-center justify-between px-3 py-1 border-t border-[#bbc3c4] text-xs text-[#708e8e]">
            <span>{(historyParams.offset || 0) + 1}-{Math.min((historyParams.offset || 0) + HISTORY_PAGE_SIZE, scansData?.total || 0)}/{scansData?.total || 0}</span>
            <div className="flex items-center gap-1">
              <button onClick={() => setHistoryParams((p) => ({ ...p, offset: ((p.offset || 0) - HISTORY_PAGE_SIZE) }))} disabled={historyPage <= 1} className="hover:text-[#0078c8] disabled:opacity-30 px-1">{'<'}</button>
              <span className="px-1">{historyPage}/{historyTotalPages}</span>
              <button onClick={() => setHistoryParams((p) => ({ ...p, offset: ((p.offset || 0) + HISTORY_PAGE_SIZE) }))} disabled={historyPage >= historyTotalPages} className="hover:text-[#0078c8] disabled:opacity-30 px-1">{'>'}</button>
            </div>
          </div>
        )}
        {(deleteScan.isError || stopScan.isError || pauseScan.isError || resumeScan.isError) && (
          <div className="px-3 py-1 text-xs text-[#e34e1c]">error: {((deleteScan.error || stopScan.error || pauseScan.error || resumeScan.error) as Error)?.message}</div>
        )}
      </div>
    </PageShell>
  );
}
