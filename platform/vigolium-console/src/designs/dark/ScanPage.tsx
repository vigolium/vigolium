'use client';

import React, { useState, useRef, useCallback, useMemo } from 'react';
import { Copy, Check, Upload, Loader2, Zap, Shield, Radar } from 'lucide-react';
import { zipSync } from 'fflate';
import { useScanURL, useScanRequest, useRunScan, useUploadRepo, useScans, useDeleteScan, useStopScan, usePauseScan, useResumeScan, useScanLogs } from '@/api/hooks';
import type { ScanURLRequest, ScanRequestRequest, RunScanRequest, ScansQueryParams, Scan, ScanLog } from '@/api/types';
import { formatDate } from '@/lib/formatters';
import PageShell from './PageShell';
import Dropdown from './Dropdown';
import GitHubRepoPicker from './GitHubRepoPicker';

type ScanMode = 'full_scan' | 'url' | 'raw_request' | 'repo_scan';

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const;
const SCOPE_ORIGINS = ['', 'all', 'relaxed', 'balanced', 'strict'] as const;
const HEURISTICS = ['', 'none', 'basic', 'advanced'] as const;
const HISTORY_PAGE_SIZE = 20;

const MODE_LABELS: Record<ScanMode, string> = {
  full_scan: 'FULL SCAN',
  url: 'URL SCAN',
  raw_request: 'RAW REQUEST',
  repo_scan: 'REPO SCAN',
};

const MODE_BADGE_COLORS: Record<ScanMode, string> = {
  full_scan: '#7fd962',
  url: '#7fd962',
  raw_request: '#68a8e4',
  repo_scan: '#d8a657',
};

const MODE_OPTIONS: { value: string; label: string }[] = [
  { value: 'full_scan', label: 'FULL SCAN' },
  { value: 'url', label: 'URL SCAN' },
  { value: 'raw_request', label: 'RAW REQUEST' },
  { value: 'repo_scan', label: 'REPO SCAN' },
];

interface HeaderRow {
  key: string;
  value: string;
}

function detectMode(input: string): ScanMode {
  const trimmed = input.trim();
  if (!trimmed) return 'full_scan';

  const firstLine = trimmed.split('\n')[0].trim();

  // Raw HTTP request detection
  if (/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\//.test(firstLine)) {
    return 'raw_request';
  }

  // Single line checks
  const lines = trimmed.split('\n').filter((l) => l.trim());
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
  const [modulesCopied, setModulesCopied] = useState(false);

  const statusColor = (s: string) =>
    s === 'running' ? '#98bc37' :
    s === 'paused' ? '#f2c55c' :
    s === 'completed' ? '#7fd962' :
    s === 'failed' || s === 'cancelled' ? '#ef2f27' : '#fce8c3';

  const levelColor = (level: string) => {
    if (level === 'warn') return '#f2c55c';
    if (level === 'error') return '#ef2f27';
    return '#918175';
  };

  return (
    <div className="border-l border-[#2e2b26] flex flex-col h-full min-h-0">
      <div className="px-3 py-1.5 border-b border-[#2e2b26] flex items-center justify-between shrink-0">
        <span className="text-[#7fd962] text-xs font-bold">SCAN DETAILS</span>
        <button onClick={onClose} className="text-[10px] text-[#918175] hover:text-[#fce8c3]">[close]</button>
      </div>
      <div className="px-3 py-2 text-xs border-b border-[#2e2b26] shrink-0 space-y-1">
        <div className="text-[#fce8c3] break-all"><span className="text-[#918175]">uuid:</span> {scan.uuid}</div>
        {scan.project_uuid && <div className="text-[#fce8c3] break-all"><span className="text-[#918175]">project_uuid:</span> {scan.project_uuid}</div>}
        <div className="flex flex-wrap gap-x-4 gap-y-0.5">
          <span><span className="text-[#918175]">status:</span> <span className="font-bold uppercase" style={{ color: statusColor(scan.status) }}>{scan.status}</span></span>
          <span><span className="text-[#918175]">name:</span> <span className="text-[#fce8c3]">{scan.name || '-'}</span></span>
          <span><span className="text-[#918175]">mode:</span> <span className="text-[#68a8e4]">{scan.scan_mode || '-'}</span></span>
          <span><span className="text-[#918175]">source:</span> <span className="text-[#2be4d0]">{scan.scan_source || '-'}</span></span>
          <span><span className="text-[#918175]">findings:</span> <span style={{ color: scan.total_findings > 0 ? '#f0c674' : '#918175' }}>{scan.total_findings}</span></span>
          <span><span className="text-[#918175]">processed:</span> <span className="text-[#98bc37]">{scan.processed_count}</span></span>
        </div>
        <div className="flex flex-wrap gap-x-4 gap-y-0.5">
          <span><span className="text-[#918175]">started:</span> <span className="text-[#fce8c3]">{scan.started_at ? formatDate(scan.started_at) : '-'}</span></span>
          <span><span className="text-[#918175]">finished:</span> <span className="text-[#fce8c3]">{scan.finished_at ? formatDate(scan.finished_at) : '-'}</span></span>
          <span><span className="text-[#918175]">created:</span> <span className="text-[#fce8c3]">{scan.created_at ? formatDate(scan.created_at) : '-'}</span></span>
        </div>
        {scan.modules && (
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[#918175]">modules:</span>
              <span className="text-[#68a8e4] text-[10px]">{scan.modules === 'all' ? 'all' : scan.modules.split(',').length + ' modules'}</span>
              <button onClick={() => { navigator.clipboard.writeText(scan.modules!); setModulesCopied(true); setTimeout(() => setModulesCopied(false), 1500); }} className="px-1.5 py-0.5 text-[10px] border border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]">
                {modulesCopied ? <><Check size={10} className="inline-block mr-0.5 -mt-px" />copied!</> : <><Copy size={10} className="inline-block mr-0.5 -mt-px" />copy</>}
              </button>
            </div>
            <textarea readOnly rows={3} value={scan.modules} className="mt-0.5 w-full bg-[#141310] border border-[#2e2b26] text-[#fce8c3] text-xs p-1.5 resize-none focus:outline-none" />
          </div>
        )}
      </div>
      <div className="px-3 py-1.5 border-b border-[#2e2b26] shrink-0">
        <span className="text-[#7fd962] text-xs font-bold">LOGS</span>
        <span className="text-[#403d38] text-[10px] ml-2">{logs.length} entries</span>
      </div>
      <div className="bg-[#141310] overflow-y-auto font-mono text-[11px] leading-relaxed flex-1 min-h-0">
        {logs.length === 0 ? (
          <div className="px-3 py-2 text-[#403d38]">no logs</div>
        ) : (
          logs.map((log: ScanLog) => (
            <div key={log.id} className="px-3 py-0.5 hover:bg-[#1c1b19] flex gap-2">
              <span className="text-[#918a84] shrink-0">{new Date(log.created_at).toLocaleTimeString()}</span>
              <span className="shrink-0 uppercase font-bold" style={{ color: levelColor(log.level) }}>{log.level.padEnd(5)}</span>
              {log.phase && <span className="text-[#98bc37] shrink-0">[{log.phase}]</span>}
              <span className="text-[#fffbf0]">{log.message}</span>
              {log.metadata && <span className="text-[#918a84]">{log.metadata}</span>}
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
          <button onClick={(e) => { e.stopPropagation(); onPause(scan.uuid); }} className="text-[10px] text-[#f2c55c] hover:underline">[pause]</button>
          <button onClick={(e) => { e.stopPropagation(); onStop(scan.uuid); }} className="text-[10px] text-[#ef2f27] hover:underline">[stop]</button>
        </>
      )}
      {scan.status === 'paused' && (
        <>
          <button onClick={(e) => { e.stopPropagation(); onResume(scan.uuid); }} className="text-[10px] text-[#98bc37] hover:underline">[resume]</button>
          <button onClick={(e) => { e.stopPropagation(); onStop(scan.uuid); }} className="text-[10px] text-[#ef2f27] hover:underline">[stop]</button>
        </>
      )}
      {!confirmDel ? (
        <button onClick={() => setConfirmDel(true)} className="text-[10px] text-[#918175] hover:text-[#ef2f27]">[del]</button>
      ) : (
        <span className="flex items-center gap-1">
          <button onClick={() => { onDelete(scan.uuid); setConfirmDel(false); }} className="text-[10px] text-[#ef2f27] hover:underline">[confirm]</button>
          <button onClick={() => setConfirmDel(false)} className="text-[10px] text-[#918175] hover:underline">[cancel]</button>
        </span>
      )}
    </div>
  );
}

export default function ScanPage() {
  // --- Consolidated state ---
  const [input, setInput] = useState('');
  const [modeOverride, setModeOverride] = useState<ScanMode | null>(null);
  const [strategy, setStrategy] = useState<'lite' | 'balanced' | 'deep'>('balanced');
  const [advancedOpen, setAdvancedOpen] = useState(false);

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

  // File upload state
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [compressing, setCompressing] = useState(false);
  const dragCounter = useRef(0);

  // Scan history state
  const [historyParams, setHistoryParams] = useState<ScansQueryParams>({ limit: HISTORY_PAGE_SIZE, offset: 0 });
  const [expandedScanUuid, setExpandedScanUuid] = useState<string | null>(null);

  // --- Hooks ---
  const scanURL = useScanURL();
  const scanRequest = useScanRequest();
  const runScan = useRunScan();
  const uploadRepo = useUploadRepo();
  const { data: scansData, isLoading: scansLoading } = useScans(historyParams);
  const deleteScan = useDeleteScan();
  const stopScan = useStopScan();
  const pauseScan = usePauseScan();
  const resumeScan = useResumeScan();

  // --- Derived ---
  const detectedMode = useMemo(() => detectMode(input), [input]);
  const activeMode: ScanMode = modeOverride ?? detectedMode;

  const mutation =
    activeMode === 'url' ? scanURL :
    activeMode === 'raw_request' ? scanRequest :
    runScan;

  const isPending = mutation.isPending;

  // --- Header helpers ---
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

  // --- File upload logic (repo mode) ---
  const doUpload = useCallback((file: File) => {
    uploadRepo.mutate(file, {
      onSuccess: (data) => { setRepoPath(data.repo_path); },
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

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    doUpload(file);
    e.target.value = '';
  };

  // --- Submit logic ---
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
        let encoded = input.trim();
        try { atob(encoded); } catch { encoded = btoa(encoded); }
        const req: ScanRequestRequest = { raw_request: encoded };
        if (modules) req.modules = modules;
        if (noPassive) req.no_passive = true;
        scanRequest.mutate(req);
        break;
      }
      case 'repo_scan': {
        const req: RunScanRequest = {};
        const targets = input.trim().split('\n').map(s => s.trim()).filter(Boolean);
        if (targets.length > 0) {
          // If the input is a repo URL, set it as repo_url, not targets
          if (targets.length === 1 && (targets[0].includes('github.com/') || targets[0].endsWith('.git'))) {
            if (!repoUrl && !repoPath) req.repo_url = targets[0];
          } else {
            req.targets = targets;
          }
        }
        if (repoPath) req.repo_path = repoPath;
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
      case 'full_scan': {
        const targets = input.trim().split('\n').map(s => s.trim()).filter(Boolean);
        const req: RunScanRequest = {};
        if (targets.length > 0) req.targets = targets;
        req.strategy = strategy;
        if (modules) req.modules = modules.split(',').map(s => s.trim()).filter(Boolean);
        if (moduleTags) req.module_tags = moduleTags.split(',').map(s => s.trim()).filter(Boolean);
        if (dryRun) req.dry_run = true;
        if (concurrency) req.concurrency = parseInt(concurrency);
        if (timeout) req.timeout = timeout;
        if (maxPerHost) req.max_per_host = parseInt(maxPerHost);
        if (rateLimit) req.rate_limit = parseInt(rateLimit);
        if (maxDuration) req.scanning_max_duration = maxDuration;
        if (scopeOrigin) req.scope_origin = scopeOrigin;
        if (heuristics) req.heuristics_check = heuristics;
        if (scanProfile) req.scanning_profile = scanProfile;
        if (repoPath) req.repo_path = repoPath;
        if (repoUrl) req.repo_url = repoUrl;
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
    true; // full_scan can run with empty targets (server decides)

  // --- Style constants ---
  const inputClass = "w-full bg-[#1c1b19] border border-[#2e2b26] text-[#fce8c3] text-xs px-2 py-1 focus:outline-none focus:border-[#7fd962]/50";
  const textareaClass = `${inputClass} font-mono resize-y whitespace-pre-wrap break-all`;
  const btnClass = "text-xs px-4 py-1 border border-[#FF9F2F] text-[#FF9F2F] bg-[#FF9F2F]/10 hover:bg-[#FF9F2F]/20 shadow-[inset_0_0_18px_rgba(255,159,47,0.5)] hover:shadow-[inset_0_0_28px_rgba(255,159,47,0.7)] disabled:opacity-50 transition-colors shrink-0";

  const selectedScan = expandedScanUuid ? scansData?.data?.find((s) => s.uuid === expandedScanUuid) ?? null : null;
  const historyPage = Math.floor((historyParams.offset || 0) / HISTORY_PAGE_SIZE) + 1;
  const historyTotalPages = Math.ceil((scansData?.total || 0) / HISTORY_PAGE_SIZE);

  return (
    <PageShell>
      {/* NEW SCAN */}
      <div className="border border-[#2e2b26] bg-[#1c1b19]">
        <div className="px-3 py-1.5 border-b border-[#2e2b26]">
          <span className="text-[#7fd962] text-xs font-bold">NEW SCAN</span>
        </div>

        <div className="p-3 space-y-3">
          {/* 1. Main input area with detected mode badge */}
          <div>
            <div className="flex items-center gap-1.5 mb-0.5">
              <label className="text-[#918175] text-xs">Target</label>
              <span className="text-[10px]" style={{ color: MODE_BADGE_COLORS[detectedMode] }}>
                (type: {MODE_LABELS[detectedMode].toLowerCase()})
              </span>
              {modeOverride && (
                <>
                  <span className="text-[10px] text-[#918175]">{'>'}</span>
                  <span className="text-[10px]" style={{ color: '#f2c55c' }}>
                    (type: {MODE_LABELS[modeOverride].toLowerCase()})
                  </span>
                  <button onClick={() => setModeOverride(null)} className="text-[10px] text-[#918175] hover:text-[#fce8c3]">[auto]</button>
                </>
              )}
              <Dropdown
                value={modeOverride ?? ''}
                onChange={(val) => setModeOverride(val ? val as ScanMode : null)}
                options={[{ value: '', label: 'auto-detect' }, ...MODE_OPTIONS]}
              />
            </div>
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              rows={Math.max(4, Math.min(30, input.split('\n').length + 1))}
              placeholder="Paste URL, targets, raw HTTP request, or repo URL..."
              className={`${textareaClass} text-sm`}
            />
          </div>

          {/* 3. Strategy presets (only for full_scan) */}
          {activeMode === 'full_scan' && (
            <div className="grid grid-cols-3 gap-2">
              <button
                onClick={() => setStrategy('lite')}
                className={`border p-3 text-center transition-colors ${
                  strategy === 'lite'
                    ? 'border-[#7fd962]/50 text-[#7fd962] bg-[#7fd962]/10'
                    : 'border-[#2e2b26] text-[#918175] hover:text-[#fce8c3] hover:border-[#918175]/50'
                }`}
              >
                <Zap className="w-4 h-4 mx-auto mb-1" />
                <div className="text-xs font-bold">QUICK</div>
                <div className="text-[10px] mt-1 opacity-70">Fast &amp; light</div>
              </button>
              <button
                onClick={() => setStrategy('balanced')}
                className={`border p-3 text-center transition-colors ${
                  strategy === 'balanced'
                    ? 'border-[#7fd962]/50 text-[#7fd962] bg-[#7fd962]/10'
                    : 'border-[#2e2b26] text-[#918175] hover:text-[#fce8c3] hover:border-[#918175]/50'
                }`}
              >
                <Shield className="w-4 h-4 mx-auto mb-1" />
                <div className="text-xs font-bold">BALANCED</div>
                <div className="text-[10px] mt-1 opacity-70">Good coverage</div>
              </button>
              <button
                onClick={() => setStrategy('deep')}
                className={`border p-3 text-center transition-colors ${
                  strategy === 'deep'
                    ? 'border-[#7fd962]/50 text-[#7fd962] bg-[#7fd962]/10'
                    : 'border-[#2e2b26] text-[#918175] hover:text-[#fce8c3] hover:border-[#918175]/50'
                }`}
              >
                <Radar className="w-4 h-4 mx-auto mb-1" />
                <div className="text-xs font-bold">DEEP</div>
                <div className="text-[10px] mt-1 opacity-70">Maximum coverage</div>
              </button>
            </div>
          )}

          {/* Repo scan: strategy is fixed to whitebox */}
          {activeMode === 'repo_scan' && (
            <div className="text-[10px] text-[#918175] italic">
              Strategy is fixed to <span className="text-[#7fd962] font-bold">whitebox</span> for repo scans.
            </div>
          )}


          {/* 4. Scan button */}
          <div className="flex gap-2 items-center">
            <button onClick={handleSubmit} disabled={!canSubmit || isPending} className={btnClass}>
              {isPending ? 'scanning...' : '[SCAN]'}
            </button>
            <button onClick={() => setDryRun(!dryRun)} className={`px-2 py-1 text-xs border transition-colors shrink-0 ${dryRun ? 'border-[#f2c55c]/50 text-[#f2c55c] bg-[#f2c55c]/10' : 'border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]'}`}>DRY_RUN: {dryRun ? 'ON' : 'OFF'}</button>
            {(activeMode === 'url' || activeMode === 'raw_request') && (
              <button onClick={() => setNoPassive(!noPassive)} className={`px-2 py-1 text-xs border transition-colors shrink-0 ${noPassive ? 'border-[#ef2f27]/50 text-[#ef2f27] bg-[#ef2f27]/10' : 'border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]'}`}>NO_PASSIVE: {noPassive ? 'ON' : 'OFF'}</button>
            )}
            <button onClick={() => setAdvancedOpen(v => !v)} className={`px-2 py-1 text-xs border transition-colors shrink-0 ${advancedOpen ? 'border-[#f2c55c]/50 text-[#f2c55c] bg-[#f2c55c]/10' : 'border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]'}`}>ADVANCED: {advancedOpen ? 'ON' : 'OFF'}</button>
          </div>
          {advancedOpen && (
            <div className="space-y-2 pl-4 border-l-2 border-[#2e2b26]">
              {/* Modules */}
              <div className="flex gap-2">
                <div className="flex-1">
                  <label className="text-[#918175] text-[10px] uppercase block mb-0.5">MODULES <span className="normal-case font-normal">(blank = all)</span></label>
                  <input type="text" value={modules} onChange={(e) => setModules(e.target.value)} placeholder="xss_scanner,sqli_error_based" className={inputClass} />
                </div>
                {(activeMode === 'full_scan' || activeMode === 'repo_scan') && (
                  <div className="flex-1">
                    <label className="text-[#918175] text-[10px] uppercase block mb-0.5">MODULE_TAGS <span className="normal-case font-normal">(blank = all)</span></label>
                    <input type="text" value={moduleTags} onChange={(e) => setModuleTags(e.target.value)} placeholder="xss,light" className={inputClass} />
                  </div>
                )}
              </div>

              {/* URL mode: method & body */}
              {activeMode === 'url' && (
                <div className="flex gap-2 items-end">
                  <div className="w-28">
                    <label className="text-[#918175] text-[10px] uppercase block mb-0.5">METHOD</label>
                    <Dropdown value={method} onChange={setMethod} options={METHODS.map(m => ({ value: m, label: m }))} />
                  </div>
                  <div className="flex-1">
                    <label className="text-[#918175] text-[10px] uppercase block mb-0.5">BODY (optional)</label>
                    <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={2} placeholder='{"key": "value"}' className={textareaClass} />
                  </div>
                </div>
              )}

              {/* Repo mode: upload + repo fields */}
              {activeMode === 'repo_scan' && (
                <>
                  <div
                    onDragEnter={onDragEnter} onDragLeave={onDragLeave} onDragOver={onDragOver} onDrop={onDrop}
                    className={`border border-dashed p-4 text-center transition-colors ${compressing || uploadRepo.isPending ? '' : 'cursor-pointer'} ${dragging ? 'border-[#3b82f6] bg-[#3b82f6]/10' : 'border-[#2e2b26] hover:border-[#3b82f6]/50'}`}
                    onClick={() => { if (!compressing && !uploadRepo.isPending) fileInputRef.current?.click(); }}
                  >
                    <input ref={fileInputRef} type="file" accept=".zip,.tar.gz,.tgz,.tar" onChange={handleFileUpload} className="hidden" />
                    {compressing || uploadRepo.isPending ? (
                      <>
                        <Loader2 className="w-5 h-5 mx-auto mb-1.5 text-[#3b82f6] animate-spin" />
                        <p className="text-xs text-[#fce8c3]">{compressing ? 'Compressing folder...' : 'Uploading...'}</p>
                      </>
                    ) : (
                      <>
                        <Upload className="w-5 h-5 mx-auto mb-1.5 text-[#3b82f6]/70" />
                        <p className="text-xs text-[#fce8c3]">
                          {dragging ? 'Drop here to upload' : 'Click or drag & drop archive or folder'}
                        </p>
                      </>
                    )}
                    <p className="text-[10px] text-[#918175] mt-1">.zip, .tar.gz, .tgz, .tar — or drop a folder (auto-zipped) — max 500 MB</p>
                    {uploadRepo.isSuccess && <p className="text-[10px] text-[#98bc37] mt-1">uploaded — repo_path set</p>}
                    {uploadRepo.isError && <p className="text-[10px] text-[#ef2f27] mt-1">upload failed: {(uploadRepo.error as Error).message}</p>}
                  </div>
                  <div>
                    <label className="text-[#918175] text-[10px] uppercase block mb-0.5">GITHUB REPO</label>
                    <GitHubRepoPicker onSelect={(url) => { setRepoUrl(url); setRepoPath(''); }} selectedRepo={repoUrl.includes('x-access-token') ? repoUrl.replace(/https:\/\/x-access-token:[^@]+@github\.com\//, '').replace('.git', '') : undefined} />
                  </div>
                  <div className="flex gap-2">
                    <div className="flex-1"><label className="text-[#918175] text-[10px] uppercase block mb-0.5">REPO_PATH (local path or uploaded)</label><input type="text" value={repoPath} onChange={(e) => { setRepoPath(e.target.value); if (e.target.value) setRepoUrl(''); }} placeholder="/path/to/repo" className={inputClass} /></div>
                    <div className="flex-1"><label className="text-[#918175] text-[10px] uppercase block mb-0.5">REPO_URL (git URL)</label><input type="text" value={repoUrl} onChange={(e) => { setRepoUrl(e.target.value); if (e.target.value) setRepoPath(''); }} placeholder="https://github.com/org/repo" className={inputClass} /></div>
                  </div>
                </>
              )}

              {/* Full scan: scope_origin, scanning_profile */}
              {activeMode === 'full_scan' && (
                <div className="flex gap-2">
                  <div className="w-36">
                    <label className="text-[#918175] text-[10px] uppercase block mb-0.5">SCOPE_ORIGIN</label>
                    <Dropdown value={scopeOrigin} onChange={setScopeOrigin} options={SCOPE_ORIGINS.map(s => ({ value: s, label: s || '(default)' }))} />
                  </div>
                  <div className="flex-1">
                    <label className="text-[#918175] text-[10px] uppercase block mb-0.5">SCANNING_PROFILE</label>
                    <input type="text" value={scanProfile} onChange={(e) => setScanProfile(e.target.value)} placeholder="profile name" className={inputClass} />
                  </div>
                </div>
              )}

              {/* Performance: concurrency, timeout, max_per_host, rate_limit, max_duration */}
              {(activeMode === 'full_scan' || activeMode === 'repo_scan') && (
                <div className="flex gap-2">
                  <div className="flex-1"><label className="text-[#918175] text-[10px] uppercase block mb-0.5">CONCURRENCY</label><input type="number" value={concurrency} onChange={(e) => setConcurrency(e.target.value)} placeholder="10" className={inputClass} /></div>
                  <div className="flex-1"><label className="text-[#918175] text-[10px] uppercase block mb-0.5">TIMEOUT</label><input type="text" value={timeout} onChange={(e) => setTimeout_(e.target.value)} placeholder="30s" className={inputClass} /></div>
                  <div className="flex-1"><label className="text-[#918175] text-[10px] uppercase block mb-0.5">MAX_PER_HOST</label><input type="number" value={maxPerHost} onChange={(e) => setMaxPerHost(e.target.value)} placeholder="5" className={inputClass} /></div>
                  <div className="flex-1"><label className="text-[#918175] text-[10px] uppercase block mb-0.5">RATE_LIMIT</label><input type="number" value={rateLimit} onChange={(e) => setRateLimit(e.target.value)} placeholder="100" className={inputClass} /></div>
                  <div className="flex-1"><label className="text-[#918175] text-[10px] uppercase block mb-0.5">MAX_DURATION</label><input type="text" value={maxDuration} onChange={(e) => setMaxDuration(e.target.value)} placeholder="30m" className={inputClass} /></div>
                </div>
              )}

              {/* Heuristics (for full_scan, repo_scan, stored_records) */}
              {(activeMode === 'full_scan' || activeMode === 'repo_scan') && (
                <div className="w-36">
                  <label className="text-[#918175] text-[10px] uppercase block mb-0.5">HEURISTICS</label>
                  <Dropdown value={heuristics} onChange={setHeuristics} options={HEURISTICS.map(h => ({ value: h, label: h || '(default)' }))} />
                </div>
              )}

              {/* Headers (all modes) */}
              <div>
                <label className="text-[#918175] text-[10px] uppercase block mb-0.5">HEADERS</label>
                <div className="space-y-1">
                  {headers.map((h, i) => (
                    <div key={i} className="flex gap-1 items-center">
                      <input type="text" value={h.key} onChange={(e) => updateHeader(i, 'key', e.target.value)} placeholder="Header-Name" className={`${inputClass} flex-1`} />
                      <input type="text" value={h.value} onChange={(e) => updateHeader(i, 'value', e.target.value)} placeholder="value" className={`${inputClass} flex-1`} />
                      <button onClick={() => removeHeader(i)} className="text-[#918175] hover:text-[#ef2f27] text-xs px-1">x</button>
                    </div>
                  ))}
                  <button onClick={addHeader} className="text-xs text-[#918175] hover:text-[#7fd962]">[+ header]</button>
                </div>
              </div>
            </div>
          )}

          {/* 6. Result display */}
          {mutation.isSuccess && mutation.data && (
            <div className="border border-[#2e2b26] p-2 text-xs flex items-center gap-4 flex-wrap">
              <span className="text-[#7fd962] font-bold">RESULT</span>
              <span><span className="text-[#918175]">scan_id:</span> <span className="text-[#fce8c3]">{mutation.data.scan_id}</span></span>
              <span><span className="text-[#918175]">status:</span> <span className="text-[#fce8c3]">{mutation.data.status}</span></span>
              {mutation.data.scan_mode && <span><span className="text-[#918175]">mode:</span> <span className="text-[#fce8c3]">{mutation.data.scan_mode}</span></span>}
              {mutation.data.targets_count != null && <span><span className="text-[#918175]">targets:</span> <span className="text-[#fce8c3]">{mutation.data.targets_count}</span></span>}
              {mutation.data.records_to_scan != null && <span><span className="text-[#918175]">records:</span> <span className="text-[#fce8c3]">{mutation.data.records_to_scan}</span></span>}
              {mutation.data.repo_path && <span><span className="text-[#918175]">repo:</span> <span className="text-[#fce8c3]">{mutation.data.repo_path}</span></span>}
              {mutation.data.message && <span><span className="text-[#918175]">msg:</span> <span className="text-[#fce8c3]">{mutation.data.message}</span></span>}
            </div>
          )}
          {mutation.isError && <div className="text-xs text-[#ef2f27]">error: {(mutation.error as Error).message}</div>}
        </div>
      </div>

      {/* Scan History */}
      <div className="border border-[#2e2b26] bg-[#1c1b19] overflow-hidden mt-3">
        <div className="px-3 py-1.5 border-b border-[#2e2b26]"><span className="text-[#7fd962] text-xs font-bold">SCAN HISTORY</span></div>
        <div className="flex" style={{ minHeight: selectedScan ? 420 : undefined }}>
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
                {scansLoading && <tr><td colSpan={7} className="px-3 py-4 text-center text-[#918175]">loading...</td></tr>}
                {!scansLoading && (!scansData?.data || scansData.data.length === 0) && <tr><td colSpan={7} className="px-3 py-4 text-center text-[#403d38]">no scans</td></tr>}
                {scansData?.data?.map((scan) => (
                  <tr key={scan.uuid} onClick={() => setExpandedScanUuid((prev) => prev === scan.uuid ? null : scan.uuid)} className={`border-b border-[#2e2b26]/50 hover:bg-[#272520] transition-colors cursor-pointer ${expandedScanUuid === scan.uuid ? 'bg-[#272520]' : ''}`}>
                    <td className="px-3 py-1.5"><StatusBadge status={scan.status} /></td>
                    <td className="px-3 py-1.5 text-[#fce8c3]">{scan.name || scan.uuid.slice(0, 8)}</td>
                    <td className="px-3 py-1.5 text-[#918175]">{[scan.scan_mode, scan.scan_source].filter(Boolean).join(' / ') || '-'}</td>
                    <td className="px-3 py-1.5 text-right text-[#fce8c3]">{scan.total_findings}</td>
                    <td className="px-3 py-1.5 text-right text-[#fce8c3]">{scan.processed_count}</td>
                    <td className="px-3 py-1.5 text-[#918175]">{formatDate(scan.started_at)}</td>
                    <td className="px-3 py-1.5"><ScanActions scan={scan} onStop={(uuid) => stopScan.mutate(uuid)} onDelete={(uuid) => deleteScan.mutate(uuid)} onPause={(uuid) => pauseScan.mutate(uuid)} onResume={(uuid) => resumeScan.mutate(uuid)} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {selectedScan && <div className="w-1/2"><ScanDetailPanel scan={selectedScan} onClose={() => setExpandedScanUuid(null)} /></div>}
        </div>
        {(scansData?.total || 0) > HISTORY_PAGE_SIZE && (
          <div className="flex items-center justify-between px-3 py-1 border-t border-[#2e2b26] text-xs text-[#918175]">
            <span>{(historyParams.offset || 0) + 1}-{Math.min((historyParams.offset || 0) + HISTORY_PAGE_SIZE, scansData?.total || 0)}/{scansData?.total || 0}</span>
            <div className="flex items-center gap-1">
              <button onClick={() => setHistoryParams((p) => ({ ...p, offset: ((p.offset || 0) - HISTORY_PAGE_SIZE) }))} disabled={historyPage <= 1} className="hover:text-[#7fd962] disabled:opacity-30 px-1">{'<'}</button>
              <span className="px-1">{historyPage}/{historyTotalPages}</span>
              <button onClick={() => setHistoryParams((p) => ({ ...p, offset: ((p.offset || 0) + HISTORY_PAGE_SIZE) }))} disabled={historyPage >= historyTotalPages} className="hover:text-[#7fd962] disabled:opacity-30 px-1">{'>'}</button>
            </div>
          </div>
        )}
        {(deleteScan.isError || stopScan.isError || pauseScan.isError || resumeScan.isError) && (
          <div className="px-3 py-1 text-xs text-[#ef2f27]">error: {((deleteScan.error || stopScan.error || pauseScan.error || resumeScan.error) as Error)?.message}</div>
        )}
      </div>
    </PageShell>
  );
}
