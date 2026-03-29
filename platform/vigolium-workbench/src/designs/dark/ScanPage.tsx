'use client';

import React, { useState, useRef, useCallback, useMemo, useEffect } from 'react';
import { ChevronRight, ChevronDown, Copy, Check, Upload, Loader2, Zap, Shield, Crosshair } from 'lucide-react';
import { zipSync } from 'fflate';
import { useScanURL, useScanRequest, useRunScan, useScanAllRecords, useUploadRepo, useScans, useDeleteScan, useStopScan, usePauseScan, useResumeScan, useScanLogs } from '@/api/hooks';
import type { ScanURLRequest, ScanRequestRequest, RunScanRequest, ScanAllRecordsRequest, ScansQueryParams, Scan, ScanLog } from '@/api/types';
import { formatDate } from '@/lib/formatters';
import PageShell from './PageShell';
import Dropdown from './Dropdown';

type DetectedMode = 'url' | 'full_scan' | 'raw_request' | 'repo';

const STRATEGIES = ['lite', 'balanced', 'deep'] as const;
const STRATEGY_META: Record<string, { icon: React.ComponentType<{ className?: string }>; label: string; desc: string }> = {
  lite: { icon: Zap, label: 'QUICK', desc: 'Fast & light' },
  balanced: { icon: Shield, label: 'BALANCED', desc: 'Good coverage' },
  deep: { icon: Crosshair, label: 'DEEP', desc: 'Maximum coverage' },
};
const PHASES = ['', 'discovery', 'spidering', 'audit'] as const;
const SCOPE_ORIGINS = ['', 'all', 'relaxed', 'balanced', 'strict'] as const;
const HEURISTICS = ['', 'none', 'basic', 'advanced'] as const;
const FILTER_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;
const HISTORY_PAGE_SIZE = 20;

interface HeaderRow {
  key: string;
  value: string;
}

function detectMode(input: string): DetectedMode {
  const trimmed = input.trim();
  if (!trimmed) return 'full_scan';
  const firstLine = trimmed.split('\n')[0].trim();
  if (/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP\//i.test(firstLine)) return 'raw_request';
  if (/\.git\s*$/.test(trimmed) || /^git@/.test(trimmed)) return 'repo';
  if (/^(\/|~\/|\.\.?\/)/.test(trimmed) && !trimmed.includes('\n')) return 'repo';
  const lines = trimmed.split('\n').filter(l => l.trim());
  return 'full_scan';
}

const MODE_LABELS: Record<DetectedMode, string> = {
  url: 'URL SCAN',
  full_scan: 'FULL SCAN',
  raw_request: 'RAW REQUEST',
  repo: 'REPO SCAN',
};

const MODE_COLORS: Record<DetectedMode, string> = {
  url: '#7fd962',
  full_scan: '#68a8e4',
  raw_request: '#f2c55c',
  repo: '#2be4d0',
};

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
  const [scanSectionOpen, setScanSectionOpen] = useState(true);

  // Smart input state
  const [input, setInput] = useState('');
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [storedRecordsOpen, setStoredRecordsOpen] = useState(false);

  // Shared advanced options
  const [strategy, setStrategy] = useState('balanced');
  const [modules, setModules] = useState('');
  const [moduleTags, setModuleTags] = useState('');
  const [noPassive, setNoPassive] = useState(false);
  const [dryRun, setDryRun] = useState(false);
  const [only, setOnly] = useState('');
  const [skip, setSkip] = useState('');
  const [scopeOrigin, setScopeOrigin] = useState('');
  const [heuristics, setHeuristics] = useState('');
  const [scanProfile, setScanProfile] = useState('');
  const [concurrency, setConcurrency] = useState('');
  const [timeout, setTimeout] = useState('');
  const [maxPerHost, setMaxPerHost] = useState('');
  const [rateLimit, setRateLimit] = useState('');
  const [maxDuration, setMaxDuration] = useState('');
  const [headers, setHeaders] = useState<HeaderRow[]>([{ key: '', value: '' }]);

  // Repo upload state
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [rsDragging, setRsDragging] = useState(false);
  const [rsCompressing, setRsCompressing] = useState(false);
  const [uploadedRepoPath, setUploadedRepoPath] = useState('');
  const dragCounter = useRef(0);

  // Stored records state
  const [srHostname, setSrHostname] = useState('');
  const [srPath, setSrPath] = useState('');
  const [srMethods, setSrMethods] = useState<string[]>([]);
  const [srStatusCodes, setSrStatusCodes] = useState('');
  const [srSource, setSrSource] = useState('');
  const [srSearch, setSrSearch] = useState('');
  const [srMinRisk, setSrMinRisk] = useState('');
  const [srRemark, setSrRemark] = useState('');
  const [srForce, setSrForce] = useState(false);

  // Scan history state
  const [historyParams, setHistoryParams] = useState<ScansQueryParams>({ limit: HISTORY_PAGE_SIZE, offset: 0 });

  const scanURL = useScanURL();
  const scanRequest = useScanRequest();
  const runScan = useRunScan();
  const scanAllRecords = useScanAllRecords();
  const uploadRepo = useUploadRepo();
  const { data: scansData, isLoading: scansLoading } = useScans(historyParams);
  const deleteScan = useDeleteScan();
  const stopScan = useStopScan();
  const pauseScan = usePauseScan();
  const resumeScan = useResumeScan();
  const [expandedScanUuid, setExpandedScanUuid] = useState<string | null>(null);

  const detectedMode = useMemo(() => detectMode(input), [input]);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    const minRows = 4;
    const lineHeight = 16;
    el.style.height = 'auto';
    const scrollH = el.scrollHeight;
    const minH = minRows * lineHeight + 12;
    el.style.height = `${Math.max(scrollH, minH)}px`;
  }, [input]);

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

  function buildAdvancedFields(req: RunScanRequest) {
    if (modules) req.modules = modules.split(',').map(s => s.trim()).filter(Boolean);
    if (moduleTags) req.module_tags = moduleTags.split(',').map(s => s.trim()).filter(Boolean);
    if (dryRun) req.dry_run = true;
    if (only) req.only = only;
    if (skip) req.skip = skip.split(',').map(s => s.trim()).filter(Boolean);
    if (scopeOrigin) req.scope_origin = scopeOrigin;
    if (heuristics) req.heuristics_check = heuristics;
    if (scanProfile) req.scanning_profile = scanProfile;
    if (concurrency) req.concurrency = parseInt(concurrency);
    if (timeout) req.timeout = timeout;
    if (maxPerHost) req.max_per_host = parseInt(maxPerHost);
    if (rateLimit) req.rate_limit = parseInt(rateLimit);
    if (maxDuration) req.scanning_max_duration = maxDuration;
    req.headers = buildHeadersObj(headers);
  }

  const handleSubmit = () => {
    const trimmed = input.trim();
    if (!trimmed) return;

    if (detectedMode === 'raw_request') {
      let encoded = trimmed;
      try { atob(trimmed); } catch { encoded = btoa(trimmed); }
      const req: ScanRequestRequest = { raw_request: encoded };
      if (modules) req.modules = modules;
      if (noPassive) req.no_passive = true;
      scanRequest.mutate(req);
    } else if (detectedMode === 'url') {
      const req: ScanURLRequest = { url: trimmed };
      req.headers = buildHeadersObj(headers);
      if (modules) req.modules = modules;
      if (noPassive) req.no_passive = true;
      scanURL.mutate(req);
    } else if (detectedMode === 'full_scan') {
      const targets = trimmed.split('\n').map(s => s.trim()).filter(Boolean);
      const req: RunScanRequest = { targets, strategy };
      buildAdvancedFields(req);
      runScan.mutate(req);
    } else if (detectedMode === 'repo') {
      const isGitUrl = /\.git\s*$/.test(trimmed) || /^git@/.test(trimmed) || /^https?:\/\//.test(trimmed);
      const req: RunScanRequest = { strategy: 'whitebox' };
      if (isGitUrl) req.repo_url = trimmed; else req.repo_path = trimmed;
      buildAdvancedFields(req);
      runScan.mutate(req);
    }
  };

  // Repo upload for repo mode
  const handleRepoUpload = () => {
    if (uploadedRepoPath) {
      const req: RunScanRequest = { repo_path: uploadedRepoPath, strategy: 'whitebox' };
      buildAdvancedFields(req);
      runScan.mutate(req);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    doUpload(file);
    e.target.value = '';
  };

  const doUpload = useCallback((file: File) => {
    uploadRepo.mutate(file, {
      onSuccess: (data) => { setUploadedRepoPath(data.repo_path); },
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

    setRsCompressing(true);
    try {
      const allFiles: { path: string; file: File }[] = [];
      for (const entry of entries) {
        allFiles.push(...await readEntryRecursive(entry));
      }
      if (allFiles.length === 0) { setRsCompressing(false); return; }
      const zipData: Record<string, Uint8Array> = {};
      for (const { path, file } of allFiles) {
        const buf = await file.arrayBuffer();
        zipData[path] = new Uint8Array(buf);
      }
      const zipped = zipSync(zipData);
      const zipFile = new File([new Uint8Array(zipped) as BlobPart], 'repo.zip', { type: 'application/zip' });
      setRsCompressing(false);
      doUpload(zipFile);
    } catch {
      setRsCompressing(false);
    }
  }, [doUpload]);

  const onDragEnter = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
    dragCounter.current++;
    setRsDragging(true);
  }, []);
  const onDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
    dragCounter.current--;
    if (dragCounter.current === 0) setRsDragging(false);
  }, []);
  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
  }, []);
  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
    dragCounter.current = 0;
    setRsDragging(false);
    if (uploadRepo.isPending) return;
    const items = e.dataTransfer.items;
    if (items && items.length > 0) {
      compressAndUpload(items);
    } else {
      const file = e.dataTransfer.files?.[0];
      if (file) doUpload(file);
    }
  }, [compressAndUpload, doUpload, uploadRepo.isPending]);

  const handleSubmitStoredRecords = () => {
    const req: ScanAllRecordsRequest = {};
    if (srHostname) req.hostname = srHostname;
    if (srPath) req.path = srPath;
    if (srMethods.length > 0) req.methods = srMethods;
    if (srStatusCodes) req.status_codes = srStatusCodes.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
    if (srSource) req.source = srSource;
    if (srSearch) req.search = srSearch;
    if (srMinRisk) req.min_risk_score = parseInt(srMinRisk);
    if (srRemark) req.remark = srRemark;
    if (srForce) req.force = true;
    if (dryRun) req.dry_run = true;
    if (modules) req.modules = modules.split(',').map(s => s.trim()).filter(Boolean);
    if (moduleTags) req.module_tags = moduleTags.split(',').map(s => s.trim()).filter(Boolean);
    if (concurrency) req.concurrency = parseInt(concurrency);
    if (timeout) req.timeout = timeout;
    if (maxPerHost) req.max_per_host = parseInt(maxPerHost);
    if (rateLimit) req.rate_limit = parseInt(rateLimit);
    if (maxDuration) req.scanning_max_duration = maxDuration;
    if (heuristics) req.heuristics_check = heuristics;
    if (scanProfile) req.scanning_profile = scanProfile;
    req.headers = buildHeadersObj(headers);
    scanAllRecords.mutate(req);
  };

  const isSubmitting = scanURL.isPending || scanRequest.isPending || runScan.isPending;
  const mutation = storedRecordsOpen ? scanAllRecords :
    (detectedMode === 'url' ? scanURL :
    detectedMode === 'raw_request' ? scanRequest : runScan);

  const canSubmit = input.trim() || (detectedMode === 'repo' && uploadedRepoPath);

  const inputClass = "w-full bg-[#1c1b19] border border-[#2e2b26] text-[#fce8c3] text-xs px-2 py-1 focus:outline-none focus:border-[#7fd962]/50";
  const btnClass = "text-xs px-4 py-1 border border-[#FF9F2F] text-[#FF9F2F] bg-[#FF9F2F]/10 hover:bg-[#FF9F2F]/20 shadow-[inset_0_0_18px_rgba(255,159,47,0.5)] hover:shadow-[inset_0_0_28px_rgba(255,159,47,0.7)] disabled:opacity-50 transition-colors shrink-0";

  const selectedScan = expandedScanUuid ? scansData?.data?.find((s) => s.uuid === expandedScanUuid) ?? null : null;
  const historyPage = Math.floor((historyParams.offset || 0) / HISTORY_PAGE_SIZE) + 1;
  const historyTotalPages = Math.ceil((scansData?.total || 0) / HISTORY_PAGE_SIZE);

  return (
    <PageShell>
      {/* NEW SCAN */}
      <div className="border border-[#2e2b26] bg-[#1c1b19]">
        <button
          onClick={() => setScanSectionOpen((v) => !v)}
          className="w-full px-3 py-1.5 border-b border-[#2e2b26] flex items-center gap-1.5 hover:bg-[#272520] transition-colors text-left"
        >
          {scanSectionOpen ? <ChevronDown className="w-3 h-3 text-[#918175]" /> : <ChevronRight className="w-3 h-3 text-[#918175]" />}
          <span className="text-[#7fd962] text-xs font-bold">NEW SCAN</span>
        </button>

        {scanSectionOpen && (
          <div className="p-3 space-y-2">
            {/* Target label with type badge and auto-detect dropdown */}
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-[#fce8c3] text-xs">Target</span>
                <span className="text-[#918175] text-xs">(type: <span style={{ color: MODE_COLORS[detectedMode] }}>{MODE_LABELS[detectedMode].toLowerCase()}</span>)</span>
                <Dropdown
                  value="auto"
                  onChange={() => {}}
                  options={[
                    { value: 'auto', label: 'auto-detect' },
                    ...Object.entries(MODE_LABELS).map(([k, v]) => ({ value: k, label: v.toLowerCase() })),
                  ]}
                />
              </div>
              <textarea
                ref={textareaRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                rows={4}
                placeholder="Paste URL, targets, raw HTTP request, or repo URL..."
                className="w-full bg-[#1c1b19] border border-[#2e2b26] text-[#fce8c3] text-xs px-2 py-1.5 font-mono resize-y focus:outline-none focus:border-[#7fd962]/50 overflow-hidden"
              />
            </div>

            {/* Strategy cards */}
            <div className="grid grid-cols-3 border border-[#2e2b26]">
              {STRATEGIES.map((s) => {
                const meta = STRATEGY_META[s];
                const selected = strategy === s;
                return (
                  <button
                    key={s}
                    onClick={() => setStrategy(s)}
                    className={`py-4 flex flex-col items-center gap-1 transition-colors ${
                      selected
                        ? 'border border-[#7fd962]/60 bg-[#7fd962]/5'
                        : 'border border-transparent hover:bg-[#272520]'
                    }`}
                  >
                    <meta.icon className={`w-5 h-5 ${selected ? 'text-[#7fd962]' : 'text-[#918175]'}`} />
                    <span className={`text-xs font-bold tracking-wider ${selected ? 'text-[#fce8c3]' : 'text-[#918175]'}`}>{meta.label}</span>
                    <span className="text-[10px] text-[#918175]">{meta.desc}</span>
                  </button>
                );
              })}
            </div>

            {/* Submit row */}
            <div className="flex gap-2 items-center flex-wrap">
              <button
                onClick={uploadedRepoPath && !input.trim() ? handleRepoUpload : handleSubmit}
                disabled={(!canSubmit && !uploadedRepoPath) || isSubmitting}
                className={btnClass}
              >
                {isSubmitting ? 'scanning...' : '[SCAN]'}
              </button>
              <button onClick={() => setDryRun(!dryRun)} className={`px-2 py-0.5 text-[10px] border transition-colors ${dryRun ? 'border-[#f2c55c]/50 text-[#f2c55c] bg-[#f2c55c]/10' : 'border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]'}`}>
                DRY_RUN: {dryRun ? 'ON' : 'OFF'}
              </button>
              <button onClick={() => setAdvancedOpen(v => !v)} className="flex items-center gap-1 text-[10px] text-[#918175] hover:text-[#fce8c3] ml-auto">
                {advancedOpen ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />} ADVANCED OPTIONS
              </button>
            </div>

            {/* Advanced options */}
            {advancedOpen && (
              <div className="space-y-2 pl-4 border-l-2 border-[#2e2b26]">
                <div className="flex gap-2 items-center">
                  <button onClick={() => setNoPassive(!noPassive)} className={`px-2 py-0.5 text-[10px] border transition-colors ${noPassive ? 'border-[#ef2f27]/50 text-[#ef2f27] bg-[#ef2f27]/10' : 'border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]'}`}>
                    NO_PASSIVE: {noPassive ? 'ON' : 'OFF'}
                  </button>
                  <button onClick={() => setStoredRecordsOpen(v => !v)} className="flex items-center gap-1 text-[10px] text-[#918175] hover:text-[#fce8c3]">
                    {storedRecordsOpen ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />} STORED RECORDS
                  </button>
                </div>
                <div className="flex gap-2">
                  <div className="flex-1">
                    <label className="text-[#918175] text-[10px] uppercase block mb-0.5">MODULES <span className="normal-case font-normal">(blank = all)</span></label>
                    <input type="text" value={modules} onChange={(e) => setModules(e.target.value)} placeholder="xss_scanner,sqli_error_based" className={inputClass} />
                  </div>
                  <div className="flex-1">
                    <label className="text-[#918175] text-[10px] uppercase block mb-0.5">MODULE_TAGS <span className="normal-case font-normal">(blank = all)</span></label>
                    <input type="text" value={moduleTags} onChange={(e) => setModuleTags(e.target.value)} placeholder="xss,light" className={inputClass} />
                  </div>
                  <div className="flex-1">
                    <label className="text-[#918175] text-[10px] uppercase block mb-0.5">SCANNING_PROFILE</label>
                    <input type="text" value={scanProfile} onChange={(e) => setScanProfile(e.target.value)} placeholder="profile name" className={inputClass} />
                  </div>
                </div>
                <div className="flex gap-2">
                  <div className="w-40">
                    <label className="text-[#918175] text-[10px] uppercase block mb-0.5">ONLY (phase)</label>
                    <Dropdown value={only} onChange={setOnly} options={PHASES.map(p => ({ value: p, label: p || '(all phases)' }))} />
                  </div>
                  <div className="flex-1">
                    <label className="text-[#918175] text-[10px] uppercase block mb-0.5">SKIP (comma-separated)</label>
                    <input type="text" value={skip} onChange={(e) => setSkip(e.target.value)} placeholder="spidering,discovery" className={inputClass} />
                  </div>
                  <div className="w-36">
                    <label className="text-[#918175] text-[10px] uppercase block mb-0.5">SCOPE_ORIGIN</label>
                    <Dropdown value={scopeOrigin} onChange={setScopeOrigin} options={SCOPE_ORIGINS.map(s => ({ value: s, label: s || '(default)' }))} />
                  </div>
                  <div className="w-36">
                    <label className="text-[#918175] text-[10px] uppercase block mb-0.5">HEURISTICS</label>
                    <Dropdown value={heuristics} onChange={setHeuristics} options={HEURISTICS.map(h => ({ value: h, label: h || '(default)' }))} />
                  </div>
                </div>
                <div className="flex gap-2">
                  <div className="flex-1"><label className="text-[#918175] text-[10px] uppercase block mb-0.5">CONCURRENCY</label><input type="number" value={concurrency} onChange={(e) => setConcurrency(e.target.value)} placeholder="10" className={inputClass} /></div>
                  <div className="flex-1"><label className="text-[#918175] text-[10px] uppercase block mb-0.5">TIMEOUT</label><input type="text" value={timeout} onChange={(e) => setTimeout(e.target.value)} placeholder="30s" className={inputClass} /></div>
                  <div className="flex-1"><label className="text-[#918175] text-[10px] uppercase block mb-0.5">MAX_PER_HOST</label><input type="number" value={maxPerHost} onChange={(e) => setMaxPerHost(e.target.value)} placeholder="5" className={inputClass} /></div>
                  <div className="flex-1"><label className="text-[#918175] text-[10px] uppercase block mb-0.5">RATE_LIMIT</label><input type="number" value={rateLimit} onChange={(e) => setRateLimit(e.target.value)} placeholder="100" className={inputClass} /></div>
                  <div className="flex-1"><label className="text-[#918175] text-[10px] uppercase block mb-0.5">MAX_DURATION</label><input type="text" value={maxDuration} onChange={(e) => setMaxDuration(e.target.value)} placeholder="30m" className={inputClass} /></div>
                </div>
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
                {/* Repo upload */}
                <div
                  onDragEnter={onDragEnter} onDragLeave={onDragLeave} onDragOver={onDragOver} onDrop={onDrop}
                  className={`border border-dashed p-3 text-center transition-colors ${rsCompressing || uploadRepo.isPending ? '' : 'cursor-pointer'} ${rsDragging ? 'border-[#7fd962] bg-[#7fd962]/10' : 'border-[#2e2b26] hover:border-[#7fd962]/50'}`}
                  onClick={() => { if (!rsCompressing && !uploadRepo.isPending) fileInputRef.current?.click(); }}
                >
                  <input ref={fileInputRef} type="file" accept=".zip,.tar.gz,.tgz,.tar" onChange={handleFileUpload} className="hidden" />
                  {rsCompressing || uploadRepo.isPending ? (
                    <>
                      <Loader2 className="w-4 h-4 mx-auto mb-1 text-[#7fd962] animate-spin" />
                      <p className="text-xs text-[#fce8c3]">{rsCompressing ? 'Compressing folder...' : 'Uploading...'}</p>
                    </>
                  ) : (
                    <>
                      <Upload className="w-4 h-4 mx-auto mb-1 text-[#7fd962]/70" />
                      <p className="text-xs text-[#fce8c3]">{rsDragging ? 'Drop here to upload' : 'Upload repo archive / folder for SAST'}</p>
                    </>
                  )}
                  <p className="text-[10px] text-[#918175] mt-0.5">.zip, .tar.gz, .tgz, .tar — or drop a folder (auto-zipped) — max 500 MB</p>
                  {uploadRepo.isSuccess && <p className="text-[10px] text-[#98bc37] mt-1">uploaded — repo_path: {uploadedRepoPath}</p>}
                  {uploadRepo.isError && <p className="text-[10px] text-[#ef2f27] mt-1">upload failed: {(uploadRepo.error as Error).message}</p>}
                </div>
              </div>
            )}

            {/* Result display */}
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

            {/* Stored Records */}
            {storedRecordsOpen && (
              <div className="space-y-2 pl-4 border-l-2 border-[#2e2b26]">
                  <div className="flex gap-2">
                    <div className="flex-1"><label className="text-[#918175] text-[10px] uppercase block mb-0.5">HOSTNAME (wildcard: *)</label><input type="text" value={srHostname} onChange={(e) => setSrHostname(e.target.value)} placeholder="*.example.com" className={inputClass} /></div>
                    <div className="flex-1"><label className="text-[#918175] text-[10px] uppercase block mb-0.5">PATH (wildcard: *)</label><input type="text" value={srPath} onChange={(e) => setSrPath(e.target.value)} placeholder="/api/*" className={inputClass} /></div>
                  </div>
                  <div className="flex gap-2 items-end">
                    <div>
                      <label className="text-[#918175] text-[10px] uppercase block mb-0.5">METHODS</label>
                      <div className="flex gap-1">
                        {FILTER_METHODS.map(m => (<button key={m} onClick={() => setSrMethods(prev => prev.includes(m) ? prev.filter(x => x !== m) : [...prev, m])} className={`px-1.5 py-0.5 text-[10px] border transition-colors ${srMethods.includes(m) ? 'border-[#7fd962]/50 text-[#7fd962] bg-[#7fd962]/10' : 'border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]'}`}>{m}</button>))}
                      </div>
                    </div>
                    <div className="flex-1"><label className="text-[#918175] text-[10px] uppercase block mb-0.5">STATUS_CODES</label><input type="text" value={srStatusCodes} onChange={(e) => setSrStatusCodes(e.target.value)} placeholder="200,301,404" className={inputClass} /></div>
                  </div>
                  <div className="flex gap-2">
                    <div className="flex-1"><label className="text-[#918175] text-[10px] uppercase block mb-0.5">SOURCE</label><input type="text" value={srSource} onChange={(e) => setSrSource(e.target.value)} placeholder="proxy, crawler" className={inputClass} /></div>
                    <div className="flex-1"><label className="text-[#918175] text-[10px] uppercase block mb-0.5">SEARCH</label><input type="text" value={srSearch} onChange={(e) => setSrSearch(e.target.value)} placeholder="keyword" className={inputClass} /></div>
                    <div className="w-28"><label className="text-[#918175] text-[10px] uppercase block mb-0.5">MIN_RISK</label><input type="number" value={srMinRisk} onChange={(e) => setSrMinRisk(e.target.value)} placeholder="0" className={inputClass} /></div>
                    <div className="flex-1"><label className="text-[#918175] text-[10px] uppercase block mb-0.5">REMARK</label><input type="text" value={srRemark} onChange={(e) => setSrRemark(e.target.value)} placeholder="filter by remark" className={inputClass} /></div>
                  </div>
                  <div className="flex gap-2 items-center">
                    <button onClick={handleSubmitStoredRecords} disabled={scanAllRecords.isPending} className={btnClass}>{scanAllRecords.isPending ? 'scanning...' : '[SCAN_RECORDS]'}</button>
                    <button onClick={() => setSrForce(!srForce)} className={`px-2 py-0.5 text-[10px] border transition-colors ${srForce ? 'border-[#ef2f27]/50 text-[#ef2f27] bg-[#ef2f27]/10' : 'border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]'}`}>FORCE: {srForce ? 'ON' : 'OFF'}</button>
                  </div>
                  {scanAllRecords.isSuccess && scanAllRecords.data && (
                    <div className="border border-[#2e2b26] p-2 text-xs flex items-center gap-4 flex-wrap">
                      <span className="text-[#7fd962] font-bold">RESULT</span>
                      <span><span className="text-[#918175]">scan_id:</span> <span className="text-[#fce8c3]">{scanAllRecords.data.scan_id}</span></span>
                      <span><span className="text-[#918175]">status:</span> <span className="text-[#fce8c3]">{scanAllRecords.data.status}</span></span>
                      {scanAllRecords.data.records_to_scan != null && <span><span className="text-[#918175]">records:</span> <span className="text-[#fce8c3]">{scanAllRecords.data.records_to_scan}</span></span>}
                      {scanAllRecords.data.message && <span><span className="text-[#918175]">msg:</span> <span className="text-[#fce8c3]">{scanAllRecords.data.message}</span></span>}
                    </div>
                  )}
                  {scanAllRecords.isError && <div className="text-xs text-[#ef2f27]">error: {(scanAllRecords.error as Error).message}</div>}
              </div>
            )}
          </div>
        )}
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
