'use client';

import React, { useState, useRef, useCallback } from 'react';
import { ChevronRight, ChevronDown, Copy, Check, Upload, Loader2 } from 'lucide-react';
import { zipSync } from 'fflate';
import { useScanURL, useScanRequest, useRunScan, useScanAllRecords, useUploadRepo, useScans, useDeleteScan, useStopScan, usePauseScan, useResumeScan, useScanLogs } from '@/api/hooks';
import type { ScanURLRequest, ScanRequestRequest, RunScanRequest, ScanAllRecordsRequest, ScansQueryParams, Scan, ScanLog } from '@/api/types';
import { formatDate } from '@/lib/formatters';
import PageShell from './PageShell';
import Dropdown from './Dropdown';
import GitHubRepoPicker from './GitHubRepoPicker';

type ScanMode = 'full_scan' | 'url' | 'raw_request' | 'repo_scan' | 'stored_records';

const TAB_DEFS: { key: ScanMode; label: string; desc: string }[] = [
  { key: 'full_scan', label: 'FULL SCAN', desc: 'Complete pipeline with discovery, spidering, and audit' },
  { key: 'url', label: 'URL SCAN', desc: 'Target a single URL directly' },
  { key: 'raw_request', label: 'RAW REQUEST', desc: 'Paste or upload a raw HTTP request' },
  { key: 'repo_scan', label: 'REPO SCAN (SAST)', desc: 'Upload or specify a source repository for whitebox analysis' },
  { key: 'stored_records', label: 'STORED RECORDS', desc: 'Scan existing HTTP records in the database' },
];

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const;
const FILTER_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;
const STRATEGIES = ['lite', 'balanced', 'deep', 'whitebox'] as const;
const PHASES = ['', 'discovery', 'spidering', 'audit'] as const;
const SCOPE_ORIGINS = ['', 'all', 'relaxed', 'balanced', 'strict'] as const;
const HEURISTICS = ['', 'none', 'basic', 'advanced'] as const;
const HISTORY_PAGE_SIZE = 20;

interface HeaderRow {
  key: string;
  value: string;
}

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
          <span><span className="text-[#708e8e]">findings:</span> <span style={{ color: scan.total_findings > 0 ? '#b58900' : '#708e8e' }}>{scan.total_findings}</span></span>
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
            <textarea readOnly rows={3} value={scan.modules} className="mt-0.5 w-full bg-[#ede4d1] border border-[#bbc3c4] text-[#005661] text-xs p-1.5 resize-none focus:outline-none" />
          </div>
        )}
      </div>
      <div className="px-3 py-1.5 border-b border-[#bbc3c4] shrink-0">
        <span className="text-[#0078c8] text-xs font-bold">LOGS</span>
        <span className="text-[#bbc3c4] text-[10px] ml-2">{logs.length} entries</span>
      </div>
      <div className="bg-[#eee8d5] overflow-y-auto font-mono text-[11px] leading-relaxed flex-1 min-h-0">
        {logs.length === 0 ? (
          <div className="px-3 py-2 text-[#bbc3c4]">no logs</div>
        ) : (
          logs.map((log: ScanLog) => (
            <div key={log.id} className="px-3 py-0.5 hover:bg-[#f6edda] flex gap-2">
              <span className="text-[#8a9394] shrink-0">{new Date(log.created_at).toLocaleTimeString()}</span>
              <span className="shrink-0 uppercase font-bold" style={{ color: levelColor(log.level) }}>{log.level.padEnd(5)}</span>
              {log.phase && <span className="text-[#00b368] shrink-0">[{log.phase}]</span>}
              <span className="text-[#00404d]">{log.message}</span>
              {log.metadata && <span className="text-[#8a9394]">{log.metadata}</span>}
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

export default function ScanPage() {
  const [mode, setMode] = useState<ScanMode>('full_scan');
  const [scanSectionOpen, setScanSectionOpen] = useState(true);

  // Full scan state
  const [fsTargets, setFsTargets] = useState('');
  const [fsStrategy, setFsStrategy] = useState('balanced');
  const [fsOnly, setFsOnly] = useState('');
  const [fsSkip, setFsSkip] = useState('');
  const [fsModules, setFsModules] = useState('');
  const [fsModuleTags, setFsModuleTags] = useState('');
  const [fsRepoPath, setFsRepoPath] = useState('');
  const [fsRepoUrl, setFsRepoUrl] = useState('');
  const [fsDryRun, setFsDryRun] = useState(false);
  const [fsAdvancedOpen, setFsAdvancedOpen] = useState(false);
  const [fsConcurrency, setFsConcurrency] = useState('');
  const [fsTimeout, setFsTimeout] = useState('');
  const [fsMaxPerHost, setFsMaxPerHost] = useState('');
  const [fsRateLimit, setFsRateLimit] = useState('');
  const [fsMaxDuration, setFsMaxDuration] = useState('');
  const [fsScopeOrigin, setFsScopeOrigin] = useState('');
  const [fsHeuristics, setFsHeuristics] = useState('');
  const [fsScanProfile, setFsScanProfile] = useState('');
  const [fsHeaders, setFsHeaders] = useState<HeaderRow[]>([{ key: '', value: '' }]);

  // URL mode state
  const [url, setUrl] = useState('');
  const [method, setMethod] = useState('GET');
  const [body, setBody] = useState('');
  const [headers, setHeaders] = useState<HeaderRow[]>([{ key: '', value: '' }]);
  const [urlModules, setUrlModules] = useState('');
  const [urlNoPassive, setUrlNoPassive] = useState(false);

  // Raw request mode state
  const [rawRequest, setRawRequest] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [rawModules, setRawModules] = useState('');
  const [rawNoPassive, setRawNoPassive] = useState(false);

  // Repo scan state
  const [rsRepoPath, setRsRepoPath] = useState('');
  const [rsRepoUrl, setRsRepoUrl] = useState('');
  const [rsTargets, setRsTargets] = useState('');
  const [rsStrategy, setRsStrategy] = useState('whitebox');
  const [rsModules, setRsModules] = useState('');
  const [rsModuleTags, setRsModuleTags] = useState('');
  const [rsDryRun, setRsDryRun] = useState(false);
  const [rsAdvancedOpen, setRsAdvancedOpen] = useState(false);
  const [rsConcurrency, setRsConcurrency] = useState('');
  const [rsTimeout, setRsTimeout] = useState('');
  const [rsMaxPerHost, setRsMaxPerHost] = useState('');
  const [rsRateLimit, setRsRateLimit] = useState('');
  const [rsMaxDuration, setRsMaxDuration] = useState('');
  const [rsHeuristics, setRsHeuristics] = useState('');
  const [rsScanProfile, setRsScanProfile] = useState('');
  const [rsHeaders, setRsHeaders] = useState<HeaderRow[]>([{ key: '', value: '' }]);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [rsDragging, setRsDragging] = useState(false);
  const [rsCompressing, setRsCompressing] = useState(false);
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
  const [srDryRun, setSrDryRun] = useState(false);
  const [srAdvancedOpen, setSrAdvancedOpen] = useState(false);
  const [srModules, setSrModules] = useState('');
  const [srModuleTags, setSrModuleTags] = useState('');
  const [srConcurrency, setSrConcurrency] = useState('');
  const [srTimeout, setSrTimeout] = useState('');
  const [srMaxPerHost, setSrMaxPerHost] = useState('');
  const [srRateLimit, setSrRateLimit] = useState('');
  const [srMaxDuration, setSrMaxDuration] = useState('');
  const [srHeuristics, setSrHeuristics] = useState('');
  const [srScanProfile, setSrScanProfile] = useState('');
  const [srHeaders, setSrHeaders] = useState<HeaderRow[]>([{ key: '', value: '' }]);

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

  const addHeader = () => setHeaders((prev) => [...prev, { key: '', value: '' }]);
  const removeHeader = (i: number) => setHeaders((prev) => prev.filter((_, idx) => idx !== i));
  const updateHeader = (i: number, field: 'key' | 'value', val: string) =>
    setHeaders((prev) => prev.map((h, idx) => (idx === i ? { ...h, [field]: val } : h)));

  const addFsHeader = () => setFsHeaders((prev) => [...prev, { key: '', value: '' }]);
  const removeFsHeader = (i: number) => setFsHeaders((prev) => prev.filter((_, idx) => idx !== i));
  const updateFsHeader = (i: number, field: 'key' | 'value', val: string) =>
    setFsHeaders((prev) => prev.map((h, idx) => (idx === i ? { ...h, [field]: val } : h)));

  const addRsHeader = () => setRsHeaders((prev) => [...prev, { key: '', value: '' }]);
  const removeRsHeader = (i: number) => setRsHeaders((prev) => prev.filter((_, idx) => idx !== i));
  const updateRsHeader = (i: number, field: 'key' | 'value', val: string) =>
    setRsHeaders((prev) => prev.map((h, idx) => (idx === i ? { ...h, [field]: val } : h)));

  const addSrHeader = () => setSrHeaders((prev) => [...prev, { key: '', value: '' }]);
  const removeSrHeader = (i: number) => setSrHeaders((prev) => prev.filter((_, idx) => idx !== i));
  const updateSrHeader = (i: number, field: 'key' | 'value', val: string) =>
    setSrHeaders((prev) => prev.map((h, idx) => (idx === i ? { ...h, [field]: val } : h)));

  function buildHeadersObj(rows: HeaderRow[]): Record<string, string> | undefined {
    const obj: Record<string, string> = {};
    for (const h of rows) {
      if (h.key.trim()) obj[h.key.trim()] = h.value;
    }
    return Object.keys(obj).length > 0 ? obj : undefined;
  }

  const handleSubmitFullScan = () => {
    const targets = fsTargets.split('\n').map(s => s.trim()).filter(Boolean);
    const req: RunScanRequest = {};
    if (targets.length > 0) req.targets = targets;
    if (fsStrategy) req.strategy = fsStrategy;
    if (fsOnly) req.only = fsOnly;
    if (fsSkip) req.skip = fsSkip.split(',').map(s => s.trim()).filter(Boolean);
    if (fsModules) req.modules = fsModules.split(',').map(s => s.trim()).filter(Boolean);
    if (fsModuleTags) req.module_tags = fsModuleTags.split(',').map(s => s.trim()).filter(Boolean);
    if (fsRepoPath) req.repo_path = fsRepoPath;
    if (fsRepoUrl) req.repo_url = fsRepoUrl;
    if (fsDryRun) req.dry_run = true;
    if (fsConcurrency) req.concurrency = parseInt(fsConcurrency);
    if (fsTimeout) req.timeout = fsTimeout;
    if (fsMaxPerHost) req.max_per_host = parseInt(fsMaxPerHost);
    if (fsRateLimit) req.rate_limit = parseInt(fsRateLimit);
    if (fsMaxDuration) req.scanning_max_duration = fsMaxDuration;
    if (fsScopeOrigin) req.scope_origin = fsScopeOrigin;
    if (fsHeuristics) req.heuristics_check = fsHeuristics;
    if (fsScanProfile) req.scanning_profile = fsScanProfile;
    req.headers = buildHeadersObj(fsHeaders);
    runScan.mutate(req);
  };

  const handleSubmitURL = () => {
    const req: ScanURLRequest = { url };
    if (method !== 'GET') req.method = method;
    if (body) req.body = body;
    req.headers = buildHeadersObj(headers);
    if (urlModules) req.modules = urlModules;
    if (urlNoPassive) req.no_passive = true;
    scanURL.mutate(req);
  };

  const handleSubmitRaw = () => {
    let encoded = rawRequest;
    try {
      atob(rawRequest);
    } catch {
      encoded = btoa(rawRequest);
    }
    const req: ScanRequestRequest = { raw_request: encoded };
    if (targetUrl) req.target_url = targetUrl;
    if (rawModules) req.modules = rawModules;
    if (rawNoPassive) req.no_passive = true;
    scanRequest.mutate(req);
  };

  const handleSubmitRepoScan = () => {
    const req: RunScanRequest = {};
    const targets = rsTargets.split('\n').map(s => s.trim()).filter(Boolean);
    if (targets.length > 0) req.targets = targets;
    if (rsRepoPath) req.repo_path = rsRepoPath;
    if (rsRepoUrl) req.repo_url = rsRepoUrl;
    if (rsStrategy) req.strategy = rsStrategy;
    if (rsModules) req.modules = rsModules.split(',').map(s => s.trim()).filter(Boolean);
    if (rsModuleTags) req.module_tags = rsModuleTags.split(',').map(s => s.trim()).filter(Boolean);
    if (rsDryRun) req.dry_run = true;
    if (rsConcurrency) req.concurrency = parseInt(rsConcurrency);
    if (rsTimeout) req.timeout = rsTimeout;
    if (rsMaxPerHost) req.max_per_host = parseInt(rsMaxPerHost);
    if (rsRateLimit) req.rate_limit = parseInt(rsRateLimit);
    if (rsMaxDuration) req.scanning_max_duration = rsMaxDuration;
    if (rsHeuristics) req.heuristics_check = rsHeuristics;
    if (rsScanProfile) req.scanning_profile = rsScanProfile;
    req.headers = buildHeadersObj(rsHeaders);
    runScan.mutate(req);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    doUpload(file);
    e.target.value = '';
  };

  const doUpload = useCallback((file: File) => {
    uploadRepo.mutate(file, {
      onSuccess: (data) => { setRsRepoPath(data.repo_path); },
    });
  }, [uploadRepo]);

  // Recursively read all files from a dropped directory entry
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
            readBatch(); // readEntries may return partial results
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

    // Single archive file dropped
    if (entries.length === 1 && entries[0].isFile) {
      const item = items[0];
      const file = item.getAsFile();
      if (file && /\.(zip|tar|tar\.gz|tgz)$/i.test(file.name)) {
        doUpload(file);
        return;
      }
    }

    // Folder(s) or non-archive files dropped — zip them
    setRsCompressing(true);
    try {
      const allFiles: { path: string; file: File }[] = [];
      for (const entry of entries) {
        allFiles.push(...await readEntryRecursive(entry));
      }
      if (allFiles.length === 0) { setRsCompressing(false); return; }

      // Build fflate zip structure
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
    if (srDryRun) req.dry_run = true;
    if (srModules) req.modules = srModules.split(',').map(s => s.trim()).filter(Boolean);
    if (srModuleTags) req.module_tags = srModuleTags.split(',').map(s => s.trim()).filter(Boolean);
    if (srConcurrency) req.concurrency = parseInt(srConcurrency);
    if (srTimeout) req.timeout = srTimeout;
    if (srMaxPerHost) req.max_per_host = parseInt(srMaxPerHost);
    if (srRateLimit) req.rate_limit = parseInt(srRateLimit);
    if (srMaxDuration) req.scanning_max_duration = srMaxDuration;
    if (srHeuristics) req.heuristics_check = srHeuristics;
    if (srScanProfile) req.scanning_profile = srScanProfile;
    req.headers = buildHeadersObj(srHeaders);
    scanAllRecords.mutate(req);
  };

  const mutation =
    mode === 'full_scan' ? runScan :
    mode === 'url' ? scanURL :
    mode === 'raw_request' ? scanRequest :
    mode === 'repo_scan' ? runScan :
    scanAllRecords;

  const inputClass = "w-full bg-[#f6edda] border border-[#bbc3c4] text-[#005661] text-xs px-2 py-1 focus:outline-none focus:border-[#0078c8]/50";
  const textareaClass = `${inputClass} font-mono resize-y`;
  const btnClass = "text-xs px-4 py-1 border border-[#FF8C00] text-[#FF8C00] bg-[#FF8C00]/10 hover:bg-[#FF8C00]/20 shadow-[inset_0_0_18px_rgba(255,140,0,0.5)] hover:shadow-[inset_0_0_28px_rgba(255,140,0,0.7)] disabled:opacity-50 transition-colors shrink-0";

  const selectedScan = expandedScanUuid ? scansData?.data?.find((s) => s.uuid === expandedScanUuid) ?? null : null;
  const historyPage = Math.floor((historyParams.offset || 0) / HISTORY_PAGE_SIZE) + 1;
  const historyTotalPages = Math.ceil((scansData?.total || 0) / HISTORY_PAGE_SIZE);

  const fsCanSubmit = fsTargets.trim() || fsRepoPath || fsRepoUrl;
  const rsCanSubmit = rsRepoPath || rsRepoUrl;

  return (
    <PageShell>
      {/* NEW SCAN — collapsible */}
      <div className="border border-[#bbc3c4] bg-[#f6edda]">
        <button
          onClick={() => setScanSectionOpen((v) => !v)}
          className="w-full px-3 py-1.5 border-b border-[#bbc3c4] flex items-center gap-1.5 hover:bg-[#ede4d1] transition-colors text-left"
        >
          {scanSectionOpen ? <ChevronDown className="w-3 h-3 text-[#708e8e]" /> : <ChevronRight className="w-3 h-3 text-[#708e8e]" />}
          <span className="text-[#0078c8] text-xs font-bold">NEW SCAN</span>
        </button>

        {scanSectionOpen && (
          <div className="p-3 space-y-2">
            {/* Mode tabs */}
            <div>
              <div className="flex items-center gap-1">
                <span className="text-[#708e8e] text-[10px] uppercase mr-1">MODE</span>
                {TAB_DEFS.map((t) => (
                  <button
                    key={t.key}
                    onClick={() => setMode(t.key)}
                    className={`px-2 py-0.5 text-xs border transition-colors ${
                      mode === t.key
                        ? 'border-[#0078c8]/50 text-[#0078c8] bg-[#0078c8]/10'
                        : 'border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]'
                    }`}
                  >
                    {t.label}
                  </button>
                ))}
              </div>
              <div className="text-[10px] text-[#708e8e] italic mt-1 ml-10">
                {TAB_DEFS.find(t => t.key === mode)?.desc}
              </div>
            </div>

            {/* ===== FULL SCAN ===== */}
            {mode === 'full_scan' && (
              <>
                <div>
                  <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">TARGETS (one URL per line)</label>
                  <textarea value={fsTargets} onChange={(e) => setFsTargets(e.target.value)} rows={3} placeholder={"https://example.com\nhttps://api.example.com"} className={textareaClass} />
                </div>

                <div className="flex gap-2">
                  <div className="w-40">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">STRATEGY</label>
                    <Dropdown value={fsStrategy} onChange={setFsStrategy} options={STRATEGIES.map(s => ({ value: s, label: s }))} />
                  </div>
                  <div className="w-48">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">ONLY (phase)</label>
                    <Dropdown value={fsOnly} onChange={setFsOnly} options={PHASES.map(p => ({ value: p, label: p || '(all phases)' }))} />
                  </div>
                  <div className="w-36">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">SCOPE_ORIGIN</label>
                    <Dropdown value={fsScopeOrigin} onChange={setFsScopeOrigin} options={SCOPE_ORIGINS.map(s => ({ value: s, label: s || '(default)' }))} />
                  </div>
                  <div className="w-36">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">HEURISTICS</label>
                    <Dropdown value={fsHeuristics} onChange={setFsHeuristics} options={HEURISTICS.map(h => ({ value: h, label: h || '(default)' }))} />
                  </div>
                </div>
                <div className="flex gap-2">
                  <div className="flex-1">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">SKIP (comma-separated)</label>
                    <input type="text" value={fsSkip} onChange={(e) => setFsSkip(e.target.value)} placeholder="spidering,discovery" className={inputClass} />
                  </div>
                  <div className="flex-1">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">MODULES <span className="normal-case font-normal">(blank = all)</span></label>
                    <input type="text" value={fsModules} onChange={(e) => setFsModules(e.target.value)} placeholder="xss_scanner,sqli_error_based" className={inputClass} />
                  </div>
                  <div className="flex-1">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">MODULE_TAGS <span className="normal-case font-normal">(blank = all)</span></label>
                    <input type="text" value={fsModuleTags} onChange={(e) => setFsModuleTags(e.target.value)} placeholder="xss,light" className={inputClass} />
                  </div>
                  <div className="flex-1">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">SCANNING_PROFILE</label>
                    <input type="text" value={fsScanProfile} onChange={(e) => setFsScanProfile(e.target.value)} placeholder="profile name" className={inputClass} />
                  </div>
                </div>

                {/* Advanced options */}
                <button onClick={() => setFsAdvancedOpen(v => !v)} className="flex items-center gap-1 text-[10px] text-[#708e8e] hover:text-[#005661]">
                  {fsAdvancedOpen ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                  ADVANCED OPTIONS
                </button>
                {fsAdvancedOpen && (
                  <div className="space-y-2 pl-4 border-l-2 border-[#bbc3c4]">
                    <div>
                      <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">GITHUB REPO</label>
                      <GitHubRepoPicker onSelect={(url) => { setFsRepoUrl(url); setFsRepoPath(''); }} selectedRepo={fsRepoUrl.includes('x-access-token') ? fsRepoUrl.replace(/https:\/\/x-access-token:[^@]+@github\.com\//, '').replace('.git', '') : undefined} />
                    </div>
                    <div className="flex gap-2">
                      <div className="flex-1">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">REPO_PATH (local path)</label>
                        <input type="text" value={fsRepoPath} onChange={(e) => { setFsRepoPath(e.target.value); if (e.target.value) setFsRepoUrl(''); }} placeholder="/path/to/repo" className={inputClass} />
                      </div>
                      <div className="flex-1">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">REPO_URL (git URL)</label>
                        <input type="text" value={fsRepoUrl} onChange={(e) => { setFsRepoUrl(e.target.value); if (e.target.value) setFsRepoPath(''); }} placeholder="https://github.com/org/repo" className={inputClass} />
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <div className="flex-1">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">CONCURRENCY</label>
                        <input type="number" value={fsConcurrency} onChange={(e) => setFsConcurrency(e.target.value)} placeholder="10" className={inputClass} />
                      </div>
                      <div className="flex-1">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">TIMEOUT</label>
                        <input type="text" value={fsTimeout} onChange={(e) => setFsTimeout(e.target.value)} placeholder="30s" className={inputClass} />
                      </div>
                      <div className="flex-1">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">MAX_PER_HOST</label>
                        <input type="number" value={fsMaxPerHost} onChange={(e) => setFsMaxPerHost(e.target.value)} placeholder="5" className={inputClass} />
                      </div>
                      <div className="flex-1">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">RATE_LIMIT</label>
                        <input type="number" value={fsRateLimit} onChange={(e) => setFsRateLimit(e.target.value)} placeholder="100" className={inputClass} />
                      </div>
                      <div className="flex-1">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">MAX_DURATION</label>
                        <input type="text" value={fsMaxDuration} onChange={(e) => setFsMaxDuration(e.target.value)} placeholder="30m" className={inputClass} />
                      </div>
                    </div>
                    <div>
                      <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">HEADERS</label>
                      <div className="space-y-1">
                        {fsHeaders.map((h, i) => (
                          <div key={i} className="flex gap-1 items-center">
                            <input type="text" value={h.key} onChange={(e) => updateFsHeader(i, 'key', e.target.value)} placeholder="Header-Name" className={`${inputClass} flex-1`} />
                            <input type="text" value={h.value} onChange={(e) => updateFsHeader(i, 'value', e.target.value)} placeholder="value" className={`${inputClass} flex-1`} />
                            <button onClick={() => removeFsHeader(i)} className="text-[#708e8e] hover:text-[#e34e1c] text-xs px-1">x</button>
                          </div>
                        ))}
                        <button onClick={addFsHeader} className="text-xs text-[#708e8e] hover:text-[#0078c8]">[+ header]</button>
                      </div>
                    </div>
                  </div>
                )}

                <div className="flex gap-2 items-center">
                  <button onClick={handleSubmitFullScan} disabled={!fsCanSubmit || runScan.isPending} className={btnClass}>
                    {runScan.isPending ? 'scanning...' : '[RUN_SCAN]'}
                  </button>
                  <button onClick={() => setFsDryRun(!fsDryRun)} className={`px-2 py-1 text-xs border transition-colors shrink-0 ${fsDryRun ? 'border-[#b8860b]/50 text-[#b8860b] bg-[#b8860b]/10' : 'border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]'}`}>
                    DRY_RUN: {fsDryRun ? 'ON' : 'OFF'}
                  </button>
                </div>
              </>
            )}

            {/* ===== URL SCAN ===== */}
            {mode === 'url' && (
              <>
                <div className="flex gap-2 items-end">
                  <div className="flex-1">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">URL *</label>
                    <input type="text" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com/api/endpoint" className={inputClass} />
                  </div>
                  <div className="w-28">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">METHOD</label>
                    <Dropdown value={method} onChange={setMethod} options={METHODS.map(m => ({ value: m, label: m }))} />
                  </div>
                </div>
                <div>
                  <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">BODY (optional)</label>
                  <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={2} placeholder='{"key": "value"}' className={textareaClass} />
                </div>
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
                <div className="flex gap-2 items-end">
                  <button onClick={handleSubmitURL} disabled={!url || scanURL.isPending} className={btnClass}>
                    {scanURL.isPending ? 'scanning...' : '[SCAN_URL]'}
                  </button>
                  <button onClick={() => setUrlNoPassive(!urlNoPassive)} className={`px-2 py-1 text-xs border transition-colors shrink-0 ${urlNoPassive ? 'border-[#e34e1c]/50 text-[#e34e1c] bg-[#e34e1c]/10' : 'border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]'}`}>
                    NO_PASSIVE: {urlNoPassive ? 'ON' : 'OFF'}
                  </button>
                  <div className="flex-1">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">MODULES <span className="normal-case font-normal">(blank = all)</span></label>
                    <input type="text" value={urlModules} onChange={(e) => setUrlModules(e.target.value)} placeholder="xss_scanner,sqli_error_based" className={inputClass} />
                  </div>
                </div>
              </>
            )}

            {/* ===== RAW REQUEST ===== */}
            {mode === 'raw_request' && (
              <>
                <div>
                  <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">RAW_REQUEST (paste plain text — auto base64-encoded on submit) *</label>
                  <textarea value={rawRequest} onChange={(e) => setRawRequest(e.target.value)} rows={6} placeholder={"GET /path HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\n..."} className={textareaClass} />
                </div>
                <div>
                  <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">TARGET_URL (optional)</label>
                  <input type="text" value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)} placeholder="https://example.com" className={inputClass} />
                </div>
                <div className="flex gap-2 items-end">
                  <button onClick={handleSubmitRaw} disabled={!rawRequest || scanRequest.isPending} className={btnClass}>
                    {scanRequest.isPending ? 'scanning...' : '[SCAN_REQUEST]'}
                  </button>
                  <button onClick={() => setRawNoPassive(!rawNoPassive)} className={`px-2 py-1 text-xs border transition-colors shrink-0 ${rawNoPassive ? 'border-[#e34e1c]/50 text-[#e34e1c] bg-[#e34e1c]/10' : 'border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]'}`}>
                    NO_PASSIVE: {rawNoPassive ? 'ON' : 'OFF'}
                  </button>
                  <div className="flex-1">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">MODULES <span className="normal-case font-normal">(blank = all)</span></label>
                    <input type="text" value={rawModules} onChange={(e) => setRawModules(e.target.value)} placeholder="xss_scanner,sqli_error_based" className={inputClass} />
                  </div>
                </div>
              </>
            )}

            {/* ===== REPO SCAN (SAST) ===== */}
            {mode === 'repo_scan' && (
              <>
                {/* Upload / drag-and-drop section */}
                <div
                  onDragEnter={onDragEnter} onDragLeave={onDragLeave} onDragOver={onDragOver} onDrop={onDrop}
                  className={`border border-dashed p-4 text-center transition-colors ${rsCompressing || uploadRepo.isPending ? '' : 'cursor-pointer'} ${rsDragging ? 'border-[#0078c8] bg-[#0078c8]/10' : 'border-[#bbc3c4] hover:border-[#0078c8]/50'}`}
                  onClick={() => { if (!rsCompressing && !uploadRepo.isPending) fileInputRef.current?.click(); }}
                >
                  <input ref={fileInputRef} type="file" accept=".zip,.tar.gz,.tgz,.tar" onChange={handleFileUpload} className="hidden" />
                  {rsCompressing || uploadRepo.isPending ? (
                    <>
                      <Loader2 className="w-5 h-5 mx-auto mb-1.5 text-[#0078c8] animate-spin" />
                      <p className="text-xs text-[#005661]">{rsCompressing ? 'Compressing folder...' : 'Uploading...'}</p>
                    </>
                  ) : (
                    <>
                      <Upload className="w-5 h-5 mx-auto mb-1.5 text-[#0078c8]/70" />
                      <p className="text-xs text-[#005661]">
                        {rsDragging ? 'Drop here to upload' : 'Click or drag & drop archive or folder'}
                      </p>
                    </>
                  )}
                  <p className="text-[10px] text-[#708e8e] mt-1">.zip, .tar.gz, .tgz, .tar — or drop a folder (auto-zipped) — max 500 MB</p>
                  {uploadRepo.isSuccess && (
                    <p className="text-[10px] text-[#00b368] mt-1">uploaded — repo_path set</p>
                  )}
                  {uploadRepo.isError && (
                    <p className="text-[10px] text-[#e34e1c] mt-1">upload failed: {(uploadRepo.error as Error).message}</p>
                  )}
                </div>

                <div>
                  <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">GITHUB REPO</label>
                  <GitHubRepoPicker onSelect={(url) => { setRsRepoUrl(url); setRsRepoPath(''); }} selectedRepo={rsRepoUrl.includes('x-access-token') ? rsRepoUrl.replace(/https:\/\/x-access-token:[^@]+@github\.com\//, '').replace('.git', '') : undefined} />
                </div>
                <div className="flex gap-2">
                  <div className="flex-1">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">REPO_PATH (local path or uploaded)</label>
                    <input type="text" value={rsRepoPath} onChange={(e) => { setRsRepoPath(e.target.value); if (e.target.value) setRsRepoUrl(''); }} placeholder="/path/to/repo" className={inputClass} />
                  </div>
                  <div className="flex-1">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">REPO_URL (git URL)</label>
                    <input type="text" value={rsRepoUrl} onChange={(e) => { setRsRepoUrl(e.target.value); if (e.target.value) setRsRepoPath(''); }} placeholder="https://github.com/org/repo" className={inputClass} />
                  </div>
                </div>

                <div>
                  <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">TARGETS (optional — URLs to correlate with source, one per line)</label>
                  <textarea value={rsTargets} onChange={(e) => setRsTargets(e.target.value)} rows={2} placeholder={"https://example.com"} className={textareaClass} />
                </div>

                <div className="flex gap-2">
                  <div className="w-40">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">STRATEGY</label>
                    <Dropdown value={rsStrategy} onChange={setRsStrategy} options={STRATEGIES.map(s => ({ value: s, label: s }))} />
                  </div>
                  <div className="flex-1">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">MODULES <span className="normal-case font-normal">(blank = all)</span></label>
                    <input type="text" value={rsModules} onChange={(e) => setRsModules(e.target.value)} placeholder="xss_scanner,sqli_error_based" className={inputClass} />
                  </div>
                  <div className="flex-1">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">MODULE_TAGS <span className="normal-case font-normal">(blank = all)</span></label>
                    <input type="text" value={rsModuleTags} onChange={(e) => setRsModuleTags(e.target.value)} placeholder="sast,light" className={inputClass} />
                  </div>
                </div>

                {/* Advanced options */}
                <button onClick={() => setRsAdvancedOpen(v => !v)} className="flex items-center gap-1 text-[10px] text-[#708e8e] hover:text-[#005661]">
                  {rsAdvancedOpen ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                  ADVANCED OPTIONS
                </button>
                {rsAdvancedOpen && (
                  <div className="space-y-2 pl-4 border-l-2 border-[#bbc3c4]">
                    <div className="flex gap-2">
                      <div className="w-28">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">CONCURRENCY</label>
                        <input type="number" value={rsConcurrency} onChange={(e) => setRsConcurrency(e.target.value)} placeholder="10" className={inputClass} />
                      </div>
                      <div className="w-28">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">TIMEOUT</label>
                        <input type="text" value={rsTimeout} onChange={(e) => setRsTimeout(e.target.value)} placeholder="30s" className={inputClass} />
                      </div>
                      <div className="w-28">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">MAX_PER_HOST</label>
                        <input type="number" value={rsMaxPerHost} onChange={(e) => setRsMaxPerHost(e.target.value)} placeholder="5" className={inputClass} />
                      </div>
                      <div className="w-28">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">RATE_LIMIT</label>
                        <input type="number" value={rsRateLimit} onChange={(e) => setRsRateLimit(e.target.value)} placeholder="100" className={inputClass} />
                      </div>
                      <div className="w-36">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">MAX_DURATION</label>
                        <input type="text" value={rsMaxDuration} onChange={(e) => setRsMaxDuration(e.target.value)} placeholder="30m" className={inputClass} />
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <div className="w-36">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">HEURISTICS</label>
                        <Dropdown value={rsHeuristics} onChange={setRsHeuristics} options={HEURISTICS.map(h => ({ value: h, label: h || '(default)' }))} />
                      </div>
                      <div className="flex-1">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">SCANNING_PROFILE</label>
                        <input type="text" value={rsScanProfile} onChange={(e) => setRsScanProfile(e.target.value)} placeholder="profile name" className={inputClass} />
                      </div>
                    </div>
                    <div>
                      <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">HEADERS</label>
                      <div className="space-y-1">
                        {rsHeaders.map((h, i) => (
                          <div key={i} className="flex gap-1 items-center">
                            <input type="text" value={h.key} onChange={(e) => updateRsHeader(i, 'key', e.target.value)} placeholder="Header-Name" className={`${inputClass} flex-1`} />
                            <input type="text" value={h.value} onChange={(e) => updateRsHeader(i, 'value', e.target.value)} placeholder="value" className={`${inputClass} flex-1`} />
                            <button onClick={() => removeRsHeader(i)} className="text-[#708e8e] hover:text-[#e34e1c] text-xs px-1">x</button>
                          </div>
                        ))}
                        <button onClick={addRsHeader} className="text-xs text-[#708e8e] hover:text-[#0078c8]">[+ header]</button>
                      </div>
                    </div>
                  </div>
                )}

                <div className="flex gap-2 items-center">
                  <button onClick={handleSubmitRepoScan} disabled={!rsCanSubmit || runScan.isPending} className={btnClass}>
                    {runScan.isPending ? 'scanning...' : '[RUN_SCAN]'}
                  </button>
                  <button onClick={() => setRsDryRun(!rsDryRun)} className={`px-2 py-1 text-xs border transition-colors shrink-0 ${rsDryRun ? 'border-[#b8860b]/50 text-[#b8860b] bg-[#b8860b]/10' : 'border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]'}`}>
                    DRY_RUN: {rsDryRun ? 'ON' : 'OFF'}
                  </button>
                </div>
              </>
            )}

            {/* ===== STORED RECORDS ===== */}
            {mode === 'stored_records' && (
              <>
                <div className="flex gap-2">
                  <div className="flex-1">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">HOSTNAME (wildcard: *)</label>
                    <input type="text" value={srHostname} onChange={(e) => setSrHostname(e.target.value)} placeholder="*.example.com" className={inputClass} />
                  </div>
                  <div className="flex-1">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">PATH (wildcard: *)</label>
                    <input type="text" value={srPath} onChange={(e) => setSrPath(e.target.value)} placeholder="/api/*" className={inputClass} />
                  </div>
                </div>
                <div className="flex gap-2 items-end">
                  <div>
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">METHODS</label>
                    <div className="flex gap-1">
                      {FILTER_METHODS.map(m => (
                        <button key={m} onClick={() => setSrMethods(prev => prev.includes(m) ? prev.filter(x => x !== m) : [...prev, m])} className={`px-1.5 py-0.5 text-[10px] border transition-colors ${srMethods.includes(m) ? 'border-[#0078c8]/50 text-[#0078c8] bg-[#0078c8]/10' : 'border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]'}`}>{m}</button>
                      ))}
                    </div>
                  </div>
                  <div className="flex-1">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">STATUS_CODES (comma-separated)</label>
                    <input type="text" value={srStatusCodes} onChange={(e) => setSrStatusCodes(e.target.value)} placeholder="200,301,404" className={inputClass} />
                  </div>
                </div>
                <div className="flex gap-2">
                  <div className="flex-1">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">SOURCE</label>
                    <input type="text" value={srSource} onChange={(e) => setSrSource(e.target.value)} placeholder="proxy, crawler" className={inputClass} />
                  </div>
                  <div className="flex-1">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">SEARCH</label>
                    <input type="text" value={srSearch} onChange={(e) => setSrSearch(e.target.value)} placeholder="keyword" className={inputClass} />
                  </div>
                </div>
                <div className="flex gap-2">
                  <div className="w-36">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">MIN_RISK_SCORE</label>
                    <input type="number" value={srMinRisk} onChange={(e) => setSrMinRisk(e.target.value)} placeholder="0" className={inputClass} />
                  </div>
                  <div className="flex-1">
                    <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">REMARK</label>
                    <input type="text" value={srRemark} onChange={(e) => setSrRemark(e.target.value)} placeholder="filter by remark" className={inputClass} />
                  </div>
                </div>
                <button onClick={() => setSrAdvancedOpen(v => !v)} className="flex items-center gap-1 text-[10px] text-[#708e8e] hover:text-[#005661]">
                  {srAdvancedOpen ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                  SCAN OPTIONS
                </button>
                {srAdvancedOpen && (
                  <div className="space-y-2 pl-4 border-l-2 border-[#bbc3c4]">
                    <div className="flex gap-2">
                      <div className="flex-1">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">MODULES <span className="normal-case font-normal">(blank = all)</span></label>
                        <input type="text" value={srModules} onChange={(e) => setSrModules(e.target.value)} placeholder="xss_scanner,sqli_error_based" className={inputClass} />
                      </div>
                      <div className="flex-1">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">MODULE_TAGS <span className="normal-case font-normal">(blank = all)</span></label>
                        <input type="text" value={srModuleTags} onChange={(e) => setSrModuleTags(e.target.value)} placeholder="xss,light" className={inputClass} />
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <div className="w-28">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">CONCURRENCY</label>
                        <input type="number" value={srConcurrency} onChange={(e) => setSrConcurrency(e.target.value)} placeholder="10" className={inputClass} />
                      </div>
                      <div className="w-28">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">TIMEOUT</label>
                        <input type="text" value={srTimeout} onChange={(e) => setSrTimeout(e.target.value)} placeholder="30s" className={inputClass} />
                      </div>
                      <div className="w-28">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">MAX_PER_HOST</label>
                        <input type="number" value={srMaxPerHost} onChange={(e) => setSrMaxPerHost(e.target.value)} placeholder="5" className={inputClass} />
                      </div>
                      <div className="w-28">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">RATE_LIMIT</label>
                        <input type="number" value={srRateLimit} onChange={(e) => setSrRateLimit(e.target.value)} placeholder="100" className={inputClass} />
                      </div>
                      <div className="w-36">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">MAX_DURATION</label>
                        <input type="text" value={srMaxDuration} onChange={(e) => setSrMaxDuration(e.target.value)} placeholder="30m" className={inputClass} />
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <div className="w-36">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">HEURISTICS</label>
                        <Dropdown value={srHeuristics} onChange={setSrHeuristics} options={HEURISTICS.map(h => ({ value: h, label: h || '(default)' }))} />
                      </div>
                      <div className="flex-1">
                        <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">SCANNING_PROFILE</label>
                        <input type="text" value={srScanProfile} onChange={(e) => setSrScanProfile(e.target.value)} placeholder="profile name" className={inputClass} />
                      </div>
                    </div>
                    <div>
                      <label className="text-[#708e8e] text-[10px] uppercase block mb-0.5">HEADERS</label>
                      <div className="space-y-1">
                        {srHeaders.map((h, i) => (
                          <div key={i} className="flex gap-1 items-center">
                            <input type="text" value={h.key} onChange={(e) => updateSrHeader(i, 'key', e.target.value)} placeholder="Header-Name" className={`${inputClass} flex-1`} />
                            <input type="text" value={h.value} onChange={(e) => updateSrHeader(i, 'value', e.target.value)} placeholder="value" className={`${inputClass} flex-1`} />
                            <button onClick={() => removeSrHeader(i)} className="text-[#708e8e] hover:text-[#e34e1c] text-xs px-1">x</button>
                          </div>
                        ))}
                        <button onClick={addSrHeader} className="text-xs text-[#708e8e] hover:text-[#0078c8]">[+ header]</button>
                      </div>
                    </div>
                  </div>
                )}
                <div className="flex gap-2 items-center">
                  <button onClick={handleSubmitStoredRecords} disabled={scanAllRecords.isPending} className={btnClass}>
                    {scanAllRecords.isPending ? 'scanning...' : '[SCAN_RECORDS]'}
                  </button>
                  <button onClick={() => setSrForce(!srForce)} className={`px-2 py-1 text-xs border transition-colors shrink-0 ${srForce ? 'border-[#e34e1c]/50 text-[#e34e1c] bg-[#e34e1c]/10' : 'border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]'}`}>
                    FORCE: {srForce ? 'ON' : 'OFF'}
                  </button>
                  <button onClick={() => setSrDryRun(!srDryRun)} className={`px-2 py-1 text-xs border transition-colors shrink-0 ${srDryRun ? 'border-[#b8860b]/50 text-[#b8860b] bg-[#b8860b]/10' : 'border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]'}`}>
                    DRY_RUN: {srDryRun ? 'ON' : 'OFF'}
                  </button>
                </div>
              </>
            )}

            {/* Result display */}
            {mutation.isSuccess && mutation.data && (
              <div className="border border-[#bbc3c4] p-2 text-xs flex items-center gap-4 flex-wrap">
                <span className="text-[#0078c8] font-bold">RESULT</span>
                <span><span className="text-[#708e8e]">scan_id:</span> <span className="text-[#005661]">{mutation.data.scan_id}</span></span>
                <span><span className="text-[#708e8e]">status:</span> <span className="text-[#005661]">{mutation.data.status}</span></span>
                {mutation.data.scan_mode && <span><span className="text-[#708e8e]">mode:</span> <span className="text-[#005661]">{mutation.data.scan_mode}</span></span>}
                {mutation.data.targets_count != null && <span><span className="text-[#708e8e]">targets:</span> <span className="text-[#005661]">{mutation.data.targets_count}</span></span>}
                {mutation.data.records_to_scan != null && <span><span className="text-[#708e8e]">records:</span> <span className="text-[#005661]">{mutation.data.records_to_scan}</span></span>}
                {mutation.data.repo_path && <span><span className="text-[#708e8e]">repo:</span> <span className="text-[#005661]">{mutation.data.repo_path}</span></span>}
                {mutation.data.message && <span><span className="text-[#708e8e]">msg:</span> <span className="text-[#005661]">{mutation.data.message}</span></span>}
              </div>
            )}
            {mutation.isError && (
              <div className="text-xs text-[#e34e1c]">error: {(mutation.error as Error).message}</div>
            )}
          </div>
        )}
      </div>

      {/* Scan History */}
      <div className="border border-[#bbc3c4] bg-[#f6edda] overflow-hidden mt-3">
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
                  <tr key={scan.uuid} onClick={() => setExpandedScanUuid((prev) => prev === scan.uuid ? null : scan.uuid)} className={`border-b border-[#bbc3c4]/50 hover:bg-[#ede4d1] transition-colors cursor-pointer ${expandedScanUuid === scan.uuid ? 'bg-[#ede4d1]' : ''}`}>
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
