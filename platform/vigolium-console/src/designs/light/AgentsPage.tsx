'use client';

import { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import { Square, Send, Bot, Terminal, MessageSquare, Clock, CheckCircle, XCircle, Loader2, Zap, Layers, Bug, ScrollText, Copy, Check, Upload, ChevronDown, Play, X, Settings2, Crosshair, Scale } from 'lucide-react';
import type { AgentSession, AgentSessionDetail } from '@/api/types';
import { formatDate, formatDuration, truncate } from '@/lib/formatters';
import PageShell from './PageShell';
import Dropdown from './Dropdown';
import GitHubRepoPicker from './GitHubRepoPicker';
import { useAgentsLogic, AGENT_OPTIONS, ARCHON_MODE_OPTIONS, INTENSITY_OPTIONS, type ScanProfile, type AdvancedMode, type DetectedInputType } from '@/hooks/useAgentsLogic';

const INPUT_TYPE_LABELS: Record<DetectedInputType, { label: string; color: string }> = {
  url: { label: 'URL', color: '#00b368' },
  raw: { label: 'RAW REQUEST', color: '#0078c8' },
  curl: { label: 'CURL', color: '#c49000' },
  empty: { label: '', color: '#708e8e' },
};

const STATUS_ICON: Record<string, typeof CheckCircle> = {
  completed: CheckCircle,
  error: XCircle,
  running: Loader2,
};

function StatusBadge({ status }: { status: string }) {
  const Icon = STATUS_ICON[status] || Clock;
  const color = status === 'completed' ? '#00b368' : status === 'error' ? '#e34e1c' : status === 'running' ? '#0078c8' : '#708e8e';
  return (
    <span className="flex items-center gap-1 text-xs font-bold" style={{ color }}>
      <Icon className={`w-3 h-3 ${status === 'running' ? 'animate-spin' : ''}`} />
      {status}
    </span>
  );
}

function tryPrettyJson(s: string | undefined): string {
  if (!s) return '';
  try { return JSON.stringify(JSON.parse(s), null, 2); } catch { return s; }
}

function SessionDetailPanel({ session, onClose }: { session: AgentSessionDetail; onClose: () => void }) {
  const [copied, setCopied] = useState<string | null>(null);
  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(key);
      setTimeout(() => setCopied(null), 2000);
    });
  };

  return (
    <div className="border-l border-[#bbc3c4] flex flex-col h-full min-h-0">
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-[#bbc3c4] shrink-0">
        <span className="text-xs font-bold text-[#0078c8]">SESSION DETAILS</span>
        <button onClick={onClose} className="text-[#708e8e] hover:text-[#005661] text-xs font-bold px-1">&#10005;</button>
      </div>
      <div className="shrink-0 border-b border-[#bbc3c4] px-3 py-2 text-xs space-y-1">
        <div className="text-[#0078c8] font-mono break-all">{session.uuid}</div>
        <div className="flex flex-wrap gap-x-4 gap-y-0.5">
          <span><span className="text-[#708e8e]">status </span><StatusBadge status={session.status} /></span>
          <span><span className="text-[#708e8e]">mode </span><span className="text-[#005661]">{session.mode}</span></span>
          <span><span className="text-[#708e8e]">agent </span><span className="text-[#005661]">{session.agent_name}</span></span>
          {session.input_type && <span><span className="text-[#708e8e]">input </span><span className="text-[#005661]">{session.input_type}</span></span>}
        </div>
        {session.target_url && (
          <div><span className="text-[#708e8e]">target </span><span className="text-[#005661] break-all">{session.target_url}</span></div>
        )}
        <div className="flex flex-wrap gap-x-4 gap-y-0.5">
          <span><span className="text-[#708e8e]">findings </span><span className="text-[#005661]">{session.finding_count}</span></span>
          <span><span className="text-[#708e8e]">records </span><span className="text-[#005661]">{session.record_count}</span></span>
          <span><span className="text-[#708e8e]">saved </span><span className="text-[#00b368]">{session.saved_count}</span></span>
        </div>
        <div className="flex flex-wrap gap-x-4 gap-y-0.5">
          <span><span className="text-[#708e8e]">duration </span><span className="text-[#005661]">{formatDuration(session.duration_ms)}</span></span>
          <span><span className="text-[#708e8e]">started </span><span className="text-[#005661]">{formatDate(session.started_at)}</span></span>
          {session.completed_at && <span><span className="text-[#708e8e]">completed </span><span className="text-[#005661]">{formatDate(session.completed_at)}</span></span>}
        </div>
        {session.phases_run && session.phases_run.length > 0 && (
          <div><span className="text-[#708e8e]">phases </span><span className="text-[#005661]">{session.phases_run.join(' \u2192 ')}</span></div>
        )}
        {session.module_names && session.module_names.length > 0 && (
          <div><span className="text-[#708e8e]">modules </span><span className="text-[#005661]">{session.module_names.join(', ')}</span></div>
        )}
      </div>
      <div className="flex-1 min-h-0 overflow-y-auto text-xs">
        {session.prompt_sent && (
          <details className="border-b border-[#bbc3c4]">
            <summary className="px-3 py-1.5 cursor-pointer text-[#0078c8] font-bold hover:bg-[#ede4d1] flex items-center gap-1.5">
              <Terminal className="w-3 h-3" />PROMPT
            </summary>
            <div className="relative">
              <button onClick={() => copyToClipboard(session.prompt_sent!, 'prompt')} className="absolute top-1.5 right-2 text-[#708e8e] hover:text-[#005661] p-0.5" title="Copy to clipboard">
                {copied === 'prompt' ? <Check className="w-3.5 h-3.5 text-[#00b368]" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
              <pre className="px-3 py-2 bg-[#ede4d1] text-[#005661] whitespace-pre-wrap break-all font-mono overflow-x-auto">{session.prompt_sent}</pre>
            </div>
          </details>
        )}
        {session.agent_raw_output && (
          <details open className="border-b border-[#bbc3c4]">
            <summary className="px-3 py-1.5 cursor-pointer text-[#0078c8] font-bold hover:bg-[#ede4d1] flex items-center gap-1.5">
              <ScrollText className="w-3 h-3" />RAW OUTPUT
            </summary>
            <div className="relative">
              <button onClick={() => copyToClipboard(session.agent_raw_output!, 'output')} className="absolute top-1.5 right-2 z-10 text-[#708e8e] hover:text-[#005661] p-0.5" title="Copy to clipboard">
                {copied === 'output' ? <Check className="w-3.5 h-3.5 text-[#00b368]" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
              <div className="px-3 py-2 bg-[#ede4d1] text-[#005661] overflow-x-auto prose prose-xs max-w-none [&_pre]:bg-[#d4e8e2] [&_pre]:p-2 [&_pre]:text-xs [&_pre]:rounded [&_code]:text-[#00b368] [&_p]:m-0 [&_p]:mb-1.5 [&_h1]:text-sm [&_h2]:text-sm [&_h3]:text-xs [&_h1]:mt-2 [&_h2]:mt-2 [&_h3]:mt-1 [&_ul]:my-1 [&_ol]:my-1 [&_li]:my-0">
                <ReactMarkdown>{session.agent_raw_output}</ReactMarkdown>
              </div>
            </div>
          </details>
        )}
        {session.attack_plan && (
          <details open className="border-b border-[#bbc3c4]">
            <summary className="px-3 py-1.5 cursor-pointer text-[#0078c8] font-bold hover:bg-[#ede4d1] flex items-center gap-1.5">
              <Zap className="w-3 h-3" />ATTACK PLAN
            </summary>
            <div className="relative">
              <button onClick={() => copyToClipboard(tryPrettyJson(session.attack_plan), 'plan')} className="absolute top-1.5 right-2 z-10 text-[#708e8e] hover:text-[#005661] p-0.5" title="Copy to clipboard">
                {copied === 'plan' ? <Check className="w-3.5 h-3.5 text-[#00b368]" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
              <div className="px-3 py-2 bg-[#ede4d1] text-[#005661] overflow-x-auto prose prose-xs max-w-none [&_pre]:bg-[#d4e8e2] [&_pre]:p-2 [&_pre]:text-xs [&_pre]:rounded [&_code]:text-[#00b368] [&_p]:m-0 [&_p]:mb-1.5 [&_h1]:text-sm [&_h2]:text-sm [&_h3]:text-xs [&_h1]:mt-2 [&_h2]:mt-2 [&_h3]:mt-1 [&_ul]:my-1 [&_ol]:my-1 [&_li]:my-0">
                <ReactMarkdown>{tryPrettyJson(session.attack_plan)}</ReactMarkdown>
              </div>
            </div>
          </details>
        )}
        {session.triage_result && (
          <details className="border-b border-[#bbc3c4]">
            <summary className="px-3 py-1.5 cursor-pointer text-[#0078c8] font-bold hover:bg-[#ede4d1] flex items-center gap-1.5">
              <Bug className="w-3 h-3" />TRIAGE RESULT
            </summary>
            <div className="relative">
              <button onClick={() => copyToClipboard(tryPrettyJson(session.triage_result), 'triage')} className="absolute top-1.5 right-2 text-[#708e8e] hover:text-[#005661] p-0.5" title="Copy to clipboard">
                {copied === 'triage' ? <Check className="w-3.5 h-3.5 text-[#00b368]" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
              <pre className="px-3 py-2 bg-[#ede4d1] text-[#005661] whitespace-pre-wrap break-all font-mono overflow-x-auto">{tryPrettyJson(session.triage_result)}</pre>
            </div>
          </details>
        )}
      </div>
    </div>
  );
}

export default function AgentsPage() {
  const h = useAgentsLogic();

  const inputClass = 'bg-[#ede4d1] border border-[#bbc3c4] text-[#005661] text-xs px-2 py-1 focus:outline-none focus:border-[#0078c8]/50 w-full';
  const modeBtnClass = (active: boolean) =>
    `px-3 py-0.5 text-xs font-bold transition-colors ${active ? 'text-[#0078c8] bg-[#0078c8]/10' : 'text-[#708e8e] hover:text-[#005661]'}`;

  return (
    <PageShell>
      <div className="flex flex-col" style={{ height: 'calc(100vh - 68px)', minHeight: 500 }}>

        {/* ── Top: Config (full width) ── */}
        <div className="shrink-0 border border-[#bbc3c4] bg-[#f6edda] flex flex-col overflow-hidden">
          {/* Header with scan button */}
          <div className="px-3 py-2 border-b border-[#bbc3c4] shrink-0 flex items-center justify-between">
            <h2 className="text-[#0078c8] text-xs font-bold tracking-wide">AGENTIC SCAN</h2>
            {h.isScanStreaming && (
              <span className="text-xs text-[#0078c8] flex items-center gap-1"><Loader2 className="w-3 h-3 animate-spin" /> streaming...</span>
            )}
          </div>

          <div className="overflow-y-auto px-3 py-2 space-y-3">
            {/* Target + GitHub/Upload — same row */}
            <div className="grid grid-cols-3 gap-2 items-stretch">
              {/* Target input — 2/3 */}
              <div className="col-span-2 flex flex-col">
                <div className="flex items-center gap-1.5 mb-0.5" style={{ minHeight: '1.25rem' }}>
                  <button
                    onClick={() => h.setTargetInputTab('target')}
                    className={`text-xs font-bold transition-colors ${h.targetInputTab === 'target' ? 'text-[#00b368]' : 'text-[#708e8e] hover:text-[#005661]'}`}
                  >Target</button>
                  <span className="text-[#bbc3c4]">|</span>
                  <button
                    onClick={() => h.setTargetInputTab('prompt')}
                    className={`text-xs font-bold transition-colors flex items-center gap-1 ${h.targetInputTab === 'prompt' ? 'text-[#00b368]' : 'text-[#708e8e] hover:text-[#005661]'}`}
                  ><Crosshair className="w-3 h-3" />Prompt</button>
                  {h.targetInputTab === 'target' ? (
                    <span className="text-[10px]" style={{ color: INPUT_TYPE_LABELS[h.detectedInputType].color }}>
                      (type: {h.detectedInputType === 'empty' ? 'url' : h.detectedInputType === 'raw' ? 'raw request' : h.detectedInputType})
                    </span>
                  ) : (
                    <span className="text-[10px] text-[#c49000]">(type: natural language)</span>
                  )}
                </div>
                {h.targetInputTab === 'target' ? (
                  <>
                    <textarea
                      value={h.targetUrl}
                      onChange={(e) => h.setTargetUrl(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && !e.shiftKey && h.detectedInputType === 'url') {
                          e.preventDefault();
                          h.handleProfileSubmit();
                        }
                      }}
                      placeholder={"https://example.com/api/endpoint\n\nor paste a raw HTTP request / curl command"}
                      rows={Math.max(4, Math.min(20, h.targetUrl.split('\n').length + 1))}
                      className={`${inputClass} !text-xs !py-1.5 font-mono resize-y whitespace-pre-wrap break-all flex-1`}
                    />
                    {h.scanError && <p className="text-xs text-[#e34e1c] mt-1">{h.scanError}</p>}
                  </>
                ) : (
                  <>
                    <textarea
                      value={h.targetPrompt}
                      onChange={(e) => h.setTargetPrompt(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && !e.shiftKey) {
                          e.preventDefault();
                          h.handleTargetSubmit();
                        }
                      }}
                      placeholder="scan localhost:3000 for auth bypass"
                      rows={Math.max(4, Math.min(20, h.targetPrompt.split('\n').length + 1))}
                      className={`${inputClass} !text-xs !py-1.5 font-mono resize-y whitespace-pre-wrap break-all flex-1`}
                    />
                    {h.targetError && <p className="text-xs text-[#e34e1c] mt-1">{h.targetError}</p>}
                    {h.targetRunStatus?.error && <p className="text-xs text-[#e34e1c] mt-1">{h.targetRunStatus.error}</p>}
                  </>
                )}
              </div>
              {/* GitHub Repo + Upload — 1/3 */}
              <div className="flex flex-col gap-1.5">
                <label className="text-[#708e8e] text-xs mb-0.5">GitHub Repo</label>
                <GitHubRepoPicker onSelect={(url) => h.setSwarmSource(url)} selectedRepo={h.swarmSource.includes('x-access-token') ? h.swarmSource.replace(/https:\/\/x-access-token:[^@]+@github\.com\//, '').replace('.git', '') : undefined} />
                <div
                  onDragEnter={h.onUploadDragEnter} onDragLeave={h.onUploadDragLeave} onDragOver={h.onUploadDragOver} onDrop={h.onUploadDrop}
                  className={`border border-dashed p-2 text-center transition-colors flex-1 ${h.uploadCompressing || h.uploadRepo.isPending ? '' : 'cursor-pointer'} ${h.uploadDragging ? 'border-[#00b368] bg-[#00b368]/10' : h.swarmSource ? 'border-[#00b368] bg-[#00b368]/5' : 'border-[#bbc3c4] hover:border-[#0078c8]/50'}`}
                  onClick={() => { if (!h.uploadCompressing && !h.uploadRepo.isPending) h.uploadFileInputRef.current?.click(); }}
                >
                  <input ref={h.uploadFileInputRef} type="file" accept=".zip,.tar.gz,.tgz,.tar" onChange={h.handleFileUpload} className="hidden" />
                  {h.uploadCompressing || h.uploadRepo.isPending ? (
                    <div className="flex items-center justify-center gap-1.5"><Loader2 className="w-3.5 h-3.5 text-[#0078c8] animate-spin" /><span className="text-[10px] text-[#005661]">{h.uploadCompressing ? 'Compressing...' : 'Uploading...'}</span></div>
                  ) : (
                    <div className="flex items-center justify-center gap-1.5"><Upload className="w-3.5 h-3.5 text-[#0078c8]/70" /><span className="text-[10px] text-[#005661]">{h.uploadDragging ? 'Drop here' : 'Upload source code'}</span></div>
                  )}
                  <p className="text-[9px] text-[#708e8e] mt-0.5">.zip, .tar.gz, folder — max 500 MB</p>
                  {h.swarmSource && (
                    <p className="text-[9px] text-[#708e8e] mt-0.5 truncate" title={h.swarmSource.includes('x-access-token') ? 'Authenticated clone URL' : h.swarmSource}>
                      {h.swarmSource.includes('x-access-token') ? h.swarmSource.replace(/https:\/\/x-access-token:[^@]+@/, 'https://') : h.swarmSource}
                    </p>
                  )}
                  {h.uploadRepo.isSuccess && <p className="text-[9px] text-[#00b368] mt-0.5">uploaded</p>}
                  {h.uploadRepo.isError && <p className="text-[9px] text-[#e34e1c] mt-0.5">failed</p>}
                </div>
              </div>
            </div>

            {/* Scanning Mode */}
            <div>
              <label className="text-[#708e8e] text-xs block mb-1">Scanning Mode</label>
              {/* Top-level mode selector */}
              <div className="grid grid-cols-2 gap-0">
                <button
                  onClick={() => h.setScanProfile('autopilot')}
                  className={`px-3 py-2 text-center border transition-colors ${
                    h.scanProfile === 'autopilot'
                      ? 'border-[#4a9aba] bg-[#4a9aba]/8'
                      : 'border-[#bbc3c4] hover:border-[#708e8e] hover:bg-[#ede4d1]/50'
                  }`}
                >
                  <div className="flex items-center justify-center gap-1.5 mb-0.5">
                    <Bot className={`w-3 h-3 ${h.scanProfile === 'autopilot' ? 'text-[#4a9aba]' : 'text-[#708e8e]'}`} />
                    <span className={`text-xs font-bold ${h.scanProfile === 'autopilot' ? 'text-[#3d7a8f]' : 'text-[#005661]'}`}>AUTOPILOT</span>
                  </div>
                  <p className="text-[10px] text-[#708e8e] leading-tight">AI agent drives the CLI autonomously — explores, scans, and iterates on findings.</p>
                </button>
                <button
                  onClick={() => { if (h.scanProfile === 'autopilot') h.setScanProfile('quick'); }}
                  className={`px-3 py-2 text-center border transition-colors ${
                    h.scanProfile !== 'autopilot'
                      ? 'border-[#4a9aba] bg-[#4a9aba]/8'
                      : 'border-[#bbc3c4] hover:border-[#708e8e] hover:bg-[#ede4d1]/50'
                  }`}
                >
                  <div className="flex items-center justify-center gap-1.5 mb-0.5">
                    <Bug className={`w-3 h-3 ${h.scanProfile !== 'autopilot' ? 'text-[#4a9aba]' : 'text-[#708e8e]'}`} />
                    <span className={`text-xs font-bold ${h.scanProfile !== 'autopilot' ? 'text-[#3d7a8f]' : 'text-[#005661]'}`}>SWARM</span>
                  </div>
                  <p className="text-[10px] text-[#708e8e] leading-tight">AI-guided targeted vulnerability scan with module selection.</p>
                </button>
              </div>
            </div>

            {/* Intensity */}
            <div>
              <label className="text-[#708e8e] text-xs block mb-1">Scan Intensity Level</label>
              <div className="grid grid-cols-3 gap-0">
                {INTENSITY_OPTIONS.filter((o) => o.value !== '').map((o) => {
                  const currentIntensity = h.scanProfile === 'autopilot' ? h.autopilotIntensity : h.swarmIntensity;
                  const active = currentIntensity === o.value || (!currentIntensity && o.value === 'balanced');
                  const Icon = o.icon === 'zap' ? Zap : o.icon === 'scale' ? Scale : Layers;
                  return (
                    <button
                      key={o.value}
                      onClick={() => { h.setSwarmIntensity(o.value); h.setAutopilotIntensity(o.value); }}
                      className={`px-3 py-2 text-center border transition-colors ${
                        active
                          ? 'border-[#4a9aba] bg-[#4a9aba]/10'
                          : 'border-[#bbc3c4] hover:border-[#708e8e] hover:bg-[#ede4d1]/50'
                      }`}
                    >
                      <div className="flex items-center justify-center gap-1.5 mb-0.5">
                        <Icon className={`w-3 h-3 ${active ? 'text-[#4a9aba]' : 'text-[#708e8e]'}`} />
                        <span className={`text-xs font-bold ${active ? 'text-[#3d7a8f]' : 'text-[#005661]'}`}>{o.label}</span>
                      </div>
                      {o.description && <p className="text-[10px] text-[#708e8e] leading-tight">{o.description}</p>}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Start Scan / Stop + Advanced toggle */}
            <div className="flex items-center gap-2">
              {h.targetInputTab === 'prompt' ? (
                <button
                  onClick={h.handleTargetSubmit}
                  disabled={!h.targetPrompt.trim() || h.startAutopilotRun.isPending}
                  className="px-4 py-1 text-xs font-bold border border-[#FF8C00] text-[#FF8C00] bg-[#FF8C00]/10 hover:bg-[#FF8C00]/20 shadow-[inset_0_0_18px_rgba(255,140,0,0.3)] hover:shadow-[inset_0_0_28px_rgba(255,140,0,0.5)] transition-colors disabled:opacity-30 flex items-center gap-1.5"
                >
                  {h.startAutopilotRun.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                  {h.startAutopilotRun.isPending ? 'SUBMITTING...' : 'START SCAN'}
                </button>
              ) : !h.isScanStreaming ? (
                <button
                  onClick={h.handleProfileSubmit}
                  disabled={!h.targetUrl.trim()}
                  className="px-4 py-1 text-xs font-bold border border-[#FF8C00] text-[#FF8C00] bg-[#FF8C00]/10 hover:bg-[#FF8C00]/20 shadow-[inset_0_0_18px_rgba(255,140,0,0.3)] hover:shadow-[inset_0_0_28px_rgba(255,140,0,0.5)] transition-colors disabled:opacity-30 flex items-center gap-1.5"
                >
                  <Play className="w-3.5 h-3.5" /> START SCAN
                </button>
              ) : (
                <button
                  onClick={h.handleScanCancel}
                  className="px-4 py-1 text-xs font-bold bg-[#e34e1c]/10 text-[#e34e1c] border border-[#e34e1c]/30 hover:bg-[#e34e1c]/20 transition-colors flex items-center gap-1.5"
                >
                  <Square className="w-3 h-3" /> STOP
                </button>
              )}
              <button
                onClick={() => h.setShowAdvanced(!h.showAdvanced)}
                className={`px-3 py-1 text-xs font-bold border flex items-center gap-1 transition-colors ${
                  h.showAdvanced
                    ? 'border-[#708e8e] bg-[#708e8e]/10 text-[#708e8e]'
                    : 'border-[#bbc3c4] text-[#bbc3c4] hover:border-[#708e8e] hover:text-[#708e8e]'
                }`}
              >
                <Settings2 className="w-3 h-3" /> ADVANCED
              </button>
              {h.targetInputTab === 'prompt' && h.targetRunId && h.targetRunStatus && (
                <span className="flex items-center gap-1.5 text-xs">
                  <span className="text-[#708e8e]">run</span>
                  <span className="text-[#0078c8] font-mono">{h.targetRunId.slice(0, 12)}</span>
                  <StatusBadge status={h.targetRunStatus.status} />
                  {h.targetRunStatus.current_phase && <span className="text-[#005661]">{h.targetRunStatus.current_phase}</span>}
                  {h.targetRunStatus.finding_count > 0 && <span className="text-[#00b368] font-bold">{h.targetRunStatus.finding_count} findings</span>}
                </span>
              )}
            </div>

            {/* Advanced Options */}
            {h.showAdvanced && (
              <div className="mt-2 space-y-2">
                {/* Swarm options (default mode) */}
                {h.advancedMode === 'swarm' && (
                  <div className="space-y-1.5">
                    <div className="grid grid-cols-4 gap-1.5">
                      <div>
                        <label className="text-[#708e8e] text-[10px] block mb-0.5">Module Tags</label>
                        <input value={h.swarmModuleTags} onChange={(e) => h.setSwarmModuleTags(e.target.value)} placeholder="xss, sqli" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#708e8e] text-[10px] block mb-0.5">Vuln Type</label>
                        <input value={h.swarmVulnType} onChange={(e) => h.setSwarmVulnType(e.target.value)} placeholder="sqli" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#708e8e] text-[10px] block mb-0.5">Max Iterations</label>
                        <input value={h.swarmMaxIterations} onChange={(e) => h.setSwarmMaxIterations(e.target.value)} placeholder="3" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#708e8e] text-[10px] block mb-0.5">Timeout</label>
                        <input value={h.swarmTimeout} onChange={(e) => h.setSwarmTimeout(e.target.value)} placeholder="30m" className={inputClass} />
                      </div>
                    </div>
                    <div>
                      <label className="text-[#708e8e] text-[10px] block mb-0.5">Instruction</label>
                      <textarea value={h.swarmInstruction} onChange={(e) => h.setSwarmInstruction(e.target.value)} placeholder="Focus on business logic flaws..." rows={2} className={`${inputClass} resize-y`} />
                    </div>
                    <div className="grid grid-cols-4 gap-1.5">
                      <div>
                        <label className="text-[#708e8e] text-[10px] block mb-0.5">Focus</label>
                        <input value={h.swarmFocus} onChange={(e) => h.setSwarmFocus(e.target.value)} placeholder="auth bypass" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#708e8e] text-[10px] block mb-0.5">Profile</label>
                        <input value={h.swarmProfile} onChange={(e) => h.setSwarmProfile(e.target.value)} placeholder="thorough" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#708e8e] text-[10px] block mb-0.5">Diff</label>
                        <input value={h.swarmDiff} onChange={(e) => h.setSwarmDiff(e.target.value)} placeholder="PR URL or main...branch" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#708e8e] text-[10px] block mb-0.5">Intensity</label>
                        <Dropdown value={h.swarmIntensity} onChange={h.setSwarmIntensity} options={INTENSITY_OPTIONS} />
                      </div>
                      <div>
                        <label className="text-[#708e8e] text-[10px] block mb-0.5">Archon</label>
                        <Dropdown value={h.swarmArchon} onChange={h.setSwarmArchon} options={ARCHON_MODE_OPTIONS} />
                      </div>
                    </div>
                    <div className="flex flex-wrap items-end gap-1">
                      {([
                        ['Discover', h.swarmDiscover, h.setSwarmDiscover] as const,
                        ['Source Only', h.swarmSourceAnalysisOnly, h.setSwarmSourceAnalysisOnly] as const,
                        ['Code Audit', h.swarmCodeAudit, h.setSwarmCodeAudit] as const,
                        ['Skip SAST', h.swarmSkipSast, h.setSwarmSkipSast] as const,
                        ['Triage', h.swarmTriage, h.setSwarmTriage] as const,
                        ['Show Prompt', h.swarmShowPrompt, h.setSwarmShowPrompt] as const,
                        ['Dry Run', h.swarmDryRun, h.setSwarmDryRun] as const,
                      ]).map(([label, value, setter]) => (
                        <button key={label} type="button" onClick={() => setter(!value)}
                          className={`px-2.5 py-1 text-xs font-bold border transition-colors ${
                            value
                              ? 'border-[#0078c8] bg-[#0078c8]/15 text-[#0078c8]'
                              : 'border-[#bbc3c4] text-[#708e8e] hover:border-[#708e8e]'
                          }`}
                        >{label}</button>
                      ))}
                    </div>
                    <div className="grid grid-cols-3 gap-1.5">
                      <div>
                        <label className="text-[#708e8e] text-[10px] block mb-0.5">Only Phase</label>
                        <input value={h.swarmOnlyPhase} onChange={(e) => h.setSwarmOnlyPhase(e.target.value)} placeholder="plan" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#708e8e] text-[10px] block mb-0.5">Skip Phases <span className="text-[#bbc3c4] italic">comma-sep</span></label>
                        <input value={h.swarmSkipPhases} onChange={(e) => h.setSwarmSkipPhases(e.target.value)} placeholder="triage, native-rescan" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#708e8e] text-[10px] block mb-0.5">Start From</label>
                        <input value={h.swarmStartFrom} onChange={(e) => h.setSwarmStartFrom(e.target.value)} placeholder="triage" className={inputClass} />
                      </div>
                    </div>
                  </div>
                )}

                {/* Autopilot options */}
                {h.advancedMode === 'autopilot' && (
                  <div className="space-y-1.5">
                    <div className="grid grid-cols-4 gap-1.5">
                      <div>
                        <label className="text-[#708e8e] text-[10px] block mb-0.5">Agent</label>
                        <Dropdown value={h.autopilotAgent} onChange={h.setAutopilotAgent} options={AGENT_OPTIONS} />
                      </div>
                      <div>
                        <label className="text-[#708e8e] text-[10px] block mb-0.5">Focus</label>
                        <input value={h.autopilotFocus} onChange={(e) => h.setAutopilotFocus(e.target.value)} placeholder="auth, api" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#708e8e] text-[10px] block mb-0.5">Timeout</label>
                        <input value={h.autopilotTimeout} onChange={(e) => h.setAutopilotTimeout(e.target.value)} placeholder="30m" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#708e8e] text-[10px] block mb-0.5">Max Commands</label>
                        <input value={h.autopilotMaxCommands} onChange={(e) => h.setAutopilotMaxCommands(e.target.value)} placeholder="50" className={inputClass} />
                      </div>
                    </div>
                    <div className="grid grid-cols-3 gap-1.5">
                      <div>
                        <label className="text-[#708e8e] text-[10px] block mb-0.5">Source</label>
                        <input value={h.autopilotSource} onChange={(e) => h.setAutopilotSource(e.target.value)} placeholder="git URL or local path" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#708e8e] text-[10px] block mb-0.5">Diff</label>
                        <input value={h.autopilotDiff} onChange={(e) => h.setAutopilotDiff(e.target.value)} placeholder="PR URL or main...branch" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#708e8e] text-[10px] block mb-0.5">Intensity</label>
                        <Dropdown value={h.autopilotIntensity} onChange={h.setAutopilotIntensity} options={INTENSITY_OPTIONS} />
                      </div>
                      <div>
                        <label className="text-[#708e8e] text-[10px] block mb-0.5">Archon Mode</label>
                        <Dropdown value={h.autopilotArchonMode} onChange={h.setAutopilotArchonMode} options={ARCHON_MODE_OPTIONS} />
                      </div>
                    </div>
                    <div>
                      <label className="text-[#708e8e] text-[10px] block mb-0.5">Instruction</label>
                      <textarea value={h.autopilotInstruction} onChange={(e) => h.setAutopilotInstruction(e.target.value)} placeholder="Custom instruction for the agent..." rows={2} className={`${inputClass} resize-y`} />
                    </div>
                    <div className="flex items-center gap-1">
                      {([
                        ['Dry Run', h.autopilotDryRun, h.setAutopilotDryRun] as const,
                        ['No Archon', h.autopilotNoArchon, h.setAutopilotNoArchon] as const,
                      ]).map(([label, value, setter]) => (
                        <button key={label} type="button" onClick={() => setter(!value)}
                          className={`px-2 py-0.5 text-[9px] font-bold border transition-colors ${
                            value
                              ? 'border-[#0078c8] bg-[#0078c8]/15 text-[#0078c8]'
                              : 'border-[#bbc3c4] text-[#708e8e] hover:border-[#708e8e]'
                          }`}
                        >{label}</button>
                      ))}
                    </div>
                  </div>
                )}

                {/* Query options */}
                {h.advancedMode === 'query' && (
                  <div className="space-y-2">
                    <div className="flex border border-[#bbc3c4]">
                      <button onClick={() => h.setScanMode('template')} className={modeBtnClass(h.scanMode === 'template')}>TEMPLATE</button>
                      <button onClick={() => h.setScanMode('custom')} className={modeBtnClass(h.scanMode === 'custom')}>CUSTOM</button>
                    </div>
                    {h.scanMode === 'template' ? (
                      <>
                        <div>
                          <label className="text-[#708e8e] text-xs block mb-0.5">Agent</label>
                          <input value={h.agentName} onChange={(e) => h.setAgentName(e.target.value)} placeholder="claude" className={inputClass} />
                        </div>
                        <div>
                          <label className="text-[#708e8e] text-xs block mb-0.5">Prompt Template</label>
                          <input value={h.promptTemplate} onChange={(e) => h.setPromptTemplate(e.target.value)} placeholder="security-analysis" className={inputClass} />
                        </div>
                      </>
                    ) : (
                      <div>
                        <label className="text-[#708e8e] text-xs block mb-0.5">Prompt</label>
                        <textarea value={h.customPrompt} onChange={(e) => h.setCustomPrompt(e.target.value)} placeholder="Enter your prompt..." rows={3} className={`${inputClass} resize-y`} />
                      </div>
                    )}
                    <div>
                      <label className="text-[#708e8e] text-xs block mb-0.5">Files <span className="text-[#bbc3c4] italic">comma-sep</span></label>
                      <input value={h.queryFiles} onChange={(e) => h.setQueryFiles(e.target.value)} placeholder="src/main.go" className={inputClass} />
                    </div>
                    <div className="grid grid-cols-2 gap-1.5">
                      <div>
                        <label className="text-[#708e8e] text-xs block mb-0.5">Instruction</label>
                        <input value={h.queryInstruction} onChange={(e) => h.setQueryInstruction(e.target.value)} placeholder="Custom instruction..." className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#708e8e] text-xs block mb-0.5">Source Label</label>
                        <input value={h.querySourceLabel} onChange={(e) => h.setQuerySourceLabel(e.target.value)} placeholder="my-source" className={inputClass} />
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

        </div>

        {/* ── Bottom: Output ── */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Streaming Output */}
          <div className="flex-1 border border-t-0 border-[#bbc3c4] bg-[#ede4d1] flex flex-col overflow-hidden">
            <div className="px-3 py-1.5 border-b border-[#bbc3c4] flex items-center justify-between shrink-0">
              <span className="text-[#0078c8] text-xs font-bold flex items-center gap-1.5">
                <ScrollText className="w-3 h-3" />STREAMING RESPONSE
              </span>
              <div className="flex items-center gap-3">
                {h.isScanStreaming && (
                  <span className="text-xs text-[#0078c8] flex items-center gap-1"><Loader2 className="w-3 h-3 animate-spin" /> streaming...</span>
                )}
                {h.scanResult && (
                  <span className="text-xs text-[#708e8e]">
                    {h.scanResult.finding_count != null && <span className="text-[#005661] mr-3">findings: <b className="text-[#00b368]">{String(h.scanResult.finding_count)}</b></span>}
                    {h.scanResult.saved_count != null && <span className="text-[#005661]">saved: <b className="text-[#00b368]">{String(h.scanResult.saved_count)}</b></span>}
                  </span>
                )}
              </div>
            </div>
            <pre ref={h.scanOutputRef} className="flex-1 overflow-auto p-3 text-xs text-[#708e8e] font-mono whitespace-pre-wrap leading-relaxed">
              {h.scanOutput || (
                <span className="text-[#bbc3c4]">
                  {h.sessionsData?.data && h.sessionsData.data.length > 0
                    ? 'Select a session below or start a new scan...'
                    : 'agent output will appear here...'}
                </span>
              )}
            </pre>
          </div>

          {/* Sessions — open by default when there are sessions and no active scan */}
          <details open={!h.scanOutput && !!(h.sessionsData?.data?.length)} className="border border-t-0 border-[#bbc3c4] bg-[#f6edda] overflow-hidden shrink-0">
            <summary className="px-3 py-1.5 border-b border-[#bbc3c4] cursor-pointer hover:bg-[#ede4d1]/80 list-none [&::-webkit-details-marker]:hidden flex items-center gap-1.5">
              <ChevronDown className="w-3 h-3 text-[#0078c8] transition-transform [[open]>&]:rotate-0 [details:not([open])>&]:-rotate-90" />
              <span className="text-[#0078c8] text-xs font-bold inline-flex items-center gap-1.5">
                <Layers className="w-3 h-3" />AGENT SESSIONS
                {h.sessionsData?.total != null && <span className="text-[#708e8e] font-normal ml-1">({h.sessionsData.total})</span>}
              </span>
            </summary>
            <div className="flex max-h-[300px]" style={{ minHeight: h.expandedSessionUuid && h.sessionDetail ? 280 : undefined }}>
              <div className={`${h.expandedSessionUuid && h.sessionDetail ? 'w-1/2' : 'w-full'} overflow-auto`}>
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-[#bbc3c4] text-[#bbc3c4]">
                      <th className="text-left px-2 py-1 font-bold">STATUS</th>
                      <th className="text-left px-2 py-1 font-bold">UUID</th>
                      <th className="text-left px-2 py-1 font-bold">MODE</th>
                      <th className="text-left px-2 py-1 font-bold">TARGET</th>
                      <th className="text-right px-2 py-1 font-bold">FINDINGS</th>
                      <th className="text-right px-2 py-1 font-bold">SAVED</th>
                      <th className="text-right px-2 py-1 font-bold">DURATION</th>
                    </tr>
                  </thead>
                  <tbody>
                    {h.sessionsData?.data && h.sessionsData.data.length > 0 ? (
                      h.sessionsData.data.map((s: AgentSession) => (
                        <tr
                          key={s.uuid}
                          onClick={() => h.setExpandedSessionUuid(prev => prev === s.uuid ? null : s.uuid)}
                          className={`border-b border-[#bbc3c4]/50 hover:bg-[#ede4d1]/50 cursor-pointer ${h.expandedSessionUuid === s.uuid ? 'bg-[#ede4d1]' : ''}`}
                        >
                          <td className="px-2 py-1"><StatusBadge status={s.status} /></td>
                          <td className="px-2 py-1 text-[#0078c8] font-mono">{s.uuid.slice(0, 8)}</td>
                          <td className="px-2 py-1 text-[#708e8e]">{s.mode}</td>
                          <td className="px-2 py-1 text-[#005661]">{s.target_url ? truncate(s.target_url, 30) : '\u2014'}</td>
                          <td className="px-2 py-1 text-right text-[#005661]">{s.finding_count}</td>
                          <td className="px-2 py-1 text-right text-[#00b368]">{s.saved_count}</td>
                          <td className="px-2 py-1 text-right text-[#005661]">{formatDuration(s.duration_ms)}</td>
                        </tr>
                      ))
                    ) : (
                      <tr><td colSpan={7} className="px-3 py-3 text-center text-[#bbc3c4]">no sessions</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
              {h.expandedSessionUuid && h.sessionDetail && (
                <div className="w-1/2">
                  <SessionDetailPanel session={h.sessionDetail} onClose={() => h.setExpandedSessionUuid(null)} />
                </div>
              )}
            </div>
          </details>
        </div>

      </div>
    </PageShell>
  );
}
