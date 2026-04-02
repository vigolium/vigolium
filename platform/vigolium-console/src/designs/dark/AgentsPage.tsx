'use client';

import { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import { Square, Send, Bot, Terminal, MessageSquare, Clock, CheckCircle, XCircle, Loader2, Zap, Layers, Bug, ScrollText, Copy, Check, Upload, ChevronDown, Play, X, Settings2 } from 'lucide-react';
import type { AgentSession, AgentSessionDetail } from '@/api/types';
import { formatDate, formatDuration, truncate } from '@/lib/formatters';
import PageShell from './PageShell';
import Dropdown from './Dropdown';
import GitHubRepoPicker from './GitHubRepoPicker';
import { useAgentsLogic, AGENT_OPTIONS, PROFILE_OPTIONS, type ScanProfile, type AdvancedMode, type DetectedInputType } from '@/hooks/useAgentsLogic';

const PROFILE_ICONS: Record<string, typeof Zap> = {
  zap: Zap,
  layers: Layers,
  'scroll-text': ScrollText,
  bot: Bot,
};

const INPUT_TYPE_LABELS: Record<DetectedInputType, { label: string; color: string }> = {
  url: { label: 'URL', color: '#7fd962' },
  raw: { label: 'RAW REQUEST', color: '#68a8e4' },
  curl: { label: 'CURL', color: '#d8a657' },
  empty: { label: '', color: '#918175' },
};

const STATUS_ICON: Record<string, typeof CheckCircle> = {
  completed: CheckCircle,
  error: XCircle,
  running: Loader2,
};

function StatusBadge({ status }: { status: string }) {
  const Icon = STATUS_ICON[status] || Clock;
  const color = status === 'completed' ? '#7fd962' : status === 'error' ? '#ef2f27' : status === 'running' ? '#68a8e4' : '#918175';
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
    <div className="border-l border-[#2e2b26] flex flex-col h-full min-h-0">
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-[#2e2b26] shrink-0">
        <span className="text-xs font-bold text-[#7fd962]">SESSION DETAILS</span>
        <button onClick={onClose} className="text-[#918175] hover:text-[#fce8c3] text-xs font-bold px-1">&#10005;</button>
      </div>
      <div className="shrink-0 border-b border-[#2e2b26] px-3 py-2 text-xs space-y-1">
        <div className="text-[#68a8e4] font-mono break-all">{session.uuid}</div>
        <div className="flex flex-wrap gap-x-4 gap-y-0.5">
          <span><span className="text-[#918175]">status </span><StatusBadge status={session.status} /></span>
          <span><span className="text-[#918175]">mode </span><span className="text-[#fce8c3]">{session.mode}</span></span>
          <span><span className="text-[#918175]">agent </span><span className="text-[#fce8c3]">{session.agent_name}</span></span>
          {session.input_type && <span><span className="text-[#918175]">input </span><span className="text-[#fce8c3]">{session.input_type}</span></span>}
        </div>
        {session.target_url && (
          <div><span className="text-[#918175]">target </span><span className="text-[#fce8c3] break-all">{session.target_url}</span></div>
        )}
        <div className="flex flex-wrap gap-x-4 gap-y-0.5">
          <span><span className="text-[#918175]">findings </span><span className="text-[#fce8c3]">{session.finding_count}</span></span>
          <span><span className="text-[#918175]">records </span><span className="text-[#fce8c3]">{session.record_count}</span></span>
          <span><span className="text-[#918175]">saved </span><span className="text-[#98bc37]">{session.saved_count}</span></span>
        </div>
        <div className="flex flex-wrap gap-x-4 gap-y-0.5">
          <span><span className="text-[#918175]">duration </span><span className="text-[#fce8c3]">{formatDuration(session.duration_ms)}</span></span>
          <span><span className="text-[#918175]">started </span><span className="text-[#fce8c3]">{formatDate(session.started_at)}</span></span>
          {session.completed_at && <span><span className="text-[#918175]">completed </span><span className="text-[#fce8c3]">{formatDate(session.completed_at)}</span></span>}
        </div>
        {session.phases_run && session.phases_run.length > 0 && (
          <div><span className="text-[#918175]">phases </span><span className="text-[#fce8c3]">{session.phases_run.join(' \u2192 ')}</span></div>
        )}
        {session.module_names && session.module_names.length > 0 && (
          <div><span className="text-[#918175]">modules </span><span className="text-[#fce8c3]">{session.module_names.join(', ')}</span></div>
        )}
      </div>
      <div className="flex-1 min-h-0 overflow-y-auto text-xs">
        {session.prompt_sent && (
          <details className="border-b border-[#2e2b26]">
            <summary className="px-3 py-1.5 cursor-pointer text-[#7fd962] font-bold hover:bg-[#2e2b26] flex items-center gap-1.5">
              <Terminal className="w-3 h-3" />PROMPT
            </summary>
            <div className="relative">
              <button onClick={() => copyToClipboard(session.prompt_sent!, 'prompt')} className="absolute top-1.5 right-2 text-[#918175] hover:text-[#fce8c3] p-0.5" title="Copy to clipboard">
                {copied === 'prompt' ? <Check className="w-3.5 h-3.5 text-[#98bc37]" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
              <pre className="px-3 py-2 bg-[#141310] text-[#fce8c3] whitespace-pre-wrap break-all font-mono overflow-x-auto">{session.prompt_sent}</pre>
            </div>
          </details>
        )}
        {session.agent_raw_output && (
          <details open className="border-b border-[#2e2b26]">
            <summary className="px-3 py-1.5 cursor-pointer text-[#7fd962] font-bold hover:bg-[#2e2b26] flex items-center gap-1.5">
              <ScrollText className="w-3 h-3" />RAW OUTPUT
            </summary>
            <div className="relative">
              <button onClick={() => copyToClipboard(session.agent_raw_output!, 'output')} className="absolute top-1.5 right-2 z-10 text-[#918175] hover:text-[#fce8c3] p-0.5" title="Copy to clipboard">
                {copied === 'output' ? <Check className="w-3.5 h-3.5 text-[#98bc37]" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
              <div className="px-3 py-2 bg-[#141310] text-[#fce8c3] overflow-x-auto prose prose-xs prose-invert max-w-none [&_pre]:bg-[#0c0b09] [&_pre]:p-2 [&_pre]:text-xs [&_pre]:rounded [&_code]:text-[#98bc37] [&_p]:m-0 [&_p]:mb-1.5 [&_h1]:text-sm [&_h2]:text-sm [&_h3]:text-xs [&_h1]:mt-2 [&_h2]:mt-2 [&_h3]:mt-1 [&_ul]:my-1 [&_ol]:my-1 [&_li]:my-0">
                <ReactMarkdown>{session.agent_raw_output}</ReactMarkdown>
              </div>
            </div>
          </details>
        )}
        {session.attack_plan && (
          <details open className="border-b border-[#2e2b26]">
            <summary className="px-3 py-1.5 cursor-pointer text-[#7fd962] font-bold hover:bg-[#2e2b26] flex items-center gap-1.5">
              <Zap className="w-3 h-3" />ATTACK PLAN
            </summary>
            <div className="relative">
              <button onClick={() => copyToClipboard(tryPrettyJson(session.attack_plan), 'plan')} className="absolute top-1.5 right-2 z-10 text-[#918175] hover:text-[#fce8c3] p-0.5" title="Copy to clipboard">
                {copied === 'plan' ? <Check className="w-3.5 h-3.5 text-[#98bc37]" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
              <div className="px-3 py-2 bg-[#141310] text-[#fce8c3] overflow-x-auto prose prose-xs prose-invert max-w-none [&_pre]:bg-[#0c0b09] [&_pre]:p-2 [&_pre]:text-xs [&_pre]:rounded [&_code]:text-[#98bc37] [&_p]:m-0 [&_p]:mb-1.5 [&_h1]:text-sm [&_h2]:text-sm [&_h3]:text-xs [&_h1]:mt-2 [&_h2]:mt-2 [&_h3]:mt-1 [&_ul]:my-1 [&_ol]:my-1 [&_li]:my-0">
                <ReactMarkdown>{tryPrettyJson(session.attack_plan)}</ReactMarkdown>
              </div>
            </div>
          </details>
        )}
        {session.triage_result && (
          <details className="border-b border-[#2e2b26]">
            <summary className="px-3 py-1.5 cursor-pointer text-[#7fd962] font-bold hover:bg-[#2e2b26] flex items-center gap-1.5">
              <Bug className="w-3 h-3" />TRIAGE RESULT
            </summary>
            <div className="relative">
              <button onClick={() => copyToClipboard(tryPrettyJson(session.triage_result), 'triage')} className="absolute top-1.5 right-2 text-[#918175] hover:text-[#fce8c3] p-0.5" title="Copy to clipboard">
                {copied === 'triage' ? <Check className="w-3.5 h-3.5 text-[#98bc37]" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
              <pre className="px-3 py-2 bg-[#141310] text-[#fce8c3] whitespace-pre-wrap break-all font-mono overflow-x-auto">{tryPrettyJson(session.triage_result)}</pre>
            </div>
          </details>
        )}
      </div>
    </div>
  );
}

export default function AgentsPage() {
  const h = useAgentsLogic();

  const inputClass = 'bg-[#141310] border border-[#2e2b26] text-[#fce8c3] text-xs px-2 py-1 focus:outline-none focus:border-[#7fd962]/50 w-full';
  const modeBtnClass = (active: boolean) =>
    `px-3 py-0.5 text-xs font-bold transition-colors ${active ? 'text-[#7fd962] bg-[#7fd962]/10' : 'text-[#918175] hover:text-[#fce8c3]'}`;

  return (
    <PageShell>
      <div className="flex flex-col" style={{ height: 'calc(100vh - 68px)', minHeight: 500 }}>

        {/* ── Top: Config (full width) ── */}
        <div className="shrink-0 border border-[#2e2b26] bg-[#1c1b19] flex flex-col overflow-hidden">
          {/* Header with scan button */}
          <div className="px-3 py-2 border-b border-[#2e2b26] shrink-0 flex items-center justify-between">
            <h2 className="text-[#7fd962] text-xs font-bold tracking-wide">AGENTIC SCAN</h2>
            {h.isScanStreaming && (
              <span className="text-xs text-[#68a8e4] flex items-center gap-1"><Loader2 className="w-3 h-3 animate-spin" /> streaming...</span>
            )}
          </div>

          <div className="overflow-y-auto px-3 py-2 space-y-3">
            {/* Target + GitHub/Upload — same row */}
            <div className="grid grid-cols-3 gap-2 items-stretch">
              {/* Target input — 2/3 */}
              <div className="col-span-2 flex flex-col">
                <div className="flex items-center gap-1.5 mb-0.5" style={{ minHeight: '1.25rem' }}>
                  <label className="text-[#918175] text-xs">Target</label>
                  <span className="text-[10px]" style={{ color: INPUT_TYPE_LABELS[h.detectedInputType].color }}>
                    (type: {h.detectedInputType === 'empty' ? 'url' : h.detectedInputType === 'raw' ? 'raw request' : h.detectedInputType})
                  </span>
                </div>
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
                {h.scanError && <p className="text-xs text-[#ef2f27] mt-1">{h.scanError}</p>}
              </div>
              {/* GitHub Repo + Upload — 1/3 */}
              <div className="flex flex-col gap-1.5">
                <label className="text-[#918175] text-xs mb-0.5">GitHub Repo</label>
                <GitHubRepoPicker onSelect={(url) => h.setSwarmSource(url)} selectedRepo={h.swarmSource.includes('x-access-token') ? h.swarmSource.replace(/https:\/\/x-access-token:[^@]+@github\.com\//, '').replace('.git', '') : undefined} />
                <div
                  onDragEnter={h.onUploadDragEnter} onDragLeave={h.onUploadDragLeave} onDragOver={h.onUploadDragOver} onDrop={h.onUploadDrop}
                  className={`border border-dashed p-2 text-center transition-colors flex-1 ${h.uploadCompressing || h.uploadRepo.isPending ? '' : 'cursor-pointer'} ${h.uploadDragging ? 'border-[#7fd962] bg-[#7fd962]/10' : h.swarmSource ? 'border-[#98bc37] bg-[#98bc37]/5' : 'border-[#2e2b26] hover:border-[#7fd962]/50'}`}
                  onClick={() => { if (!h.uploadCompressing && !h.uploadRepo.isPending) h.uploadFileInputRef.current?.click(); }}
                >
                  <input ref={h.uploadFileInputRef} type="file" accept=".zip,.tar.gz,.tgz,.tar" onChange={h.handleFileUpload} className="hidden" />
                  {h.uploadCompressing || h.uploadRepo.isPending ? (
                    <div className="flex items-center justify-center gap-1.5"><Loader2 className="w-3.5 h-3.5 text-[#7fd962] animate-spin" /><span className="text-[10px] text-[#fce8c3]">{h.uploadCompressing ? 'Compressing...' : 'Uploading...'}</span></div>
                  ) : (
                    <div className="flex items-center justify-center gap-1.5"><Upload className="w-3.5 h-3.5 text-[#7fd962]/70" /><span className="text-[10px] text-[#fce8c3]">{h.uploadDragging ? 'Drop here' : 'Upload source code'}</span></div>
                  )}
                  <p className="text-[9px] text-[#918175] mt-0.5">.zip, .tar.gz, folder — max 500 MB</p>
                  {h.swarmSource && (
                    <p className="text-[9px] text-[#918175] mt-0.5 truncate" title={h.swarmSource.includes('x-access-token') ? 'Authenticated clone URL' : h.swarmSource}>
                      {h.swarmSource.includes('x-access-token') ? h.swarmSource.replace(/https:\/\/x-access-token:[^@]+@/, 'https://') : h.swarmSource}
                    </p>
                  )}
                  {h.uploadRepo.isSuccess && <p className="text-[9px] text-[#98bc37] mt-0.5">uploaded</p>}
                  {h.uploadRepo.isError && <p className="text-[9px] text-[#ef2f27] mt-0.5">failed</p>}
                </div>
              </div>
            </div>

            {/* Scanning Mode */}
            <div>
              <label className="text-[#918175] text-xs block mb-1">Scanning Mode</label>
              {/* Top-level mode selector */}
              <div className="grid grid-cols-2 gap-0">
                <button
                  onClick={() => h.setScanProfile('autopilot')}
                  className={`px-3 py-2 text-center border transition-colors ${
                    h.scanProfile === 'autopilot'
                      ? 'border-[#7fd962] bg-[#7fd962]/10'
                      : 'border-[#2e2b26] hover:border-[#918175] hover:bg-[#2e2b26]/30'
                  }`}
                >
                  <div className="flex items-center justify-center gap-1.5 mb-0.5">
                    <Bot className={`w-3 h-3 ${h.scanProfile === 'autopilot' ? 'text-[#7fd962]' : 'text-[#918175]'}`} />
                    <span className={`text-xs font-bold ${h.scanProfile === 'autopilot' ? 'text-[#7fd962]' : 'text-[#fce8c3]'}`}>AUTOPILOT</span>
                  </div>
                  <p className="text-[10px] text-[#706560] leading-tight">AI agent drives the CLI autonomously — explores, scans, and iterates on findings.</p>
                </button>
                <button
                  onClick={() => { if (h.scanProfile === 'autopilot') h.setScanProfile('quick'); }}
                  className={`px-3 py-2 text-center border transition-colors ${
                    h.scanProfile !== 'autopilot'
                      ? 'border-[#7fd962] bg-[#7fd962]/10'
                      : 'border-[#2e2b26] hover:border-[#918175] hover:bg-[#2e2b26]/30'
                  }`}
                >
                  <div className="flex items-center justify-center gap-1.5 mb-0.5">
                    <Bug className={`w-3 h-3 ${h.scanProfile !== 'autopilot' ? 'text-[#7fd962]' : 'text-[#918175]'}`} />
                    <span className={`text-xs font-bold ${h.scanProfile !== 'autopilot' ? 'text-[#7fd962]' : 'text-[#fce8c3]'}`}>SWARM</span>
                  </div>
                  <p className="text-[10px] text-[#706560] leading-tight">AI-guided targeted vulnerability scan with module selection.</p>
                </button>
              </div>
            </div>

            {/* Start Scan / Stop + Advanced toggle */}
            <div className="flex items-center gap-2">
              {!h.isScanStreaming ? (
                <button
                  onClick={h.handleProfileSubmit}
                  disabled={!h.targetUrl.trim()}
                  className="px-4 py-1 text-xs font-bold border border-[#FF9F2F] text-[#FF9F2F] bg-[#FF9F2F]/10 hover:bg-[#FF9F2F]/20 shadow-[inset_0_0_18px_rgba(255,159,47,0.5)] hover:shadow-[inset_0_0_28px_rgba(255,159,47,0.7)] transition-colors disabled:opacity-30 flex items-center gap-1.5"
                >
                  <Play className="w-3.5 h-3.5" /> START SCAN
                </button>
              ) : (
                <button
                  onClick={h.handleScanCancel}
                  className="px-4 py-1 text-xs font-bold bg-[#ef2f27]/10 text-[#ef2f27] border border-[#ef2f27]/30 hover:bg-[#ef2f27]/20 transition-colors flex items-center gap-1.5"
                >
                  <Square className="w-3 h-3" /> STOP
                </button>
              )}
              <button
                onClick={() => h.setShowAdvanced(!h.showAdvanced)}
                className={`px-3 py-1 text-xs font-bold border flex items-center gap-1 transition-colors ${
                  h.showAdvanced
                    ? 'border-[#918175] bg-[#918175]/10 text-[#918175]'
                    : 'border-[#2e2b26] text-[#706560] hover:border-[#918175] hover:text-[#918175]'
                }`}
              >
                <Settings2 className="w-3 h-3" /> ADVANCED
              </button>
            </div>

            {/* Advanced Options */}
            {h.showAdvanced && (
              <div className="mt-2 space-y-2">
                {/* Swarm sub-profiles */}
                {h.scanProfile !== 'autopilot' && (
                  <div>
                    <label className="text-[#918175] text-[10px] block mb-0.5">Swarm Profile</label>
                    <div className="flex gap-0">
                      {PROFILE_OPTIONS.filter((p) => p.value !== 'autopilot').map((p) => {
                        const Icon = PROFILE_ICONS[p.icon] || Zap;
                        const active = h.scanProfile === p.value;
                        return (
                          <button
                            key={p.value}
                            onClick={() => h.setScanProfile(p.value)}
                            className={`flex-1 px-2 py-1 text-center border transition-colors ${
                              active
                                ? 'border-[#68a8e4] bg-[#68a8e4]/10'
                                : 'border-[#2e2b26] hover:border-[#918175] hover:bg-[#2e2b26]/30'
                            }`}
                          >
                            <div className="flex items-center justify-center gap-1 mb-0.5">
                              <Icon className={`w-3 h-3 ${active ? 'text-[#68a8e4]' : 'text-[#918175]'}`} />
                              <span className={`text-[10px] font-bold ${active ? 'text-[#68a8e4]' : 'text-[#fce8c3]'}`}>{p.label}</span>
                            </div>
                            <p className="text-[9px] text-[#706560] leading-tight">{p.description}</p>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}
                {/* Swarm options (default mode) */}
                {h.advancedMode === 'swarm' && (
                  <div className="space-y-1.5">
                    <div className="grid grid-cols-4 gap-1.5">
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Module Tags</label>
                        <input value={h.swarmModuleTags} onChange={(e) => h.setSwarmModuleTags(e.target.value)} placeholder="xss, sqli" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Vuln Type</label>
                        <input value={h.swarmVulnType} onChange={(e) => h.setSwarmVulnType(e.target.value)} placeholder="sqli" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Max Iterations</label>
                        <input value={h.swarmMaxIterations} onChange={(e) => h.setSwarmMaxIterations(e.target.value)} placeholder="3" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Timeout</label>
                        <input value={h.swarmTimeout} onChange={(e) => h.setSwarmTimeout(e.target.value)} placeholder="30m" className={inputClass} />
                      </div>
                    </div>
                    <div>
                      <label className="text-[#918175] text-[10px] block mb-0.5">Instruction</label>
                      <textarea value={h.swarmInstruction} onChange={(e) => h.setSwarmInstruction(e.target.value)} placeholder="Focus on business logic flaws..." rows={2} className={`${inputClass} resize-y`} />
                    </div>
                    <div className="grid grid-cols-4 gap-1.5">
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Focus</label>
                        <input value={h.swarmFocus} onChange={(e) => h.setSwarmFocus(e.target.value)} placeholder="auth bypass" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Profile</label>
                        <input value={h.swarmProfile} onChange={(e) => h.setSwarmProfile(e.target.value)} placeholder="thorough" className={inputClass} />
                      </div>
                      <div className="col-span-2 flex flex-wrap items-end gap-1">
                        {([
                          ['Discover', h.swarmDiscover, h.setSwarmDiscover] as const,
                          ['Source Only', h.swarmSourceAnalysisOnly, h.setSwarmSourceAnalysisOnly] as const,
                          ['Code Audit', h.swarmCodeAudit, h.setSwarmCodeAudit] as const,
                          ['Skip SAST', h.swarmSkipSast, h.setSwarmSkipSast] as const,
                          ['Dry Run', h.swarmDryRun, h.setSwarmDryRun] as const,
                        ]).map(([label, value, setter]) => (
                          <button key={label} type="button" onClick={() => setter(!value)}
                            className={`px-2.5 py-1 text-xs font-bold border transition-colors ${
                              value
                                ? 'border-[#7fd962] bg-[#7fd962]/15 text-[#7fd962]'
                                : 'border-[#2e2b26] text-[#918175] hover:border-[#918175]'
                            }`}
                          >{label}</button>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {/* Autopilot options */}
                {h.advancedMode === 'autopilot' && (
                  <div className="space-y-1.5">
                    <div className="grid grid-cols-4 gap-1.5">
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Agent</label>
                        <Dropdown value={h.autopilotAgent} onChange={h.setAutopilotAgent} options={AGENT_OPTIONS} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Focus</label>
                        <input value={h.autopilotFocus} onChange={(e) => h.setAutopilotFocus(e.target.value)} placeholder="auth, api" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Timeout</label>
                        <input value={h.autopilotTimeout} onChange={(e) => h.setAutopilotTimeout(e.target.value)} placeholder="30m" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Max Commands</label>
                        <input value={h.autopilotMaxCommands} onChange={(e) => h.setAutopilotMaxCommands(e.target.value)} placeholder="50" className={inputClass} />
                      </div>
                    </div>
                    <div>
                      <label className="text-[#918175] text-[10px] block mb-0.5">System Prompt</label>
                      <textarea value={h.autopilotSystemPrompt} onChange={(e) => h.setAutopilotSystemPrompt(e.target.value)} placeholder="Custom system prompt..." rows={2} className={`${inputClass} resize-y`} />
                    </div>
                    <div className="flex items-center gap-1">
                      <button type="button" onClick={() => h.setAutopilotDryRun(!h.autopilotDryRun)}
                        className={`px-2 py-0.5 text-[9px] font-bold border transition-colors ${
                          h.autopilotDryRun
                            ? 'border-[#7fd962] bg-[#7fd962]/15 text-[#7fd962]'
                            : 'border-[#2e2b26] text-[#918175] hover:border-[#918175]'
                        }`}
                      >Dry Run</button>
                    </div>
                  </div>
                )}

                {/* Query options */}
                {h.advancedMode === 'query' && (
                  <div className="space-y-2">
                    <div className="flex border border-[#2e2b26]">
                      <button onClick={() => h.setScanMode('template')} className={modeBtnClass(h.scanMode === 'template')}>TEMPLATE</button>
                      <button onClick={() => h.setScanMode('custom')} className={modeBtnClass(h.scanMode === 'custom')}>CUSTOM</button>
                    </div>
                    {h.scanMode === 'template' ? (
                      <>
                        <div>
                          <label className="text-[#918175] text-xs block mb-0.5">Agent</label>
                          <input value={h.agentName} onChange={(e) => h.setAgentName(e.target.value)} placeholder="claude" className={inputClass} />
                        </div>
                        <div>
                          <label className="text-[#918175] text-xs block mb-0.5">Prompt Template</label>
                          <input value={h.promptTemplate} onChange={(e) => h.setPromptTemplate(e.target.value)} placeholder="security-analysis" className={inputClass} />
                        </div>
                      </>
                    ) : (
                      <div>
                        <label className="text-[#918175] text-xs block mb-0.5">Prompt</label>
                        <textarea value={h.customPrompt} onChange={(e) => h.setCustomPrompt(e.target.value)} placeholder="Enter your prompt..." rows={3} className={`${inputClass} resize-y`} />
                      </div>
                    )}
                    <div>
                      <label className="text-[#918175] text-xs block mb-0.5">Files <span className="text-[#706560] italic">comma-sep</span></label>
                      <input value={h.queryFiles} onChange={(e) => h.setQueryFiles(e.target.value)} placeholder="src/main.go" className={inputClass} />
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
          <div className="flex-1 border border-t-0 border-[#2e2b26] bg-[#141310] flex flex-col overflow-hidden">
            <div className="px-3 py-1.5 border-b border-[#2e2b26] flex items-center justify-between shrink-0">
              <span className="text-[#7fd962] text-xs font-bold flex items-center gap-1.5">
                <ScrollText className="w-3 h-3" />STREAMING RESPONSE
              </span>
              <div className="flex items-center gap-3">
                {h.isScanStreaming && (
                  <span className="text-xs text-[#68a8e4] flex items-center gap-1"><Loader2 className="w-3 h-3 animate-spin" /> streaming...</span>
                )}
                {h.scanResult && (
                  <span className="text-xs text-[#918175]">
                    {h.scanResult.finding_count != null && <span className="text-[#fce8c3] mr-3">findings: <b className="text-[#7fd962]">{String(h.scanResult.finding_count)}</b></span>}
                    {h.scanResult.saved_count != null && <span className="text-[#fce8c3]">saved: <b className="text-[#98bc37]">{String(h.scanResult.saved_count)}</b></span>}
                  </span>
                )}
              </div>
            </div>
            <pre ref={h.scanOutputRef} className="flex-1 overflow-auto p-3 text-xs text-[#a89888] font-mono whitespace-pre-wrap leading-relaxed">
              {h.scanOutput || (
                <span className="text-[#403d38]">
                  {h.sessionsData?.data && h.sessionsData.data.length > 0
                    ? 'Select a session below or start a new scan...'
                    : 'agent output will appear here...'}
                </span>
              )}
            </pre>
          </div>

          {/* Sessions — open by default when there are sessions and no active scan */}
          <details open={!h.scanOutput && !!(h.sessionsData?.data?.length)} className="border border-t-0 border-[#2e2b26] bg-[#1c1b19] overflow-hidden shrink-0">
            <summary className="px-3 py-1.5 border-b border-[#2e2b26] cursor-pointer hover:bg-[#2e2b26]/30 list-none [&::-webkit-details-marker]:hidden flex items-center gap-1.5">
              <ChevronDown className="w-3 h-3 text-[#7fd962] transition-transform [[open]>&]:rotate-0 [details:not([open])>&]:-rotate-90" />
              <span className="text-[#7fd962] text-xs font-bold inline-flex items-center gap-1.5">
                <Layers className="w-3 h-3" />AGENT SESSIONS
                {h.sessionsData?.total != null && <span className="text-[#918175] font-normal ml-1">({h.sessionsData.total})</span>}
              </span>
            </summary>
            <div className="flex max-h-[300px]" style={{ minHeight: h.expandedSessionUuid && h.sessionDetail ? 280 : undefined }}>
              <div className={`${h.expandedSessionUuid && h.sessionDetail ? 'w-1/2' : 'w-full'} overflow-auto`}>
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-[#2e2b26] text-[#706560]">
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
                          className={`border-b border-[#2e2b26]/50 hover:bg-[#2e2b26]/30 cursor-pointer ${h.expandedSessionUuid === s.uuid ? 'bg-[#2e2b26]' : ''}`}
                        >
                          <td className="px-2 py-1"><StatusBadge status={s.status} /></td>
                          <td className="px-2 py-1 text-[#68a8e4] font-mono">{s.uuid.slice(0, 8)}</td>
                          <td className="px-2 py-1 text-[#918175]">{s.mode}</td>
                          <td className="px-2 py-1 text-[#fce8c3]">{s.target_url ? truncate(s.target_url, 30) : '\u2014'}</td>
                          <td className="px-2 py-1 text-right text-[#fce8c3]">{s.finding_count}</td>
                          <td className="px-2 py-1 text-right text-[#98bc37]">{s.saved_count}</td>
                          <td className="px-2 py-1 text-right text-[#fce8c3]">{formatDuration(s.duration_ms)}</td>
                        </tr>
                      ))
                    ) : (
                      <tr><td colSpan={7} className="px-3 py-3 text-center text-[#403d38]">no sessions</td></tr>
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
