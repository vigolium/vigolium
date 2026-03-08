'use client';

import { useState, useRef, useCallback, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import { Play, Square, Send, Bot, Terminal, MessageSquare, Clock, CheckCircle, XCircle, Loader2, Zap, Layers } from 'lucide-react';
import { useAgentRuns } from '@/api/hooks';
import { fetchSSE } from '@/lib/sse';
import type { AgentRunStatusResponse } from '@/api/types';
import PageShell from './PageShell';

type MainTab = 'query' | 'autopilot' | 'pipeline' | 'chat';
type ScanMode = 'template' | 'custom';

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

const PIPELINE_PHASES = ['discover', 'plan', 'scan', 'triage', 'rescan', 'report'] as const;

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

function PipelineProgress({ currentPhase, phasesCompleted }: { currentPhase: string; phasesCompleted: string[] }) {
  return (
    <div className="flex items-center gap-1 px-3 py-2 border-x border-[#bbc3c4] bg-[#f6edda]">
      {PIPELINE_PHASES.map((phase, i) => {
        const completed = phasesCompleted.includes(phase);
        const active = currentPhase === phase;
        const color = completed ? '#00b368' : active ? '#0078c8' : '#bbc3c4';
        return (
          <div key={phase} className="flex items-center gap-1">
            {i > 0 && <span className="text-[#bbc3c4] text-xs mx-0.5">→</span>}
            <span className="flex items-center gap-0.5 text-xs font-bold" style={{ color }}>
              {active && <Loader2 className="w-3 h-3 animate-spin" />}
              {completed && <CheckCircle className="w-3 h-3" />}
              {phase.toUpperCase()}
            </span>
          </div>
        );
      })}
    </div>
  );
}

export default function AgentsPage() {
  const [mainTab, setMainTab] = useState<MainTab>('query');

  // Query tab state
  const [scanMode, setScanMode] = useState<ScanMode>('template');
  const [agentName, setAgentName] = useState('');
  const [promptTemplate, setPromptTemplate] = useState('');
  const [customPrompt, setCustomPrompt] = useState('');
  const [repoPath, setRepoPath] = useState('');
  const [files, setFiles] = useState('');
  const [append, setAppend] = useState('');
  const [source, setSource] = useState('');
  const [scanUuid, setScanUuid] = useState('');
  const [scanOutput, setScanOutput] = useState('');
  const [scanResult, setScanResult] = useState<Record<string, unknown> | null>(null);
  const [scanError, setScanError] = useState('');

  // Autopilot tab state
  const [autopilotTarget, setAutopilotTarget] = useState('');
  const [autopilotAgent, setAutopilotAgent] = useState('');
  const [autopilotFocus, setAutopilotFocus] = useState('');
  const [autopilotTimeout, setAutopilotTimeout] = useState('');
  const [autopilotSystemPrompt, setAutopilotSystemPrompt] = useState('');
  const [autopilotMaxCommands, setAutopilotMaxCommands] = useState('');
  const [autopilotDryRun, setAutopilotDryRun] = useState(false);
  const [autopilotRepoPath, setAutopilotRepoPath] = useState('');
  const [autopilotFiles, setAutopilotFiles] = useState('');
  const [autopilotScanUuid, setAutopilotScanUuid] = useState('');

  // Pipeline tab state
  const [pipelineTarget, setPipelineTarget] = useState('');
  const [pipelineAgent, setPipelineAgent] = useState('');
  const [pipelineFocus, setPipelineFocus] = useState('');
  const [pipelineProfile, setPipelineProfile] = useState('');
  const [pipelineTimeout, setPipelineTimeout] = useState('');
  const [pipelineMaxRescanRounds, setPipelineMaxRescanRounds] = useState('');
  const [pipelineSkipPhases, setPipelineSkipPhases] = useState('');
  const [pipelineStartFrom, setPipelineStartFrom] = useState('');
  const [pipelineDryRun, setPipelineDryRun] = useState(false);
  const [pipelineRepoPath, setPipelineRepoPath] = useState('');
  const [pipelineFiles, setPipelineFiles] = useState('');
  const [pipelineScanUuid, setPipelineScanUuid] = useState('');
  const [pipelineProjectUuid, setPipelineProjectUuid] = useState('');
  const [currentPhase, setCurrentPhase] = useState('');
  const [phasesCompleted, setPhasesCompleted] = useState<string[]>([]);

  // Chat tab state
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState('');

  // Shared state
  const [isStreaming, setIsStreaming] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const scanOutputRef = useRef<HTMLPreElement>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);

  // Agent run history
  const { data: runsData } = useAgentRuns();

  const scrollScanOutput = useCallback(() => {
    if (scanOutputRef.current) {
      scanOutputRef.current.scrollTop = scanOutputRef.current.scrollHeight;
    }
  }, []);

  const scrollChatToBottom = useCallback(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  useEffect(scrollChatToBottom, [messages, scrollChatToBottom]);

  const handleCancel = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    setIsStreaming(false);
  }, []);

  const handleQuerySubmit = useCallback(() => {
    if (isStreaming) return;
    setScanOutput('');
    setScanResult(null);
    setScanError('');
    setIsStreaming(true);

    const abort = new AbortController();
    abortRef.current = abort;

    const body: Record<string, unknown> = { stream: true };
    if (scanMode === 'template') {
      if (agentName) body.agent = agentName;
      if (promptTemplate) body.prompt_template = promptTemplate;
    } else {
      if (customPrompt) body.prompt = customPrompt;
    }
    if (repoPath) body.repo_path = repoPath;
    if (files) body.files = files.split(',').map((f) => f.trim()).filter(Boolean);
    if (append) body.append = append;
    if (source) body.source = source;
    if (scanUuid) body.scan_uuid = scanUuid;

    fetchSSE('/api/agent/run/query', body, {
      onChunk: (text) => {
        setScanOutput((prev) => prev + text);
        setTimeout(scrollScanOutput, 0);
      },
      onDone: (result) => {
        setIsStreaming(false);
        abortRef.current = null;
        if (result && typeof result === 'object') setScanResult(result as Record<string, unknown>);
      },
      onError: (err) => {
        setIsStreaming(false);
        abortRef.current = null;
        setScanError(err.message);
      },
    }, abort.signal);
  }, [isStreaming, scanMode, agentName, promptTemplate, customPrompt, repoPath, files, append, source, scanUuid, scrollScanOutput]);

  const handleAutopilotSubmit = useCallback(() => {
    if (isStreaming || !autopilotTarget.trim()) return;
    setScanOutput('');
    setScanResult(null);
    setScanError('');
    setIsStreaming(true);

    const abort = new AbortController();
    abortRef.current = abort;

    const body: Record<string, unknown> = { target: autopilotTarget.trim(), stream: true };
    if (autopilotAgent) body.agent = autopilotAgent;
    if (autopilotFocus) body.focus = autopilotFocus;
    if (autopilotTimeout) body.timeout = autopilotTimeout;
    if (autopilotSystemPrompt) body.system_prompt = autopilotSystemPrompt;
    if (autopilotMaxCommands) body.max_commands = parseInt(autopilotMaxCommands, 10);
    if (autopilotDryRun) body.dry_run = true;
    if (autopilotRepoPath) body.repo_path = autopilotRepoPath;
    if (autopilotFiles) body.files = autopilotFiles.split(',').map((f) => f.trim()).filter(Boolean);
    if (autopilotScanUuid) body.scan_uuid = autopilotScanUuid;

    fetchSSE('/api/agent/run/autopilot', body, {
      onChunk: (text) => {
        setScanOutput((prev) => prev + text);
        setTimeout(scrollScanOutput, 0);
      },
      onDone: (result) => {
        setIsStreaming(false);
        abortRef.current = null;
        if (result && typeof result === 'object') setScanResult(result as Record<string, unknown>);
      },
      onError: (err) => {
        setIsStreaming(false);
        abortRef.current = null;
        setScanError(err.message);
      },
    }, abort.signal);
  }, [isStreaming, autopilotTarget, autopilotAgent, autopilotFocus, autopilotTimeout, autopilotSystemPrompt, autopilotMaxCommands, autopilotDryRun, autopilotRepoPath, autopilotFiles, autopilotScanUuid, scrollScanOutput]);

  const handlePipelineSubmit = useCallback(() => {
    if (isStreaming || !pipelineTarget.trim()) return;
    setScanOutput('');
    setScanResult(null);
    setScanError('');
    setCurrentPhase('');
    setPhasesCompleted([]);
    setIsStreaming(true);

    const abort = new AbortController();
    abortRef.current = abort;

    const body: Record<string, unknown> = { target: pipelineTarget.trim(), stream: true };
    if (pipelineAgent) body.agent = pipelineAgent;
    if (pipelineFocus) body.focus = pipelineFocus;
    if (pipelineProfile) body.profile = pipelineProfile;
    if (pipelineTimeout) body.timeout = pipelineTimeout;
    if (pipelineMaxRescanRounds) body.max_rescan_rounds = parseInt(pipelineMaxRescanRounds, 10);
    if (pipelineSkipPhases) body.skip_phases = pipelineSkipPhases.split(',').map((p) => p.trim()).filter(Boolean);
    if (pipelineStartFrom) body.start_from = pipelineStartFrom;
    if (pipelineDryRun) body.dry_run = true;
    if (pipelineRepoPath) body.repo_path = pipelineRepoPath;
    if (pipelineFiles) body.files = pipelineFiles.split(',').map((f) => f.trim()).filter(Boolean);
    if (pipelineScanUuid) body.scan_uuid = pipelineScanUuid;
    if (pipelineProjectUuid) body.project_uuid = pipelineProjectUuid;

    fetchSSE('/api/agent/run/pipeline', body, {
      onChunk: (text) => {
        setScanOutput((prev) => prev + text);
        setTimeout(scrollScanOutput, 0);
      },
      onDone: (result) => {
        setIsStreaming(false);
        abortRef.current = null;
        if (result && typeof result === 'object') setScanResult(result as Record<string, unknown>);
      },
      onError: (err) => {
        setIsStreaming(false);
        abortRef.current = null;
        setScanError(err.message);
      },
      onPhase: (phase) => {
        setCurrentPhase((prev) => {
          if (prev && prev !== phase) {
            setPhasesCompleted((completed) => completed.includes(prev) ? completed : [...completed, prev]);
          }
          return phase;
        });
      },
    }, abort.signal);
  }, [isStreaming, pipelineTarget, pipelineAgent, pipelineFocus, pipelineProfile, pipelineTimeout, pipelineMaxRescanRounds, pipelineSkipPhases, pipelineStartFrom, pipelineDryRun, pipelineRepoPath, pipelineFiles, pipelineScanUuid, pipelineProjectUuid, scrollScanOutput]);

  const handleChatSend = useCallback(() => {
    const text = chatInput.trim();
    if (!text || isStreaming) return;
    setChatInput('');
    const newMessages: ChatMessage[] = [...messages, { role: 'user', content: text }];
    setMessages(newMessages);
    setIsStreaming(true);

    const abort = new AbortController();
    abortRef.current = abort;

    setMessages((prev) => [...prev, { role: 'assistant', content: '' }]);

    const body = {
      model: 'default',
      messages: newMessages.map((m) => ({ role: m.role, content: m.content })),
    };

    fetchSSE('/api/agent/chat/completions', body, {
      onChunk: (chunk) => {
        setMessages((prev) => {
          const updated = [...prev];
          const last = updated[updated.length - 1];
          if (last && last.role === 'assistant') {
            updated[updated.length - 1] = { ...last, content: last.content + chunk };
          }
          return updated;
        });
      },
      onDone: () => {
        setIsStreaming(false);
        abortRef.current = null;
      },
      onError: (err) => {
        setIsStreaming(false);
        abortRef.current = null;
        setMessages((prev) => {
          const updated = [...prev];
          const last = updated[updated.length - 1];
          if (last && last.role === 'assistant') {
            updated[updated.length - 1] = { ...last, content: last.content + `\n\n**Error:** ${err.message}` };
          }
          return updated;
        });
      },
    }, abort.signal);
  }, [chatInput, isStreaming, messages]);

  const handleChatKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleChatSend();
    }
  }, [handleChatSend]);

  const tabBtnClass = (active: boolean) =>
    `px-3 py-0.5 text-xs font-bold transition-colors ${
      active ? 'text-[#0078c8] bg-[#0078c8]/10' : 'text-[#708e8e] hover:text-[#005661]'
    }`;

  const inputClass = 'bg-[#ede4d1] border border-[#bbc3c4] text-[#005661] text-xs px-2 py-1 focus:outline-none focus:border-[#0078c8]/50 w-full';

  const showOutputPanel = mainTab === 'query' || mainTab === 'autopilot' || mainTab === 'pipeline';

  return (
    <PageShell>
      <div className="flex flex-col" style={{ height: 'calc(100vh - 120px)', minHeight: 500 }}>
        {/* Tab bar */}
        <div className="px-3 py-1.5 border border-[#bbc3c4] bg-[#f6edda] flex items-center gap-1.5">
          <div className="flex border border-[#bbc3c4]">
            <button onClick={() => setMainTab('query')} className={tabBtnClass(mainTab === 'query')}>
              <span className="flex items-center gap-1"><Terminal className="w-3 h-3" />QUERY</span>
            </button>
            <button onClick={() => setMainTab('autopilot')} className={tabBtnClass(mainTab === 'autopilot')}>
              <span className="flex items-center gap-1"><Zap className="w-3 h-3" />AUTOPILOT</span>
            </button>
            <button onClick={() => setMainTab('pipeline')} className={tabBtnClass(mainTab === 'pipeline')}>
              <span className="flex items-center gap-1"><Layers className="w-3 h-3" />PIPELINE</span>
            </button>
            <button onClick={() => setMainTab('chat')} className={tabBtnClass(mainTab === 'chat')}>
              <span className="flex items-center gap-1"><MessageSquare className="w-3 h-3" />CHAT</span>
            </button>
          </div>
          {isStreaming && (
            <span className="text-xs text-[#0078c8] flex items-center gap-1 ml-2">
              <Loader2 className="w-3 h-3 animate-spin" /> streaming…
            </span>
          )}
        </div>

        {/* Query tab */}
        {mainTab === 'query' && (
          <div className="px-3 py-2 border-x border-[#bbc3c4] bg-[#f6edda] space-y-2">
            <div className="flex items-center gap-2">
              <div className="flex border border-[#bbc3c4]">
                <button onClick={() => setScanMode('template')} className={tabBtnClass(scanMode === 'template')}>TEMPLATE</button>
                <button onClick={() => setScanMode('custom')} className={tabBtnClass(scanMode === 'custom')}>CUSTOM PROMPT</button>
              </div>
            </div>

            {scanMode === 'template' ? (
              <div className="grid grid-cols-3 gap-2">
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Agent</label>
                  <input value={agentName} onChange={(e) => setAgentName(e.target.value)} placeholder="claude" className={inputClass} />
                </div>
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Prompt Template</label>
                  <input value={promptTemplate} onChange={(e) => setPromptTemplate(e.target.value)} placeholder="security-analysis" className={inputClass} />
                </div>
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Repo Path</label>
                  <input value={repoPath} onChange={(e) => setRepoPath(e.target.value)} placeholder="/path/to/repo" className={inputClass} />
                </div>
              </div>
            ) : (
              <div>
                <label className="text-[#708e8e] text-xs block mb-0.5">Prompt</label>
                <textarea
                  value={customPrompt}
                  onChange={(e) => setCustomPrompt(e.target.value)}
                  placeholder="Enter your prompt for the agent..."
                  rows={3}
                  className={`${inputClass} resize-y`}
                />
              </div>
            )}

            <details className="group">
              <summary className="text-[#bbc3c4] text-xs cursor-pointer hover:text-[#708e8e] select-none">optional fields</summary>
              <div className="grid grid-cols-3 gap-2 mt-1.5">
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Files (comma-separated)</label>
                  <input value={files} onChange={(e) => setFiles(e.target.value)} placeholder="src/main.go, pkg/api.go" className={inputClass} />
                </div>
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Append</label>
                  <input value={append} onChange={(e) => setAppend(e.target.value)} placeholder="Additional context" className={inputClass} />
                </div>
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Source</label>
                  <input value={source} onChange={(e) => setSource(e.target.value)} placeholder="dashboard" className={inputClass} />
                </div>
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Scan UUID</label>
                  <input value={scanUuid} onChange={(e) => setScanUuid(e.target.value)} placeholder="uuid" className={inputClass} />
                </div>
              </div>
            </details>

            <div className="flex items-center gap-2">
              {!isStreaming ? (
                <button
                  onClick={handleQuerySubmit}
                  className="flex items-center gap-1 px-3 py-1 text-xs font-bold bg-[#00b368]/10 text-[#00b368] border border-[#00b368]/30 hover:bg-[#00b368]/20 transition-colors"
                >
                  <Play className="w-3 h-3" /> RUN QUERY
                </button>
              ) : (
                <button
                  onClick={handleCancel}
                  className="flex items-center gap-1 px-3 py-1 text-xs font-bold bg-[#e34e1c]/10 text-[#e34e1c] border border-[#e34e1c]/30 hover:bg-[#e34e1c]/20 transition-colors"
                >
                  <Square className="w-3 h-3" /> CANCEL
                </button>
              )}
              {scanError && <span className="text-xs text-[#e34e1c]">{scanError}</span>}
            </div>
          </div>
        )}

        {/* Autopilot tab */}
        {mainTab === 'autopilot' && (
          <div className="px-3 py-2 border-x border-[#bbc3c4] bg-[#f6edda] space-y-2">
            <div>
              <label className="text-[#708e8e] text-xs block mb-0.5">Target URL <span className="text-[#e34e1c]">*</span></label>
              <input value={autopilotTarget} onChange={(e) => setAutopilotTarget(e.target.value)} placeholder="https://example.com" className={inputClass} />
            </div>
            <div className="grid grid-cols-3 gap-2">
              <div>
                <label className="text-[#708e8e] text-xs block mb-0.5">Agent</label>
                <input value={autopilotAgent} onChange={(e) => setAutopilotAgent(e.target.value)} placeholder="claude" className={inputClass} />
              </div>
              <div>
                <label className="text-[#708e8e] text-xs block mb-0.5">Focus</label>
                <input value={autopilotFocus} onChange={(e) => setAutopilotFocus(e.target.value)} placeholder="authentication, api" className={inputClass} />
              </div>
              <div>
                <label className="text-[#708e8e] text-xs block mb-0.5">Timeout</label>
                <input value={autopilotTimeout} onChange={(e) => setAutopilotTimeout(e.target.value)} placeholder="30m" className={inputClass} />
              </div>
            </div>

            <details className="group">
              <summary className="text-[#bbc3c4] text-xs cursor-pointer hover:text-[#708e8e] select-none">optional fields</summary>
              <div className="space-y-2 mt-1.5">
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">System Prompt</label>
                  <textarea value={autopilotSystemPrompt} onChange={(e) => setAutopilotSystemPrompt(e.target.value)} placeholder="Custom system prompt..." rows={2} className={`${inputClass} resize-y`} />
                </div>
                <div className="grid grid-cols-3 gap-2">
                  <div>
                    <label className="text-[#708e8e] text-xs block mb-0.5">Max Commands</label>
                    <input value={autopilotMaxCommands} onChange={(e) => setAutopilotMaxCommands(e.target.value)} placeholder="50" className={inputClass} />
                  </div>
                  <div>
                    <label className="text-[#708e8e] text-xs block mb-0.5">Repo Path</label>
                    <input value={autopilotRepoPath} onChange={(e) => setAutopilotRepoPath(e.target.value)} placeholder="/path/to/repo" className={inputClass} />
                  </div>
                  <div>
                    <label className="text-[#708e8e] text-xs block mb-0.5">Scan UUID</label>
                    <input value={autopilotScanUuid} onChange={(e) => setAutopilotScanUuid(e.target.value)} placeholder="uuid" className={inputClass} />
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-2">
                  <div>
                    <label className="text-[#708e8e] text-xs block mb-0.5">Files (comma-separated)</label>
                    <input value={autopilotFiles} onChange={(e) => setAutopilotFiles(e.target.value)} placeholder="src/main.go" className={inputClass} />
                  </div>
                  <div className="flex items-center gap-2 pt-4">
                    <input type="checkbox" id="autopilot-dry-run" checked={autopilotDryRun} onChange={(e) => setAutopilotDryRun(e.target.checked)} className="accent-[#0078c8]" />
                    <label htmlFor="autopilot-dry-run" className="text-[#708e8e] text-xs">Dry Run</label>
                  </div>
                </div>
              </div>
            </details>

            <div className="flex items-center gap-2">
              {!isStreaming ? (
                <button
                  onClick={handleAutopilotSubmit}
                  disabled={!autopilotTarget.trim()}
                  className="flex items-center gap-1 px-3 py-1 text-xs font-bold bg-[#00b368]/10 text-[#00b368] border border-[#00b368]/30 hover:bg-[#00b368]/20 transition-colors disabled:opacity-30"
                >
                  <Zap className="w-3 h-3" /> RUN AUTOPILOT
                </button>
              ) : (
                <button
                  onClick={handleCancel}
                  className="flex items-center gap-1 px-3 py-1 text-xs font-bold bg-[#e34e1c]/10 text-[#e34e1c] border border-[#e34e1c]/30 hover:bg-[#e34e1c]/20 transition-colors"
                >
                  <Square className="w-3 h-3" /> CANCEL
                </button>
              )}
              {scanError && <span className="text-xs text-[#e34e1c]">{scanError}</span>}
            </div>
          </div>
        )}

        {/* Pipeline tab */}
        {mainTab === 'pipeline' && (
          <div className="px-3 py-2 border-x border-[#bbc3c4] bg-[#f6edda] space-y-2">
            <div>
              <label className="text-[#708e8e] text-xs block mb-0.5">Target URL <span className="text-[#e34e1c]">*</span></label>
              <input value={pipelineTarget} onChange={(e) => setPipelineTarget(e.target.value)} placeholder="https://example.com" className={inputClass} />
            </div>
            <div className="grid grid-cols-3 gap-2">
              <div>
                <label className="text-[#708e8e] text-xs block mb-0.5">Agent</label>
                <input value={pipelineAgent} onChange={(e) => setPipelineAgent(e.target.value)} placeholder="claude" className={inputClass} />
              </div>
              <div>
                <label className="text-[#708e8e] text-xs block mb-0.5">Profile</label>
                <input value={pipelineProfile} onChange={(e) => setPipelineProfile(e.target.value)} placeholder="default" className={inputClass} />
              </div>
              <div>
                <label className="text-[#708e8e] text-xs block mb-0.5">Focus</label>
                <input value={pipelineFocus} onChange={(e) => setPipelineFocus(e.target.value)} placeholder="authentication, api" className={inputClass} />
              </div>
            </div>

            <details className="group">
              <summary className="text-[#bbc3c4] text-xs cursor-pointer hover:text-[#708e8e] select-none">optional fields</summary>
              <div className="grid grid-cols-3 gap-2 mt-1.5">
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Timeout</label>
                  <input value={pipelineTimeout} onChange={(e) => setPipelineTimeout(e.target.value)} placeholder="60m" className={inputClass} />
                </div>
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Max Rescan Rounds</label>
                  <input value={pipelineMaxRescanRounds} onChange={(e) => setPipelineMaxRescanRounds(e.target.value)} placeholder="3" className={inputClass} />
                </div>
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Skip Phases (comma-sep)</label>
                  <input value={pipelineSkipPhases} onChange={(e) => setPipelineSkipPhases(e.target.value)} placeholder="rescan, report" className={inputClass} />
                </div>
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Start From</label>
                  <input value={pipelineStartFrom} onChange={(e) => setPipelineStartFrom(e.target.value)} placeholder="scan" className={inputClass} />
                </div>
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Repo Path</label>
                  <input value={pipelineRepoPath} onChange={(e) => setPipelineRepoPath(e.target.value)} placeholder="/path/to/repo" className={inputClass} />
                </div>
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Files (comma-separated)</label>
                  <input value={pipelineFiles} onChange={(e) => setPipelineFiles(e.target.value)} placeholder="src/main.go" className={inputClass} />
                </div>
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Scan UUID</label>
                  <input value={pipelineScanUuid} onChange={(e) => setPipelineScanUuid(e.target.value)} placeholder="uuid" className={inputClass} />
                </div>
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Project UUID</label>
                  <input value={pipelineProjectUuid} onChange={(e) => setPipelineProjectUuid(e.target.value)} placeholder="uuid" className={inputClass} />
                </div>
                <div className="flex items-center gap-2 pt-4">
                  <input type="checkbox" id="pipeline-dry-run" checked={pipelineDryRun} onChange={(e) => setPipelineDryRun(e.target.checked)} className="accent-[#0078c8]" />
                  <label htmlFor="pipeline-dry-run" className="text-[#708e8e] text-xs">Dry Run</label>
                </div>
              </div>
            </details>

            <div className="flex items-center gap-2">
              {!isStreaming ? (
                <button
                  onClick={handlePipelineSubmit}
                  disabled={!pipelineTarget.trim()}
                  className="flex items-center gap-1 px-3 py-1 text-xs font-bold bg-[#00b368]/10 text-[#00b368] border border-[#00b368]/30 hover:bg-[#00b368]/20 transition-colors disabled:opacity-30"
                >
                  <Layers className="w-3 h-3" /> RUN PIPELINE
                </button>
              ) : (
                <button
                  onClick={handleCancel}
                  className="flex items-center gap-1 px-3 py-1 text-xs font-bold bg-[#e34e1c]/10 text-[#e34e1c] border border-[#e34e1c]/30 hover:bg-[#e34e1c]/20 transition-colors"
                >
                  <Square className="w-3 h-3" /> CANCEL
                </button>
              )}
              {scanError && <span className="text-xs text-[#e34e1c]">{scanError}</span>}
            </div>
          </div>
        )}

        {/* Pipeline phase progress */}
        {mainTab === 'pipeline' && (currentPhase || phasesCompleted.length > 0) && (
          <PipelineProgress currentPhase={currentPhase} phasesCompleted={phasesCompleted} />
        )}

        {/* Shared output panel for query/autopilot/pipeline */}
        {showOutputPanel && (
          <div className="flex-1 flex flex-col gap-0 overflow-hidden">
            <div className="flex-1 border border-[#bbc3c4] bg-[#ede4d1] overflow-hidden flex flex-col">
              <div className="px-3 py-1 border-b border-[#bbc3c4] flex items-center justify-between">
                <span className="text-[#bbc3c4] text-xs">output</span>
                {scanResult && (
                  <span className="text-xs text-[#708e8e]">
                    {scanResult.finding_count != null && <span className="text-[#005661] mr-3">findings: <b className="text-[#00b368]">{String(scanResult.finding_count)}</b></span>}
                    {scanResult.saved_count != null && <span className="text-[#005661]">saved: <b className="text-[#00b368]">{String(scanResult.saved_count)}</b></span>}
                  </span>
                )}
              </div>
              <pre
                ref={scanOutputRef}
                className="flex-1 overflow-auto p-3 text-xs text-[#005661] font-mono whitespace-pre-wrap leading-relaxed"
              >
                {scanOutput || <span className="text-[#bbc3c4]">agent output will appear here…</span>}
              </pre>
            </div>

            {/* Run history table */}
            {runsData?.runs && runsData.runs.length > 0 && (
              <div className="border border-[#bbc3c4] bg-[#f6edda] max-h-48 overflow-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-[#bbc3c4] text-[#708e8e]">
                      <th className="text-left px-3 py-1 font-bold">RUN ID</th>
                      <th className="text-left px-3 py-1 font-bold">AGENT</th>
                      <th className="text-left px-3 py-1 font-bold">MODE</th>
                      <th className="text-left px-3 py-1 font-bold">TEMPLATE</th>
                      <th className="text-left px-3 py-1 font-bold">STATUS</th>
                      <th className="text-right px-3 py-1 font-bold">FINDINGS</th>
                      <th className="text-right px-3 py-1 font-bold">SAVED</th>
                      <th className="text-left px-3 py-1 font-bold">COMPLETED</th>
                    </tr>
                  </thead>
                  <tbody>
                    {runsData.runs.map((run: AgentRunStatusResponse) => (
                      <tr key={run.run_id} className="border-b border-[#bbc3c4]/50 hover:bg-[#bbc3c4]/20">
                        <td className="px-3 py-1 text-[#0078c8] font-mono">{run.run_id.slice(0, 8)}</td>
                        <td className="px-3 py-1 text-[#005661]">{run.agent_name || '—'}</td>
                        <td className="px-3 py-1 text-[#708e8e]">{run.mode || 'query'}</td>
                        <td className="px-3 py-1 text-[#708e8e]">{run.template_id || '—'}</td>
                        <td className="px-3 py-1"><StatusBadge status={run.status} /></td>
                        <td className="px-3 py-1 text-right text-[#005661]">{run.finding_count}</td>
                        <td className="px-3 py-1 text-right text-[#00b368]">{run.saved_count}</td>
                        <td className="px-3 py-1 text-[#708e8e]">{run.completed_at ? new Date(run.completed_at).toLocaleString() : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Chat tab */}
        {mainTab === 'chat' && (
          <div className="flex-1 flex flex-col border-x border-b border-[#bbc3c4] bg-[#f6edda] overflow-hidden">
            <div className="flex-1 overflow-auto p-3 space-y-3">
              {messages.length === 0 && (
                <div className="flex items-center justify-center h-full">
                  <span className="text-[#bbc3c4] text-xs flex items-center gap-2"><Bot className="w-4 h-4" /> send a message to start chatting with the agent</span>
                </div>
              )}
              {messages.map((msg, i) => (
                <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div
                    className={`max-w-[75%] px-3 py-2 text-xs leading-relaxed ${
                      msg.role === 'user'
                        ? 'bg-[#bbc3c4] text-[#005661] rounded-l-lg rounded-tr-lg'
                        : 'bg-[#ede4d1] text-[#005661] rounded-r-lg rounded-tl-lg'
                    }`}
                  >
                    {msg.role === 'assistant' ? (
                      <div className="prose prose-xs max-w-none [&_pre]:bg-[#d4e8e2] [&_pre]:p-2 [&_pre]:text-xs [&_code]:text-[#00b368] [&_p]:m-0 [&_p]:mb-1.5">
                        <ReactMarkdown>{msg.content || '…'}</ReactMarkdown>
                      </div>
                    ) : (
                      <span className="whitespace-pre-wrap">{msg.content}</span>
                    )}
                  </div>
                </div>
              ))}
              <div ref={chatEndRef} />
            </div>

            <div className="border-t border-[#bbc3c4] px-3 py-2 flex items-end gap-2">
              <textarea
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                onKeyDown={handleChatKeyDown}
                placeholder={isStreaming ? 'Agent is responding…' : 'Type a message…'}
                disabled={isStreaming}
                rows={1}
                className="flex-1 bg-[#ede4d1] border border-[#bbc3c4] text-[#005661] text-xs px-2 py-1.5 resize-none focus:outline-none focus:border-[#0078c8]/50 disabled:opacity-50"
              />
              {isStreaming ? (
                <button
                  onClick={handleCancel}
                  className="flex items-center gap-1 px-3 py-1.5 text-xs font-bold bg-[#e34e1c]/10 text-[#e34e1c] border border-[#e34e1c]/30 hover:bg-[#e34e1c]/20 transition-colors shrink-0"
                >
                  <Square className="w-3 h-3" />
                </button>
              ) : (
                <button
                  onClick={handleChatSend}
                  disabled={!chatInput.trim()}
                  className="flex items-center gap-1 px-3 py-1.5 text-xs font-bold bg-[#0078c8]/10 text-[#0078c8] border border-[#0078c8]/30 hover:bg-[#0078c8]/20 transition-colors disabled:opacity-30 shrink-0"
                >
                  <Send className="w-3 h-3" />
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </PageShell>
  );
}
