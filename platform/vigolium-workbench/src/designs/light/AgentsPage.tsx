'use client';

import { useState, useRef, useCallback, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import { Play, Square, Send, Bot, Terminal, MessageSquare, Clock, CheckCircle, XCircle, Loader2, Zap, Layers, Bug, ScrollText, Copy, Check, Upload } from 'lucide-react';
import { zipSync } from 'fflate';
import { useAgentSessions, useAgentSessionDetail, useUploadRepo } from '@/api/hooks';
import { fetchSSE } from '@/lib/sse';
import type { AgentSession, AgentSessionDetail } from '@/api/types';
import { formatDate, formatDuration, truncate } from '@/lib/formatters';
import PageShell from './PageShell';
import Dropdown from './Dropdown';

type MainTab = 'swarm' | 'autopilot' | 'query' | 'chat';
type ScanMode = 'template' | 'custom';
type InputMode = 'url' | 'raw' | 'curl';

const AGENT_OPTIONS = [
  { value: '', label: 'default' },
  { value: 'claude', label: 'claude' },
  { value: 'opencode', label: 'opencode' },
  { value: 'gemini', label: 'gemini' },
  { value: 'custom', label: 'custom' },
];

const TAB_DESCRIPTIONS: Record<MainTab, string> = {
  swarm: 'AI-guided targeted vulnerability swarm. Best for focused scanning with module selection.',
  autopilot: 'Full autonomy — agent drives the CLI. Best for exploratory scanning and ad-hoc testing.',
  query: 'Single prompt → structured output. Best for code review and endpoint discovery.',
  chat: 'Conversational interface for interactive agent sessions.',
};

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

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
        <button onClick={onClose} className="text-[#708e8e] hover:text-[#005661] text-xs font-bold px-1">✕</button>
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
          <div><span className="text-[#708e8e]">phases </span><span className="text-[#005661]">{session.phases_run.join(' → ')}</span></div>
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
              <button
                onClick={() => copyToClipboard(session.prompt_sent!, 'prompt')}
                className="absolute top-1.5 right-2 text-[#708e8e] hover:text-[#005661] p-0.5"
                title="Copy to clipboard"
              >
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
              <button
                onClick={() => copyToClipboard(session.agent_raw_output!, 'output')}
                className="absolute top-1.5 right-2 z-10 text-[#708e8e] hover:text-[#005661] p-0.5"
                title="Copy to clipboard"
              >
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
              <button
                onClick={() => copyToClipboard(tryPrettyJson(session.attack_plan), 'plan')}
                className="absolute top-1.5 right-2 z-10 text-[#708e8e] hover:text-[#005661] p-0.5"
                title="Copy to clipboard"
              >
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
              <button
                onClick={() => copyToClipboard(tryPrettyJson(session.triage_result), 'triage')}
                className="absolute top-1.5 right-2 text-[#708e8e] hover:text-[#005661] p-0.5"
                title="Copy to clipboard"
              >
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
  const [mainTab, setMainTab] = useState<MainTab>('swarm');

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

  // Swarm tab state
  const [swarmInputMode, setSwarmInputMode] = useState<InputMode>('url');
  const [swarmInput, setSwarmInput] = useState('');
  const [swarmInputs, setSwarmInputs] = useState('');
  const [swarmSource, setSwarmSource] = useState('');
  const [swarmModuleTags, setSwarmModuleTags] = useState('');
  const [swarmAgent, setSwarmAgent] = useState('');
  const [swarmVulnType, setSwarmVulnType] = useState('');
  const [swarmMaxIterations, setSwarmMaxIterations] = useState('');
  const [swarmTimeout, setSwarmTimeout] = useState('');
  const [swarmDryRun, setSwarmDryRun] = useState(false);
  const [swarmScanUuid, setSwarmScanUuid] = useState('');
  const [swarmProjectUuid, setSwarmProjectUuid] = useState('');
  const [swarmInstruction, setSwarmInstruction] = useState('');
  const [swarmFiles, setSwarmFiles] = useState('');
  const [swarmFocus, setSwarmFocus] = useState('');
  const [swarmProfile, setSwarmProfile] = useState('');
  const [swarmSourceAnalysisOnly, setSwarmSourceAnalysisOnly] = useState(false);
  const [swarmDiscover, setSwarmDiscover] = useState(false);
  const [swarmCodeAudit, setSwarmCodeAudit] = useState(false);
  const [swarmSkipSast, setSwarmSkipSast] = useState(false);

  // Chat tab state
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState('');

  // Repo upload state
  const [uploadDragging, setUploadDragging] = useState(false);
  const [uploadCompressing, setUploadCompressing] = useState(false);
  const uploadDragCounter = useRef(0);
  const uploadFileInputRef = useRef<HTMLInputElement>(null);
  const uploadRepo = useUploadRepo();

  // Shared state
  const [isStreaming, setIsStreaming] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const scanOutputRef = useRef<HTMLPreElement>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);

  // Agent sessions
  const [expandedSessionUuid, setExpandedSessionUuid] = useState<string | null>(null);
  const { data: sessionsData } = useAgentSessions({ limit: 20 });
  const { data: sessionDetail } = useAgentSessionDetail(expandedSessionUuid);

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

  const handleSwarmSubmit = useCallback(() => {
    if (isStreaming || !swarmInput.trim()) return;
    setScanOutput('');
    setScanResult(null);
    setScanError('');
    setIsStreaming(true);

    const abort = new AbortController();
    abortRef.current = abort;

    const body: Record<string, unknown> = { stream: true };
    if (swarmInputMode === 'raw') {
      body.http_request_base64 = btoa(swarmInput);
    } else {
      body.input = swarmInput;
    }
    if (swarmInputs) body.inputs = swarmInputs.split('\n').map((s) => s.trim()).filter(Boolean);
    if (swarmSource) body.source = swarmSource;
    if (swarmModuleTags) body.module_tags = swarmModuleTags.split(',').map((t) => t.trim()).filter(Boolean);
    if (swarmAgent) body.agent = swarmAgent;
    if (swarmVulnType) body.vuln_type = swarmVulnType;
    if (swarmMaxIterations) body.max_iterations = parseInt(swarmMaxIterations, 10);
    if (swarmTimeout) body.timeout = swarmTimeout;
    if (swarmDryRun) body.dry_run = true;
    if (swarmScanUuid) body.scan_uuid = swarmScanUuid;
    if (swarmProjectUuid) body.project_uuid = swarmProjectUuid;
    if (swarmInstruction) body.instruction = swarmInstruction;
    if (swarmFiles) body.files = swarmFiles.split('\n').map((s) => s.trim()).filter(Boolean);
    if (swarmFocus) body.focus = swarmFocus;
    if (swarmProfile) body.profile = swarmProfile;
    if (swarmSourceAnalysisOnly) body.source_analysis_only = true;
    if (swarmDiscover) body.discover = true;
    if (swarmCodeAudit) body.code_audit = true;
    if (swarmSkipSast) body.skip_sast = true;

    fetchSSE('/api/agent/run/swarm', body, {
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
  }, [isStreaming, swarmInput, swarmInputMode, swarmInputs, swarmSource, swarmModuleTags, swarmAgent, swarmVulnType, swarmMaxIterations, swarmTimeout, swarmDryRun, swarmScanUuid, swarmProjectUuid, swarmInstruction, swarmFiles, swarmFocus, swarmProfile, swarmSourceAnalysisOnly, swarmDiscover, swarmCodeAudit, swarmSkipSast, scrollScanOutput]);

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

  // ── Repo upload handlers ──

  const doUpload = useCallback((file: File) => {
    uploadRepo.mutate(file, {
      onSuccess: (data) => {
        if (mainTab === 'swarm') setSwarmSource(data.repo_path);
        else if (mainTab === 'autopilot') setAutopilotRepoPath(data.repo_path);
        else if (mainTab === 'query') setRepoPath(data.repo_path);
      },
    });
  }, [uploadRepo, mainTab]);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    doUpload(file);
    e.target.value = '';
  };

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

    setUploadCompressing(true);
    try {
      const allFiles: { path: string; file: File }[] = [];
      for (const entry of entries) {
        allFiles.push(...await readEntryRecursive(entry));
      }
      if (allFiles.length === 0) { setUploadCompressing(false); return; }

      const zipData: Record<string, Uint8Array> = {};
      for (const { path, file } of allFiles) {
        const buf = await file.arrayBuffer();
        zipData[path] = new Uint8Array(buf);
      }
      const zipped = zipSync(zipData);
      const zipFile = new File([new Uint8Array(zipped) as BlobPart], 'repo.zip', { type: 'application/zip' });
      setUploadCompressing(false);
      doUpload(zipFile);
    } catch {
      setUploadCompressing(false);
    }
  }, [doUpload]);

  const onUploadDragEnter = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
    uploadDragCounter.current++;
    setUploadDragging(true);
  }, []);
  const onUploadDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
    uploadDragCounter.current--;
    if (uploadDragCounter.current === 0) setUploadDragging(false);
  }, []);
  const onUploadDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
  }, []);
  const onUploadDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
    uploadDragCounter.current = 0;
    setUploadDragging(false);
    if (uploadRepo.isPending) return;
    const items = e.dataTransfer.items;
    if (items && items.length > 0) {
      compressAndUpload(items);
    } else {
      const file = e.dataTransfer.files?.[0];
      if (file) doUpload(file);
    }
  }, [compressAndUpload, doUpload, uploadRepo.isPending]);

  const tabBtnClass = (active: boolean) =>
    `px-3 py-0.5 text-xs font-bold transition-colors ${
      active ? 'text-[#0078c8] bg-[#0078c8]/10' : 'text-[#708e8e] hover:text-[#005661]'
    }`;

  const inputClass = 'bg-[#ede4d1] border border-[#bbc3c4] text-[#005661] text-xs px-2 py-1 focus:outline-none focus:border-[#0078c8]/50 w-full';

  const showOutputPanel = mainTab === 'swarm' || mainTab === 'query' || mainTab === 'autopilot';

  const inputModeBtnClass = (active: boolean) =>
    `px-2 py-0.5 text-xs font-bold transition-colors ${
      active ? 'text-[#0078c8] bg-[#0078c8]/10' : 'text-[#708e8e] hover:text-[#005661]'
    }`;

  return (
    <PageShell>
      <div className="flex flex-col" style={{ height: 'calc(100vh - 68px)', minHeight: 500 }}>
        {/* Tab bar + description */}
        <div className="px-3 py-1.5 border border-b-0 border-[#bbc3c4] bg-[#f6edda] flex items-center gap-1.5">
          <div className="flex border border-[#bbc3c4]">
            <button onClick={() => setMainTab('swarm')} className={tabBtnClass(mainTab === 'swarm')}>
              <span className="flex items-center gap-1"><Bug className="w-3 h-3" />SWARM</span>
            </button>
            <button onClick={() => setMainTab('autopilot')} className={tabBtnClass(mainTab === 'autopilot')}>
              <span className="flex items-center gap-1"><Zap className="w-3 h-3" />AUTOPILOT</span>
            </button>
            <button onClick={() => setMainTab('query')} className={tabBtnClass(mainTab === 'query')}>
              <span className="flex items-center gap-1"><Terminal className="w-3 h-3" />QUERY</span>
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
        <div className="px-3 py-1 border-x border-[#bbc3c4] bg-[#f6edda] text-[#708e8e] text-xs italic">
          {TAB_DESCRIPTIONS[mainTab]}
        </div>

        {/* Swarm tab */}
        {mainTab === 'swarm' && (
          <div className="px-3 py-2 border-x border-[#bbc3c4] bg-[#f6edda] space-y-2">
            <div className="flex items-center gap-2">
              <div className="flex border border-[#bbc3c4]">
                <button onClick={() => setSwarmInputMode('url')} className={inputModeBtnClass(swarmInputMode === 'url')}>URL</button>
                <button onClick={() => setSwarmInputMode('raw')} className={inputModeBtnClass(swarmInputMode === 'raw')}>RAW REQUEST</button>
                <button onClick={() => setSwarmInputMode('curl')} className={inputModeBtnClass(swarmInputMode === 'curl')}>CURL</button>
              </div>
            </div>

            {swarmInputMode === 'url' && (
              <div>
                <label className="text-[#708e8e] text-xs block mb-0.5">Target URL <span className="text-[#e34e1c]">*</span></label>
                <input value={swarmInput} onChange={(e) => setSwarmInput(e.target.value)} placeholder="https://example.com/api/endpoint" className={inputClass} />
              </div>
            )}
            {swarmInputMode === 'raw' && (
              <div>
                <label className="text-[#708e8e] text-xs block mb-0.5">Raw HTTP Request <span className="text-[#e34e1c]">*</span> <span className="text-[#bbc3c4] font-normal italic">— auto base64-encoded before sending</span></label>
                <textarea value={swarmInput} onChange={(e) => setSwarmInput(e.target.value)} placeholder={"GET /api/endpoint HTTP/1.1\nHost: example.com\nAuthorization: Bearer token123"} rows={6} className={`${inputClass} resize-y font-mono`} />
              </div>
            )}
            {swarmInputMode === 'curl' && (
              <div>
                <label className="text-[#708e8e] text-xs block mb-0.5">cURL Command <span className="text-[#e34e1c]">*</span></label>
                <textarea value={swarmInput} onChange={(e) => setSwarmInput(e.target.value)} placeholder="curl -X POST https://example.com/api/endpoint -H 'Content-Type: application/json' -d '{...}'" rows={3} className={`${inputClass} resize-y font-mono`} />
              </div>
            )}

            <div className="grid grid-cols-3 gap-2">
              <div>
                <label className="text-[#708e8e] text-xs block mb-0.5">Agent</label>
                <Dropdown value={swarmAgent} onChange={setSwarmAgent} options={AGENT_OPTIONS} />
              </div>
              <div>
                <label className="text-[#708e8e] text-xs block mb-0.5">Module Tags (comma-sep) <span className="text-[#bbc3c4] font-normal italic">— blank = agent decides</span></label>
                <input value={swarmModuleTags} onChange={(e) => setSwarmModuleTags(e.target.value)} placeholder="xss, sqli, auth" className={inputClass} />
              </div>
              <div>
                <label className="text-[#708e8e] text-xs block mb-0.5">Vuln Type <span className="text-[#bbc3c4] font-normal italic">— blank = agent decides</span></label>
                <input value={swarmVulnType} onChange={(e) => setSwarmVulnType(e.target.value)} placeholder="sqli" className={inputClass} />
              </div>
            </div>

            <details className="group">
              <summary className="text-[#bbc3c4] text-xs cursor-pointer hover:text-[#708e8e] select-none">optional fields</summary>
              <div className="space-y-2 mt-1.5">
                <div
                  onDragEnter={onUploadDragEnter} onDragLeave={onUploadDragLeave} onDragOver={onUploadDragOver} onDrop={onUploadDrop}
                  className={`border border-dashed p-4 text-center transition-colors ${uploadCompressing || uploadRepo.isPending ? '' : 'cursor-pointer'} ${uploadDragging ? 'border-[#0078c8] bg-[#0078c8]/10' : 'border-[#bbc3c4] hover:border-[#0078c8]/50'}`}
                  onClick={() => { if (!uploadCompressing && !uploadRepo.isPending) uploadFileInputRef.current?.click(); }}
                >
                  <input ref={uploadFileInputRef} type="file" accept=".zip,.tar.gz,.tgz,.tar" onChange={handleFileUpload} className="hidden" />
                  {uploadCompressing || uploadRepo.isPending ? (
                    <><Loader2 className="w-5 h-5 mx-auto mb-1.5 text-[#0078c8] animate-spin" /><p className="text-xs text-[#005661]">{uploadCompressing ? 'Compressing folder...' : 'Uploading...'}</p></>
                  ) : (
                    <><Upload className="w-5 h-5 mx-auto mb-1.5 text-[#0078c8]/70" /><p className="text-xs text-[#005661]">{uploadDragging ? 'Drop here to upload' : 'Click or drag & drop repo archive or folder'}</p></>
                  )}
                  <p className="text-[10px] text-[#708e8e] mt-1">.zip, .tar.gz, .tgz, .tar — or drop a folder (auto-zipped) — max 500 MB</p>
                  {uploadRepo.isSuccess && <p className="text-[10px] text-[#00b368] mt-1">uploaded — source path set</p>}
                  {uploadRepo.isError && <p className="text-[10px] text-[#e34e1c] mt-1">upload failed: {(uploadRepo.error as Error).message}</p>}
                </div>
                <div className="grid grid-cols-3 gap-2">
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Source Path</label>
                  <input value={swarmSource} onChange={(e) => setSwarmSource(e.target.value)} placeholder="/path/to/source" className={inputClass} />
                </div>
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Max Iterations</label>
                  <input value={swarmMaxIterations} onChange={(e) => setSwarmMaxIterations(e.target.value)} placeholder="3" className={inputClass} />
                </div>
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Timeout</label>
                  <input value={swarmTimeout} onChange={(e) => setSwarmTimeout(e.target.value)} placeholder="30m" className={inputClass} />
                </div>
                <div className="col-span-3">
                  <label className="text-[#708e8e] text-xs block mb-0.5">Instruction</label>
                  <textarea value={swarmInstruction} onChange={(e) => setSwarmInstruction(e.target.value)} placeholder="Focus on business logic flaws in the payment flow" rows={2} className={`${inputClass} resize-y`} />
                </div>
                <div className="col-span-3">
                  <label className="text-[#708e8e] text-xs block mb-0.5">Files (one per line, relative to source path)</label>
                  <textarea value={swarmFiles} onChange={(e) => setSwarmFiles(e.target.value)} placeholder={"routes/api.js\ncontrollers/auth.js\nmiddleware/session.js"} rows={3} className={`${inputClass} resize-y font-mono`} />
                </div>
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Focus</label>
                  <input value={swarmFocus} onChange={(e) => setSwarmFocus(e.target.value)} placeholder="API injection, auth bypass" className={inputClass} />
                </div>
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Profile</label>
                  <input value={swarmProfile} onChange={(e) => setSwarmProfile(e.target.value)} placeholder="light, thorough" className={inputClass} />
                </div>
                <div className="col-span-3">
                  <label className="text-[#708e8e] text-xs block mb-0.5">Additional Inputs (one per line)</label>
                  <textarea value={swarmInputs} onChange={(e) => setSwarmInputs(e.target.value)} placeholder={"https://example.com/api/users\nhttps://example.com/api/admin"} rows={3} className={`${inputClass} resize-y font-mono`} />
                </div>
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Scan UUID</label>
                  <input value={swarmScanUuid} onChange={(e) => setSwarmScanUuid(e.target.value)} placeholder="uuid" className={inputClass} />
                </div>
                <div>
                  <label className="text-[#708e8e] text-xs block mb-0.5">Project UUID</label>
                  <input value={swarmProjectUuid} onChange={(e) => setSwarmProjectUuid(e.target.value)} placeholder="uuid" className={inputClass} />
                </div>
                <div className="col-span-3 flex flex-wrap items-center gap-x-4 gap-y-2 pt-2">
                  {([
                    ['Discover', swarmDiscover, setSwarmDiscover] as const,
                    ['Source Analysis Only', swarmSourceAnalysisOnly, setSwarmSourceAnalysisOnly] as const,
                    ['Skip SAST', swarmSkipSast, setSwarmSkipSast] as const,
                    ['Dry Run', swarmDryRun, setSwarmDryRun] as const,
                  ]).map(([label, value, setter]) => (
                    <div key={label} className="flex items-center gap-2">
                      <button
                        type="button"
                        role="switch"
                        aria-checked={value}
                        onClick={() => setter(!value)}
                        className="relative inline-flex h-4 w-7 items-center rounded-full transition-colors shrink-0"
                        style={{ backgroundColor: value ? '#0078c8' : '#bbc3c4' }}
                      >
                        <span
                          className="inline-block h-3 w-3 rounded-full bg-white transition-transform"
                          style={{ transform: value ? 'translateX(14px)' : 'translateX(2px)' }}
                        />
                      </button>
                      <span className="text-[#708e8e] text-xs">{label}</span>
                    </div>
                  ))}
                </div>
              </div>
              </div>
            </details>

            <div className="flex items-center gap-2">
              {!isStreaming ? (
                <button
                  onClick={handleSwarmSubmit}
                  disabled={!swarmInput.trim()}
                  className="px-4 py-1 text-xs font-bold border border-[#FF8C00] text-[#FF8C00] bg-[#FF8C00]/10 hover:bg-[#FF8C00]/20 shadow-[inset_0_0_18px_rgba(255,140,0,0.5)] hover:shadow-[inset_0_0_28px_rgba(255,140,0,0.7)] transition-colors disabled:opacity-30"
                >
                  [RUN SWARM]
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
              <div className="space-y-2 mt-1.5">
                <div
                  onDragEnter={onUploadDragEnter} onDragLeave={onUploadDragLeave} onDragOver={onUploadDragOver} onDrop={onUploadDrop}
                  className={`border border-dashed p-4 text-center transition-colors ${uploadCompressing || uploadRepo.isPending ? '' : 'cursor-pointer'} ${uploadDragging ? 'border-[#0078c8] bg-[#0078c8]/10' : 'border-[#bbc3c4] hover:border-[#0078c8]/50'}`}
                  onClick={() => { if (!uploadCompressing && !uploadRepo.isPending) uploadFileInputRef.current?.click(); }}
                >
                  <input ref={uploadFileInputRef} type="file" accept=".zip,.tar.gz,.tgz,.tar" onChange={handleFileUpload} className="hidden" />
                  {uploadCompressing || uploadRepo.isPending ? (
                    <><Loader2 className="w-5 h-5 mx-auto mb-1.5 text-[#0078c8] animate-spin" /><p className="text-xs text-[#005661]">{uploadCompressing ? 'Compressing folder...' : 'Uploading...'}</p></>
                  ) : (
                    <><Upload className="w-5 h-5 mx-auto mb-1.5 text-[#0078c8]/70" /><p className="text-xs text-[#005661]">{uploadDragging ? 'Drop here to upload' : 'Click or drag & drop repo archive or folder'}</p></>
                  )}
                  <p className="text-[10px] text-[#708e8e] mt-1">.zip, .tar.gz, .tgz, .tar — or drop a folder (auto-zipped) — max 500 MB</p>
                  {uploadRepo.isSuccess && <p className="text-[10px] text-[#00b368] mt-1">uploaded — source path set</p>}
                  {uploadRepo.isError && <p className="text-[10px] text-[#e34e1c] mt-1">upload failed: {(uploadRepo.error as Error).message}</p>}
                </div>
                <div className="grid grid-cols-3 gap-2">
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
              </div>
            </details>

            <div className="flex items-center gap-2">
              {!isStreaming ? (
                <button
                  onClick={handleQuerySubmit}
                  className="px-4 py-1 text-xs font-bold border border-[#FF8C00] text-[#FF8C00] bg-[#FF8C00]/10 hover:bg-[#FF8C00]/20 shadow-[inset_0_0_18px_rgba(255,140,0,0.5)] hover:shadow-[inset_0_0_28px_rgba(255,140,0,0.7)] transition-colors"
                >
                  [RUN QUERY]
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
                <Dropdown value={autopilotAgent} onChange={setAutopilotAgent} options={AGENT_OPTIONS} />
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
                <div
                  onDragEnter={onUploadDragEnter} onDragLeave={onUploadDragLeave} onDragOver={onUploadDragOver} onDrop={onUploadDrop}
                  className={`border border-dashed p-4 text-center transition-colors ${uploadCompressing || uploadRepo.isPending ? '' : 'cursor-pointer'} ${uploadDragging ? 'border-[#0078c8] bg-[#0078c8]/10' : 'border-[#bbc3c4] hover:border-[#0078c8]/50'}`}
                  onClick={() => { if (!uploadCompressing && !uploadRepo.isPending) uploadFileInputRef.current?.click(); }}
                >
                  <input ref={uploadFileInputRef} type="file" accept=".zip,.tar.gz,.tgz,.tar" onChange={handleFileUpload} className="hidden" />
                  {uploadCompressing || uploadRepo.isPending ? (
                    <><Loader2 className="w-5 h-5 mx-auto mb-1.5 text-[#0078c8] animate-spin" /><p className="text-xs text-[#005661]">{uploadCompressing ? 'Compressing folder...' : 'Uploading...'}</p></>
                  ) : (
                    <><Upload className="w-5 h-5 mx-auto mb-1.5 text-[#0078c8]/70" /><p className="text-xs text-[#005661]">{uploadDragging ? 'Drop here to upload' : 'Click or drag & drop repo archive or folder'}</p></>
                  )}
                  <p className="text-[10px] text-[#708e8e] mt-1">.zip, .tar.gz, .tgz, .tar — or drop a folder (auto-zipped) — max 500 MB</p>
                  {uploadRepo.isSuccess && <p className="text-[10px] text-[#00b368] mt-1">uploaded — source path set</p>}
                  {uploadRepo.isError && <p className="text-[10px] text-[#e34e1c] mt-1">upload failed: {(uploadRepo.error as Error).message}</p>}
                </div>
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
                    <button
                      type="button"
                      role="switch"
                      aria-checked={autopilotDryRun}
                      onClick={() => setAutopilotDryRun(!autopilotDryRun)}
                      className="relative inline-flex h-4 w-7 items-center rounded-full transition-colors shrink-0"
                      style={{ backgroundColor: autopilotDryRun ? '#0078c8' : '#bbc3c4' }}
                    >
                      <span
                        className="inline-block h-3 w-3 rounded-full bg-white transition-transform"
                        style={{ transform: autopilotDryRun ? 'translateX(14px)' : 'translateX(2px)' }}
                      />
                    </button>
                    <span className="text-[#708e8e] text-xs">Dry Run</span>
                  </div>
                </div>
              </div>
            </details>

            <div className="flex items-center gap-2">
              {!isStreaming ? (
                <button
                  onClick={handleAutopilotSubmit}
                  disabled={!autopilotTarget.trim()}
                  className="px-4 py-1 text-xs font-bold border border-[#FF8C00] text-[#FF8C00] bg-[#FF8C00]/10 hover:bg-[#FF8C00]/20 shadow-[inset_0_0_18px_rgba(255,140,0,0.5)] hover:shadow-[inset_0_0_28px_rgba(255,140,0,0.7)] transition-colors disabled:opacity-30"
                >
                  [RUN AUTOPILOT]
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

        {/* Shared output panel for query/autopilot/swarm */}
        {showOutputPanel && (
          <div className="flex-1 flex flex-col gap-0 overflow-hidden">
            {/* Output section */}
            <details open className="border border-[#bbc3c4] bg-[#ede4d1] overflow-hidden flex flex-col group">
              <summary className="px-3 py-1.5 border-b border-[#bbc3c4] flex items-center justify-between cursor-pointer hover:bg-[#bbc3c4]/20">
                <span className="text-[#0078c8] text-xs font-bold flex items-center gap-1.5">
                  <ScrollText className="w-3 h-3" />STREAMING RESPONSE
                </span>
                {scanResult && (
                  <span className="text-xs text-[#708e8e]">
                    {scanResult.finding_count != null && <span className="text-[#005661] mr-3">findings: <b className="text-[#00b368]">{String(scanResult.finding_count)}</b></span>}
                    {scanResult.saved_count != null && <span className="text-[#005661]">saved: <b className="text-[#00b368]">{String(scanResult.saved_count)}</b></span>}
                  </span>
                )}
              </summary>
              <pre
                ref={scanOutputRef}
                className="flex-1 overflow-auto p-3 text-xs text-[#005661] font-mono whitespace-pre-wrap leading-relaxed"
              >
                {scanOutput || <span className="text-[#bbc3c4]">agent output will appear here…</span>}
              </pre>
            </details>

            {/* Agent Sessions section */}
            <details open className="border border-[#bbc3c4] bg-[#f6edda] overflow-hidden">
              <summary className="px-3 py-1.5 border-b border-[#bbc3c4] cursor-pointer hover:bg-[#bbc3c4]/20">
                <span className="text-[#0078c8] text-xs font-bold inline-flex items-center gap-1.5">
                  <Layers className="w-3 h-3" />AGENT SESSIONS
                  {sessionsData?.total != null && <span className="text-[#708e8e] font-normal ml-1">({sessionsData.total})</span>}
                </span>
              </summary>
              <div className="flex" style={{ minHeight: expandedSessionUuid && sessionDetail ? 320 : undefined }}>
                <div className={`${expandedSessionUuid && sessionDetail ? 'w-1/2' : 'w-full'} overflow-x-auto`}>
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-[#bbc3c4] text-[#708e8e]">
                        <th className="text-left px-3 py-1 font-bold">STATUS</th>
                        <th className="text-left px-3 py-1 font-bold">UUID</th>
                        <th className="text-left px-3 py-1 font-bold">MODE</th>
                        <th className="text-left px-3 py-1 font-bold">AGENT</th>
                        <th className="text-left px-3 py-1 font-bold">TARGET</th>
                        <th className="text-right px-3 py-1 font-bold">FINDINGS</th>
                        <th className="text-right px-3 py-1 font-bold">SAVED</th>
                        <th className="text-right px-3 py-1 font-bold">DURATION</th>
                        <th className="text-left px-3 py-1 font-bold">COMPLETED</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sessionsData?.data && sessionsData.data.length > 0 ? (
                        sessionsData.data.map((s: AgentSession) => (
                          <tr
                            key={s.uuid}
                            onClick={() => setExpandedSessionUuid(prev => prev === s.uuid ? null : s.uuid)}
                            className={`border-b border-[#bbc3c4]/50 hover:bg-[#bbc3c4]/20 cursor-pointer ${expandedSessionUuid === s.uuid ? 'bg-[#ede4d1]' : ''}`}
                          >
                            <td className="px-3 py-1"><StatusBadge status={s.status} /></td>
                            <td className="px-3 py-1 text-[#0078c8] font-mono">{s.uuid.slice(0, 8)}</td>
                            <td className="px-3 py-1 text-[#708e8e]">{s.mode}</td>
                            <td className="px-3 py-1 text-[#005661]">{s.agent_name || '—'}</td>
                            <td className="px-3 py-1 text-[#005661]">{s.target_url ? truncate(s.target_url, 40) : '—'}</td>
                            <td className="px-3 py-1 text-right text-[#005661]">{s.finding_count}</td>
                            <td className="px-3 py-1 text-right text-[#00b368]">{s.saved_count}</td>
                            <td className="px-3 py-1 text-right text-[#005661]">{formatDuration(s.duration_ms)}</td>
                            <td className="px-3 py-1 text-[#708e8e]">{s.completed_at ? formatDate(s.completed_at) : '—'}</td>
                          </tr>
                        ))
                      ) : (
                        <tr><td colSpan={9} className="px-3 py-3 text-center text-[#bbc3c4]">no sessions</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
                {expandedSessionUuid && sessionDetail && (
                  <div className="w-1/2">
                    <SessionDetailPanel session={sessionDetail} onClose={() => setExpandedSessionUuid(null)} />
                  </div>
                )}
              </div>
            </details>
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
