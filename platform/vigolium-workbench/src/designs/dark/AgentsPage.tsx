'use client';

import { useState, useRef, useCallback, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import { Play, Square, Send, Bot, Terminal, MessageSquare, Clock, CheckCircle, XCircle, Loader2, Zap, Layers, Bug, ScrollText, Copy, Check, Upload, Search, ChevronRight, ChevronDown } from 'lucide-react';
import { zipSync } from 'fflate';
import { useAgentSessions, useAgentSessionDetail, useUploadRepo } from '@/api/hooks';
import { fetchSSE } from '@/lib/sse';
import type { AgentSession, AgentSessionDetail } from '@/api/types';
import { formatDate, formatDuration, truncate } from '@/lib/formatters';
import PageShell from './PageShell';
import Dropdown from './Dropdown';

type ScanType = 'quick' | 'deep' | 'ask';

const AGENT_OPTIONS = [
  { value: '', label: 'default' },
  { value: 'claude', label: 'claude' },
  { value: 'opencode', label: 'opencode' },
  { value: 'gemini', label: 'gemini' },
  { value: 'custom', label: 'custom' },
];

const SCAN_TYPE_META: Record<ScanType, { label: string; desc: string; icon: typeof Bug; endpoint: string; btnLabel: string }> = {
  quick: { label: 'Swarm', desc: 'AI-guided targeted vulnerability scan with module selection.', icon: Bug, endpoint: '/api/agent/run/swarm', btnLabel: 'START SCAN' },
  deep: { label: 'Autopilot', desc: 'Full autonomy — agent drives the scanner for exploratory testing.', icon: Bot, endpoint: '/api/agent/run/autopilot', btnLabel: 'START SCAN' },
  ask: { label: 'Ask AI', desc: 'Single prompt for code review, endpoint discovery, or security questions.', icon: Search, endpoint: '/api/agent/run/query', btnLabel: 'ASK' },
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
        <button onClick={onClose} className="text-[#918175] hover:text-[#fce8c3] text-xs font-bold px-1">✕</button>
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
          <div><span className="text-[#918175]">phases </span><span className="text-[#fce8c3]">{session.phases_run.join(' → ')}</span></div>
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
              <button
                onClick={() => copyToClipboard(session.prompt_sent!, 'prompt')}
                className="absolute top-1.5 right-2 text-[#918175] hover:text-[#fce8c3] p-0.5"
                title="Copy to clipboard"
              >
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
              <button
                onClick={() => copyToClipboard(session.agent_raw_output!, 'output')}
                className="absolute top-1.5 right-2 z-10 text-[#918175] hover:text-[#fce8c3] p-0.5"
                title="Copy to clipboard"
              >
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
              <button
                onClick={() => copyToClipboard(tryPrettyJson(session.attack_plan), 'plan')}
                className="absolute top-1.5 right-2 z-10 text-[#918175] hover:text-[#fce8c3] p-0.5"
                title="Copy to clipboard"
              >
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
              <button
                onClick={() => copyToClipboard(tryPrettyJson(session.triage_result), 'triage')}
                className="absolute top-1.5 right-2 text-[#918175] hover:text-[#fce8c3] p-0.5"
                title="Copy to clipboard"
              >
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

/* ── Detect input type from pasted text ── */
type DetectedInputType = 'url' | 'raw' | 'curl' | 'targets';

function detectInputType(input: string): DetectedInputType {
  const trimmed = input.trim();
  if (!trimmed) return 'url';
  if (/^curl\s/i.test(trimmed)) return 'curl';
  if (/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+\s*HTTP\//i.test(trimmed)) return 'raw';
  if (/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\//i.test(trimmed)) return 'raw';
  const lines = trimmed.split('\n').filter(l => l.trim());
  if (lines.length > 1 && lines.every(l => /^https?:\/\//.test(l.trim()))) return 'targets';
  return 'url';
}

const INPUT_TYPE_LABELS: Record<DetectedInputType, string> = {
  url: 'url',
  raw: 'raw request',
  curl: 'curl',
  targets: 'multi-target',
};

const INPUT_TYPE_COLORS: Record<DetectedInputType, string> = {
  url: '#7fd962',
  raw: '#f2c55c',
  curl: '#68a8e4',
  targets: '#2be4d0',
};

export default function AgentsPage() {
  const [scanType, setScanType] = useState<ScanType>('quick');

  // Unified input
  const [input, setInput] = useState('');
  const [prompt, setPrompt] = useState('');
  const inputTextareaRef = useRef<HTMLTextAreaElement>(null);
  const promptTextareaRef = useRef<HTMLTextAreaElement>(null);

  const detectedInputType = input.trim() ? detectInputType(input) : null;

  // Advanced options (shared across modes)
  const [agent, setAgent] = useState('');
  const [moduleTags, setModuleTags] = useState('');
  const [vulnType, setVulnType] = useState('');
  const [sourcePath, setSourcePath] = useState('');
  const [timeout, setTimeout_] = useState('');
  const [instruction, setInstruction] = useState('');
  const [files, setFiles] = useState('');
  const [focus, setFocus] = useState('');
  const [profile, setProfile] = useState('');
  const [maxIterations, setMaxIterations] = useState('');
  const [additionalInputs, setAdditionalInputs] = useState('');
  const [scanUuid, setScanUuid] = useState('');
  const [projectUuid, setProjectUuid] = useState('');
  const [discover, setDiscover] = useState(false);
  const [codeAudit, setCodeAudit] = useState(false);
  const [skipSast, setSkipSast] = useState(false);
  const [dryRun, setDryRun] = useState(false);

  // Chat state
  const [showChat, setShowChat] = useState(false);
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
  const [scanOutput, setScanOutput] = useState('');
  const [scanResult, setScanResult] = useState<Record<string, unknown> | null>(null);
  const [scanError, setScanError] = useState('');
  const abortRef = useRef<AbortController | null>(null);
  const scanOutputRef = useRef<HTMLPreElement>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);

  // Agent sessions
  const [expandedSessionUuid, setExpandedSessionUuid] = useState<string | null>(null);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [outputOpen, setOutputOpen] = useState(true);
  const [recentScansOpen, setRecentScansOpen] = useState(true);
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

  // Auto-expand textareas
  useEffect(() => {
    const el = inputTextareaRef.current;
    if (!el) return;
    const minH = 8 * 16 + 12;
    el.style.height = 'auto';
    el.style.height = `${Math.max(el.scrollHeight, minH)}px`;
  }, [input]);

  useEffect(() => {
    const el = promptTextareaRef.current;
    if (!el) return;
    const minH = 4 * 16 + 12;
    el.style.height = 'auto';
    el.style.height = `${Math.max(el.scrollHeight, minH)}px`;
  }, [prompt]);

  const handleCancel = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    setIsStreaming(false);
  }, []);

  const handleSubmit = useCallback(() => {
    if (isStreaming) return;
    const trimmedInput = input.trim();
    const trimmedPrompt = prompt.trim();

    // For ask mode, we need either a prompt or input
    if (scanType === 'ask' && !trimmedPrompt && !trimmedInput) return;
    // For scan modes, we need an input
    if (scanType !== 'ask' && !trimmedInput) return;

    setScanOutput('');
    setScanResult(null);
    setScanError('');
    setIsStreaming(true);

    const abort = new AbortController();
    abortRef.current = abort;

    const body: Record<string, unknown> = { stream: true };
    const meta = SCAN_TYPE_META[scanType];

    if (scanType === 'quick') {
      // Swarm mode
      const inputType = detectInputType(trimmedInput);
      if (inputType === 'raw') {
        body.http_request_base64 = btoa(trimmedInput);
      } else {
        body.input = trimmedInput;
      }
      if (additionalInputs) body.inputs = additionalInputs.split('\n').map((s) => s.trim()).filter(Boolean);
      if (moduleTags) body.module_tags = moduleTags.split(',').map((t) => t.trim()).filter(Boolean);
      if (vulnType) body.vuln_type = vulnType;
      if (maxIterations) body.max_iterations = parseInt(maxIterations, 10);
      if (instruction) body.instruction = instruction;
      if (files) body.files = files.split('\n').map((s) => s.trim()).filter(Boolean);
      if (focus) body.focus = focus;
      if (profile) body.profile = profile;
      if (discover) body.discover = true;
      if (codeAudit) body.code_audit = true;
      if (skipSast) body.skip_sast = true;
      if (projectUuid) body.project_uuid = projectUuid;
    } else if (scanType === 'deep') {
      // Autopilot mode
      body.target = trimmedInput;
      if (focus) body.focus = focus;
      if (instruction) body.system_prompt = instruction;
      if (maxIterations) body.max_commands = parseInt(maxIterations, 10);
      if (files) body.files = files.split(',').map((f) => f.trim()).filter(Boolean);
    } else {
      // Ask AI / Query mode
      if (trimmedPrompt) body.prompt = trimmedPrompt;
      if (trimmedInput) body.source = trimmedInput;
      if (files) body.files = files.split(',').map((f) => f.trim()).filter(Boolean);
    }

    // Shared fields
    if (agent) body.agent = agent;
    if (sourcePath) body.source = sourcePath;
    if (timeout) body.timeout = timeout;
    if (scanUuid) body.scan_uuid = scanUuid;
    if (dryRun) body.dry_run = true;
    if (sourcePath) body.repo_path = sourcePath;

    fetchSSE(meta.endpoint, body, {
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
  }, [isStreaming, input, prompt, scanType, agent, moduleTags, vulnType, sourcePath, timeout, instruction, files, focus, profile, maxIterations, additionalInputs, scanUuid, projectUuid, discover, codeAudit, skipSast, dryRun, scrollScanOutput]);

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
        setSourcePath(data.repo_path);
      },
    });
  }, [uploadRepo]);

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

  const inputClass = 'bg-[#141310] border border-[#2e2b26] text-[#fce8c3] text-xs px-2 py-1 focus:outline-none focus:border-[#7fd962]/50 w-full';

  const scanTypeBtnClass = (active: boolean) =>
    `flex items-center gap-1.5 px-3 py-1 text-xs font-bold transition-all ${
      active
        ? 'text-[#7fd962] bg-[#7fd962]/10 border border-[#7fd962]/40'
        : 'text-[#918175] hover:text-[#fce8c3] border border-[#2e2b26] hover:border-[#918175]/50'
    }`;

  const canSubmit = scanType === 'ask'
    ? (prompt.trim() || input.trim())
    : input.trim();

  return (
    <PageShell>
      <div className="flex flex-col" style={{ height: 'calc(100vh - 68px)', minHeight: 500 }}>
        {/* ── Main form section ── */}
        <div className="px-3 py-3 border border-b-0 border-[#2e2b26] bg-[#1c1b19] space-y-3">

          {/* Scan type selector */}
          <div className="flex items-center gap-2">
            {(Object.keys(SCAN_TYPE_META) as ScanType[]).map((t) => {
              const meta = SCAN_TYPE_META[t];
              const Icon = meta.icon;
              return (
                <button key={t} onClick={() => setScanType(t)} className={scanTypeBtnClass(scanType === t)}>
                  <Icon className="w-3.5 h-3.5" />{meta.label}
                </button>
              );
            })}

            {/* Chat toggle */}
            <button
              onClick={() => setShowChat(!showChat)}
              className={`ml-auto flex items-center gap-1.5 px-3 py-1 text-xs font-bold transition-all ${
                showChat
                  ? 'text-[#68a8e4] bg-[#68a8e4]/10 border border-[#68a8e4]/40'
                  : 'text-[#918175] hover:text-[#fce8c3] border border-[#2e2b26] hover:border-[#918175]/50'
              }`}
            >
              <MessageSquare className="w-3.5 h-3.5" />Chat
            </button>

            {isStreaming && (
              <span className="text-xs text-[#68a8e4] flex items-center gap-1">
                <Loader2 className="w-3 h-3 animate-spin" /> scanning…
              </span>
            )}
          </div>

          <p className="text-[#706560] text-xs italic">{SCAN_TYPE_META[scanType].desc}</p>

          {/* Unified target input + source upload */}
          {scanType === 'ask' ? (
            <div className="space-y-2">
              <div>
                <label className="text-[#918175] text-xs block mb-0.5">Prompt <span className="text-[#ef2f27]">*</span></label>
                <textarea
                  ref={promptTextareaRef}
                  value={prompt}
                  onChange={(e) => setPrompt(e.target.value)}
                  placeholder="Analyze this codebase for authentication bypass vulnerabilities..."
                  rows={4}
                  className={`${inputClass} resize-y overflow-hidden`}
                />
              </div>
              <div className="flex gap-2">
                <div className="flex-1">
                  <label className="text-[#918175] text-xs block mb-0.5">Source / Repo Path <span className="text-[#706560] font-normal italic">— optional</span></label>
                  <input
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder="/path/to/source or https://github.com/org/repo"
                    className={inputClass}
                  />
                </div>
                <div
                  onDragEnter={onUploadDragEnter} onDragLeave={onUploadDragLeave} onDragOver={onUploadDragOver} onDrop={onUploadDrop}
                  className={`w-1/3 shrink-0 border border-dashed flex flex-col items-center justify-center text-center transition-colors ${uploadCompressing || uploadRepo.isPending ? '' : 'cursor-pointer'} ${uploadDragging ? 'border-[#7fd962] bg-[#7fd962]/10' : 'border-[#2e2b26] hover:border-[#7fd962]/50'}`}
                  onClick={() => { if (!uploadCompressing && !uploadRepo.isPending) uploadFileInputRef.current?.click(); }}
                >
                  <input ref={uploadFileInputRef} type="file" accept=".zip,.tar.gz,.tgz,.tar" onChange={handleFileUpload} className="hidden" />
                  {uploadCompressing || uploadRepo.isPending ? (
                    <span className="text-xs text-[#fce8c3] flex items-center gap-1"><Loader2 className="w-3 h-3 text-[#7fd962] animate-spin" />{uploadCompressing ? 'Compressing…' : 'Uploading…'}</span>
                  ) : uploadRepo.isSuccess ? (
                    <span className="text-[10px] text-[#98bc37]">uploaded</span>
                  ) : (
                    <><Upload className="w-5 h-5 text-[#7fd962]/70 mb-1" /><span className="text-xs text-[#918175]">{uploadDragging ? 'Drop here to upload' : 'Upload source code'}</span><span className="text-[10px] text-[#706560] mt-0.5">zip, tar.gz, or drop a folder</span></>
                  )}
                  {uploadRepo.isError && <span className="text-[10px] text-[#ef2f27]">failed</span>}
                </div>
              </div>
            </div>
          ) : (
            <div className="flex gap-2 items-stretch">
              <div className="flex-1 flex flex-col">
                <div className="flex items-center gap-2 mb-0.5">
                  <label className="text-[#918175] text-xs">
                    Target <span className="text-[#ef2f27]">*</span>
                  </label>
                  {detectedInputType && (
                    <span className="text-[10px] px-1.5 py-0.5 border" style={{ color: INPUT_TYPE_COLORS[detectedInputType], borderColor: INPUT_TYPE_COLORS[detectedInputType] + '40', backgroundColor: INPUT_TYPE_COLORS[detectedInputType] + '10' }}>
                      {INPUT_TYPE_LABELS[detectedInputType]}
                    </span>
                  )}
                </div>
                <textarea
                  ref={inputTextareaRef}
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder={scanType === 'deep'
                    ? 'https://example.com'
                    : "Paste URL, targets, raw HTTP request, or curl command..."}
                  rows={8}
                  className={`${inputClass} resize-y font-mono flex-1 overflow-hidden`}
                />
              </div>
              <div className="w-1/3 shrink-0 flex flex-col gap-1.5">
                <div>
                  <label className="text-[#918175] text-xs block mb-0.5">Source Path</label>
                  <input value={sourcePath} onChange={(e) => setSourcePath(e.target.value)} placeholder="/path/to/source" className={inputClass} />
                </div>
                <div
                  onDragEnter={onUploadDragEnter} onDragLeave={onUploadDragLeave} onDragOver={onUploadDragOver} onDrop={onUploadDrop}
                  className={`flex-1 min-h-[120px] border border-dashed flex flex-col items-center justify-center text-center transition-colors ${uploadCompressing || uploadRepo.isPending ? '' : 'cursor-pointer'} ${uploadDragging ? 'border-[#7fd962] bg-[#7fd962]/10' : 'border-[#2e2b26] hover:border-[#7fd962]/50'}`}
                  onClick={() => { if (!uploadCompressing && !uploadRepo.isPending) uploadFileInputRef.current?.click(); }}
                >
                  <input ref={uploadFileInputRef} type="file" accept=".zip,.tar.gz,.tgz,.tar" onChange={handleFileUpload} className="hidden" />
                  {uploadCompressing || uploadRepo.isPending ? (
                    <span className="text-xs text-[#fce8c3] flex items-center gap-1"><Loader2 className="w-3 h-3 text-[#7fd962] animate-spin" />{uploadCompressing ? 'Compressing…' : 'Uploading…'}</span>
                  ) : uploadRepo.isSuccess ? (
                    <span className="text-[10px] text-[#98bc37]">uploaded</span>
                  ) : (
                    <><Upload className="w-5 h-5 text-[#7fd962]/70 mb-1" /><span className="text-xs text-[#918175]">{uploadDragging ? 'Drop here to upload' : 'Upload source code'}</span><span className="text-[10px] text-[#706560] mt-0.5">zip, tar.gz, or drop a folder</span></>
                  )}
                  {uploadRepo.isError && <span className="text-[10px] text-[#ef2f27]">failed</span>}
                </div>
              </div>
            </div>
          )}

          {/* Advanced options */}
          <div>
            <button onClick={() => setAdvancedOpen(v => !v)} className="text-[#706560] text-xs cursor-pointer hover:text-[#918175] select-none flex items-center gap-1">
              {advancedOpen ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
              Advanced Options
            </button>
            {advancedOpen && <div className="space-y-2 mt-2 pt-2 border-t border-[#2e2b26]/50">
              <div className="grid grid-cols-4 gap-2">
                <div>
                  <label className="text-[#918175] text-xs block mb-0.5">Agent</label>
                  <Dropdown value={agent} onChange={setAgent} options={AGENT_OPTIONS} />
                </div>
                {scanType === 'quick' && (
                  <>
                    <div>
                      <label className="text-[#918175] text-xs block mb-0.5">Module Tags</label>
                      <input value={moduleTags} onChange={(e) => setModuleTags(e.target.value)} placeholder="xss, sqli, auth" className={inputClass} />
                    </div>
                    <div>
                      <label className="text-[#918175] text-xs block mb-0.5">Vuln Type</label>
                      <input value={vulnType} onChange={(e) => setVulnType(e.target.value)} placeholder="sqli" className={inputClass} />
                    </div>
                  </>
                )}
                <div>
                  <label className="text-[#918175] text-xs block mb-0.5">Timeout</label>
                  <input value={timeout} onChange={(e) => setTimeout_(e.target.value)} placeholder="30m" className={inputClass} />
                </div>
                <div>
                  <label className="text-[#918175] text-xs block mb-0.5">Focus</label>
                  <input value={focus} onChange={(e) => setFocus(e.target.value)} placeholder="auth, injection" className={inputClass} />
                </div>
                {scanType === 'quick' && (
                  <>
                    <div>
                      <label className="text-[#918175] text-xs block mb-0.5">Max Iterations</label>
                      <input value={maxIterations} onChange={(e) => setMaxIterations(e.target.value)} placeholder="3" className={inputClass} />
                    </div>
                    <div>
                      <label className="text-[#918175] text-xs block mb-0.5">Profile</label>
                      <input value={profile} onChange={(e) => setProfile(e.target.value)} placeholder="light, thorough" className={inputClass} />
                    </div>
                  </>
                )}
                {scanType === 'deep' && (
                  <div>
                    <label className="text-[#918175] text-xs block mb-0.5">Max Commands</label>
                    <input value={maxIterations} onChange={(e) => setMaxIterations(e.target.value)} placeholder="50" className={inputClass} />
                  </div>
                )}
              </div>

              <div>
                <label className="text-[#918175] text-xs block mb-0.5">{scanType === 'deep' ? 'System Prompt' : 'Instruction'}</label>
                <textarea value={instruction} onChange={(e) => setInstruction(e.target.value)} placeholder="Focus on business logic flaws in the payment flow" rows={2} className={`${inputClass} resize-y`} />
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-[#918175] text-xs block mb-0.5">Files</label>
                  <textarea value={files} onChange={(e) => setFiles(e.target.value)} placeholder={"routes/api.js\ncontrollers/auth.js"} rows={2} className={`${inputClass} resize-y font-mono`} />
                </div>
                {scanType === 'quick' && (
                  <div>
                    <label className="text-[#918175] text-xs block mb-0.5">Additional Inputs (one per line)</label>
                    <textarea value={additionalInputs} onChange={(e) => setAdditionalInputs(e.target.value)} placeholder={"https://example.com/api/users\nhttps://example.com/api/admin"} rows={2} className={`${inputClass} resize-y font-mono`} />
                  </div>
                )}
              </div>

              <div className="grid grid-cols-3 gap-2">
                <div>
                  <label className="text-[#918175] text-xs block mb-0.5">Scan UUID</label>
                  <input value={scanUuid} onChange={(e) => setScanUuid(e.target.value)} placeholder="uuid" className={inputClass} />
                </div>
                {scanType === 'quick' && (
                  <div>
                    <label className="text-[#918175] text-xs block mb-0.5">Project UUID</label>
                    <input value={projectUuid} onChange={(e) => setProjectUuid(e.target.value)} placeholder="uuid" className={inputClass} />
                  </div>
                )}
              </div>

              {/* Toggle switches */}
              <div className="flex flex-wrap items-center gap-x-4 gap-y-2 pt-1">
                {scanType === 'quick' && (
                  <>
                    {([
                      ['Discover', discover, setDiscover] as const,
                      ['Code Audit', codeAudit, setCodeAudit] as const,
                      ['Skip SAST', skipSast, setSkipSast] as const,
                    ]).map(([label, value, setter]) => (
                      <div key={label} className="flex items-center gap-2">
                        <button
                          type="button" role="switch" aria-checked={value}
                          onClick={() => setter(!value)}
                          className="relative inline-flex h-4 w-7 items-center rounded-full transition-colors shrink-0"
                          style={{ backgroundColor: value ? '#7fd962' : '#2e2b26' }}
                        >
                          <span className="inline-block h-3 w-3 rounded-full bg-[#fce8c3] transition-transform" style={{ transform: value ? 'translateX(14px)' : 'translateX(2px)' }} />
                        </button>
                        <span className="text-[#918175] text-xs">{label}</span>
                      </div>
                    ))}
                  </>
                )}
                <div className="flex items-center gap-2">
                  <button
                    type="button" role="switch" aria-checked={dryRun}
                    onClick={() => setDryRun(!dryRun)}
                    className="relative inline-flex h-4 w-7 items-center rounded-full transition-colors shrink-0"
                    style={{ backgroundColor: dryRun ? '#7fd962' : '#2e2b26' }}
                  >
                    <span className="inline-block h-3 w-3 rounded-full bg-[#fce8c3] transition-transform" style={{ transform: dryRun ? 'translateX(14px)' : 'translateX(2px)' }} />
                  </button>
                  <span className="text-[#918175] text-xs">Dry Run</span>
                </div>
              </div>
            </div>}
          </div>

          {/* Submit row */}
          <div className="flex items-center gap-2">
            {!isStreaming ? (
              <button
                onClick={handleSubmit}
                disabled={!canSubmit}
                className="px-5 py-1.5 text-xs font-bold border border-[#FF9F2F] text-[#FF9F2F] bg-[#FF9F2F]/10 hover:bg-[#FF9F2F]/20 shadow-[inset_0_0_18px_rgba(255,159,47,0.5)] hover:shadow-[inset_0_0_28px_rgba(255,159,47,0.7)] transition-colors disabled:opacity-30 flex items-center gap-1.5"
              >
                <Play className="w-3 h-3" />{SCAN_TYPE_META[scanType].btnLabel}
              </button>
            ) : (
              <button
                onClick={handleCancel}
                className="flex items-center gap-1 px-4 py-1.5 text-xs font-bold bg-[#ef2f27]/10 text-[#ef2f27] border border-[#ef2f27]/30 hover:bg-[#ef2f27]/20 transition-colors"
              >
                <Square className="w-3 h-3" /> CANCEL
              </button>
            )}
            {scanError && <span className="text-xs text-[#ef2f27]">{scanError}</span>}
            {scanResult && (
              <span className="text-xs text-[#918175] ml-2">
                {scanResult.finding_count != null && <span className="text-[#fce8c3] mr-3">findings: <b className="text-[#7fd962]">{String(scanResult.finding_count)}</b></span>}
                {scanResult.saved_count != null && <span className="text-[#fce8c3]">saved: <b className="text-[#98bc37]">{String(scanResult.saved_count)}</b></span>}
              </span>
            )}
          </div>
        </div>

        {/* ── Chat panel (toggleable) ── */}
        {showChat && (
          <div className="flex flex-col border-x border-[#2e2b26] bg-[#1c1b19] overflow-hidden" style={{ height: 280 }}>
            <div className="px-3 py-1 border-b border-[#2e2b26] flex items-center justify-between">
              <span className="text-[#7fd962] text-xs font-bold flex items-center gap-1.5"><MessageSquare className="w-3 h-3" />CHAT</span>
              <button onClick={() => setShowChat(false)} className="text-[#918175] hover:text-[#fce8c3] text-xs font-bold px-1">✕</button>
            </div>
            <div className="flex-1 overflow-auto p-3 space-y-3">
              {messages.length === 0 && (
                <div className="flex items-center justify-center h-full">
                  <span className="text-[#403d38] text-xs flex items-center gap-2"><Bot className="w-4 h-4" /> send a message to chat with the agent</span>
                </div>
              )}
              {messages.map((msg, i) => (
                <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div
                    className={`max-w-[75%] px-3 py-2 text-xs leading-relaxed ${
                      msg.role === 'user'
                        ? 'bg-[#2e2b26] text-[#fce8c3] rounded-l-lg rounded-tr-lg'
                        : 'bg-[#141310] text-[#a89888] rounded-r-lg rounded-tl-lg'
                    }`}
                  >
                    {msg.role === 'assistant' ? (
                      <div className="prose prose-invert prose-xs max-w-none [&_pre]:bg-[#0e0d0b] [&_pre]:p-2 [&_pre]:text-xs [&_code]:text-[#98bc37] [&_p]:m-0 [&_p]:mb-1.5">
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
            <div className="border-t border-[#2e2b26] px-3 py-2 flex items-end gap-2">
              <textarea
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                onKeyDown={handleChatKeyDown}
                placeholder={isStreaming ? 'Agent is responding…' : 'Type a message…'}
                disabled={isStreaming}
                rows={1}
                className="flex-1 bg-[#141310] border border-[#2e2b26] text-[#fce8c3] text-xs px-2 py-1.5 resize-none focus:outline-none focus:border-[#7fd962]/50 disabled:opacity-50"
              />
              {isStreaming ? (
                <button onClick={handleCancel} className="flex items-center gap-1 px-3 py-1.5 text-xs font-bold bg-[#ef2f27]/10 text-[#ef2f27] border border-[#ef2f27]/30 hover:bg-[#ef2f27]/20 transition-colors shrink-0">
                  <Square className="w-3 h-3" />
                </button>
              ) : (
                <button
                  onClick={handleChatSend}
                  disabled={!chatInput.trim()}
                  className="flex items-center gap-1 px-3 py-1.5 text-xs font-bold bg-[#7fd962]/10 text-[#7fd962] border border-[#7fd962]/30 hover:bg-[#7fd962]/20 transition-colors disabled:opacity-30 shrink-0"
                >
                  <Send className="w-3 h-3" />
                </button>
              )}
            </div>
          </div>
        )}

        {/* ── Streaming output ── */}
        <div className="flex-1 flex flex-col gap-0 overflow-hidden">
          <div className="border border-[#2e2b26] bg-[#141310] overflow-hidden flex flex-col">
            <button onClick={() => setOutputOpen(v => !v)} className="px-3 py-1.5 border-b border-[#2e2b26] flex items-center gap-1.5 cursor-pointer hover:bg-[#2e2b26]/30 text-left">
              {outputOpen ? <ChevronDown className="w-3 h-3 text-[#918175]" /> : <ChevronRight className="w-3 h-3 text-[#918175]" />}
              <span className="text-[#7fd962] text-xs font-bold flex items-center gap-1.5">
                <ScrollText className="w-3 h-3" />OUTPUT
              </span>
            </button>
            {outputOpen && (
              <pre
                ref={scanOutputRef}
                className="flex-1 overflow-auto p-3 text-xs text-[#a89888] font-mono whitespace-pre-wrap leading-relaxed"
              >
                {scanOutput || <span className="text-[#403d38]">agent output will appear here…</span>}
              </pre>
            )}
          </div>

          {/* ── Recent scans ── */}
          <div className="border border-[#2e2b26] bg-[#1c1b19] overflow-hidden">
            <button onClick={() => setRecentScansOpen(v => !v)} className="w-full px-3 py-1.5 border-b border-[#2e2b26] cursor-pointer hover:bg-[#2e2b26]/30 flex items-center gap-1.5 text-left">
              {recentScansOpen ? <ChevronDown className="w-3 h-3 text-[#918175]" /> : <ChevronRight className="w-3 h-3 text-[#918175]" />}
              <span className="text-[#7fd962] text-xs font-bold inline-flex items-center gap-1.5">
                <Layers className="w-3 h-3" />RECENT SCANS
                {sessionsData?.total != null && <span className="text-[#918175] font-normal ml-1">({sessionsData.total})</span>}
              </span>
            </button>
            {recentScansOpen && (
              <div className="flex" style={{ minHeight: expandedSessionUuid && sessionDetail ? 320 : undefined }}>
                <div className={`${expandedSessionUuid && sessionDetail ? 'w-1/2' : 'w-full'} overflow-x-auto`}>
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-[#2e2b26] text-[#706560]">
                        <th className="text-left px-3 py-1 font-bold">STATUS</th>
                        <th className="text-left px-3 py-1 font-bold">TYPE</th>
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
                            className={`border-b border-[#2e2b26]/50 hover:bg-[#2e2b26]/30 cursor-pointer ${expandedSessionUuid === s.uuid ? 'bg-[#2e2b26]' : ''}`}
                          >
                            <td className="px-3 py-1"><StatusBadge status={s.status} /></td>
                            <td className="px-3 py-1 text-[#918175]">{s.mode}</td>
                            <td className="px-3 py-1 text-[#fce8c3]">{s.target_url ? truncate(s.target_url, 50) : '—'}</td>
                            <td className="px-3 py-1 text-right text-[#fce8c3]">{s.finding_count}</td>
                            <td className="px-3 py-1 text-right text-[#98bc37]">{s.saved_count}</td>
                            <td className="px-3 py-1 text-right text-[#fce8c3]">{formatDuration(s.duration_ms)}</td>
                            <td className="px-3 py-1 text-[#706560]">{s.completed_at ? formatDate(s.completed_at) : '—'}</td>
                          </tr>
                        ))
                      ) : (
                        <tr><td colSpan={7} className="px-3 py-3 text-center text-[#403d38]">no scans yet</td></tr>
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
            )}
          </div>
        </div>
      </div>
    </PageShell>
  );
}
