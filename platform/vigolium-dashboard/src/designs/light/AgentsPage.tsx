'use client';

import { useState, useRef, useCallback, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import { Play, Square, Send, Bot, Terminal, MessageSquare, Clock, CheckCircle, XCircle, Loader2 } from 'lucide-react';
import { useAgentRuns } from '@/api/hooks';
import { fetchSSE } from '@/lib/sse';
import type { AgentRunStatusResponse } from '@/api/types';
import PageShell from './PageShell';

type MainTab = 'scan' | 'chat';
type ScanMode = 'template' | 'custom';

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

export default function AgentsPage() {
  const [mainTab, setMainTab] = useState<MainTab>('scan');

  // Scan tab state
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

  const handleScanSubmit = useCallback(() => {
    if (isStreaming) return;
    setScanOutput('');
    setScanResult(null);
    setScanError('');
    setIsStreaming(true);

    const abort = new AbortController();
    abortRef.current = abort;

    const body: Record<string, unknown> = { stream: true };
    if (scanMode === 'template') {
      if (agentName) body.agent_name = agentName;
      if (promptTemplate) body.prompt_template = promptTemplate;
    } else {
      if (customPrompt) body.prompt = customPrompt;
    }
    if (repoPath) body.repo_path = repoPath;
    if (files) body.files = files.split(',').map((f) => f.trim()).filter(Boolean);
    if (append) body.append = append;
    if (source) body.source = source;
    if (scanUuid) body.scan_uuid = scanUuid;

    fetchSSE('/api/agent/run', body, {
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

  const handleChatSend = useCallback(() => {
    const text = chatInput.trim();
    if (!text || isStreaming) return;
    setChatInput('');
    setMessages((prev) => [...prev, { role: 'user', content: text }]);
    setIsStreaming(true);

    const abort = new AbortController();
    abortRef.current = abort;

    setMessages((prev) => [...prev, { role: 'assistant', content: '' }]);

    fetchSSE('/api/agent/run', { prompt: text, stream: true }, {
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
  }, [chatInput, isStreaming]);

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

  return (
    <PageShell>
      <div className="flex flex-col" style={{ height: 'calc(100vh - 120px)', minHeight: 500 }}>
        {/* Tab bar */}
        <div className="px-3 py-1.5 border border-[#bbc3c4] bg-[#f6edda] flex items-center gap-1.5">
          <div className="flex border border-[#bbc3c4]">
            <button onClick={() => setMainTab('scan')} className={tabBtnClass(mainTab === 'scan')}>
              <span className="flex items-center gap-1"><Terminal className="w-3 h-3" />SCAN WITH AGENT</span>
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

        {/* Scan tab */}
        {mainTab === 'scan' && (
          <div className="flex-1 flex flex-col gap-0 overflow-hidden">
            {/* Form */}
            <div className="px-3 py-2 border-x border-[#bbc3c4] bg-[#f6edda] space-y-2">
              {/* Mode toggle */}
              <div className="flex items-center gap-2">
                <div className="flex border border-[#bbc3c4]">
                  <button onClick={() => setScanMode('template')} className={tabBtnClass(scanMode === 'template')}>TEMPLATE</button>
                  <button onClick={() => setScanMode('custom')} className={tabBtnClass(scanMode === 'custom')}>CUSTOM PROMPT</button>
                </div>
              </div>

              {scanMode === 'template' ? (
                <div className="grid grid-cols-3 gap-2">
                  <div>
                    <label className="text-[#708e8e] text-xs block mb-0.5">Agent Name</label>
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

              {/* Optional fields */}
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

              {/* Submit / Cancel */}
              <div className="flex items-center gap-2">
                {!isStreaming ? (
                  <button
                    onClick={handleScanSubmit}
                    className="flex items-center gap-1 px-3 py-1 text-xs font-bold bg-[#00b368]/10 text-[#00b368] border border-[#00b368]/30 hover:bg-[#00b368]/20 transition-colors"
                  >
                    <Play className="w-3 h-3" /> RUN AGENT
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

            {/* Output panel */}
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
            {/* Messages area */}
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

            {/* Input area */}
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
