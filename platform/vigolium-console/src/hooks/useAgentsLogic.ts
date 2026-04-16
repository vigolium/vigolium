'use client';

import { useState, useRef, useCallback, useEffect, useMemo } from 'react';
import { useSearchParams } from 'next/navigation';
import { zipSync } from 'fflate';
import { useAgentSessions, useAgentSessionDetail, useUploadRepo, useGitHubCloneUrl, useStartAutopilotRun, useAgentRunStatus } from '@/api/hooks';
import { withDemoKey } from '@/api/client';
import { fetchSSE } from '@/lib/sse';

export type ScanProfile = 'quick' | 'deep' | 'code-review' | 'autopilot';
export type InputMode = 'url' | 'raw' | 'curl';
export type TargetInputTab = 'target' | 'prompt';
export type DetectedInputType = 'url' | 'raw' | 'curl' | 'empty';
export type AdvancedMode = 'swarm' | 'autopilot' | 'query';
export type ScanMode = 'template' | 'custom';

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

export const AGENT_OPTIONS = [
  { value: '', label: 'default' },
  { value: 'claude', label: 'claude' },
  { value: 'opencode', label: 'opencode' },
  { value: 'gemini', label: 'gemini' },
  { value: 'custom', label: 'custom' },
];

export const PROFILE_OPTIONS: { value: ScanProfile; label: string; description: string; icon: string }[] = [
  { value: 'quick', label: 'Quick Scan', description: 'Fast surface-level scan with light profile', icon: 'zap' },
  { value: 'deep', label: 'Deep Scan', description: 'Thorough scan with crawling & discovery', icon: 'layers' },
  { value: 'code-review', label: 'Code Review', description: 'Static analysis & source code audit', icon: 'scroll-text' },
  { value: 'autopilot', label: 'Autopilot', description: 'AI agent drives the CLI autonomously', icon: 'bot' },
];

export const ARCHON_MODE_OPTIONS = [
  { value: '', label: 'Default' },
  { value: 'lite', label: 'Lite' },
  { value: 'scan', label: 'Scan' },
  { value: 'deep', label: 'Deep' },
];

export const INTENSITY_OPTIONS = [
  { value: '', label: 'Default (balanced)' },
  { value: 'quick', label: 'Quick', description: 'Fast surface-level scan for common issues', icon: 'zap' },
  { value: 'balanced', label: 'Balanced', description: 'Thorough scan with smart defaults', icon: 'scale' },
  { value: 'deep', label: 'Deep', description: 'Exhaustive scan with full discovery and verification', icon: 'layers' },
];

const HTTP_METHODS = /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s/;

export function detectInputType(value: string): DetectedInputType {
  const trimmed = value.trim();
  if (!trimmed) return 'empty';
  if (/^curl\s/i.test(trimmed)) return 'curl';
  if (HTTP_METHODS.test(trimmed)) return 'raw';
  return 'url';
}

export function useAgentsLogic() {
  const searchParams = useSearchParams();
  const cloneUrlMutation = useGitHubCloneUrl();

  // Hero state
  const [targetUrl, setTargetUrl] = useState('');
  const [scanProfile, setScanProfile] = useState<ScanProfile>('autopilot');

  // Advanced options visibility
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [advancedMode, setAdvancedMode] = useState<AdvancedMode>('autopilot');

  // Chat panel visibility
  const [chatOpen, setChatOpen] = useState(false);

  // Auto-detect input type from content
  const detectedInputType = useMemo(() => detectInputType(targetUrl), [targetUrl]);

  // Swarm advanced fields
  const [inputMode, setInputMode] = useState<InputMode>('url');
  const [swarmAgent, setSwarmAgent] = useState('');
  const [swarmModuleTags, setSwarmModuleTags] = useState('');
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
  const [swarmSource, setSwarmSource] = useState('');
  const [swarmInputs, setSwarmInputs] = useState('');
  const [swarmSourceAnalysisOnly, setSwarmSourceAnalysisOnly] = useState(false);
  const [swarmDiscover, setSwarmDiscover] = useState(false);
  const [swarmCodeAudit, setSwarmCodeAudit] = useState(false);
  const [swarmSkipSast, setSwarmSkipSast] = useState(false);
  const [swarmDiff, setSwarmDiff] = useState('');
  const [swarmLastCommits, setSwarmLastCommits] = useState('');
  const [swarmTriage, setSwarmTriage] = useState(false);
  const [swarmOnlyPhase, setSwarmOnlyPhase] = useState('');
  const [swarmSkipPhases, setSwarmSkipPhases] = useState('');
  const [swarmStartFrom, setSwarmStartFrom] = useState('');
  const [swarmShowPrompt, setSwarmShowPrompt] = useState(false);
  const [swarmArchon, setSwarmArchon] = useState('');
  const [swarmIntensity, setSwarmIntensity] = useState('');

  // Autopilot advanced fields
  const [autopilotAgent, setAutopilotAgent] = useState('');
  const [autopilotFocus, setAutopilotFocus] = useState('');
  const [autopilotTimeout, setAutopilotTimeout] = useState('');
  const [autopilotInstruction, setAutopilotInstruction] = useState('');
  const [autopilotMaxCommands, setAutopilotMaxCommands] = useState('');
  const [autopilotDryRun, setAutopilotDryRun] = useState(false);
  const [autopilotSource, setAutopilotSource] = useState('');
  const [autopilotFiles, setAutopilotFiles] = useState('');
  const [autopilotScanUuid, setAutopilotScanUuid] = useState('');
  const [autopilotDiff, setAutopilotDiff] = useState('');
  const [autopilotArchonMode, setAutopilotArchonMode] = useState('');
  const [autopilotNoArchon, setAutopilotNoArchon] = useState(false);
  const [autopilotIntensity, setAutopilotIntensity] = useState('');

  // Query advanced fields
  const [scanMode, setScanMode] = useState<ScanMode>('template');
  const [agentName, setAgentName] = useState('');
  const [promptTemplate, setPromptTemplate] = useState('');
  const [customPrompt, setCustomPrompt] = useState('');
  const [repoPath, setRepoPath] = useState('');
  const [queryFiles, setQueryFiles] = useState('');
  const [append, setAppend] = useState('');
  const [querySource, setQuerySource] = useState('');
  const [queryScanUuid, setQueryScanUuid] = useState('');
  const [queryInstruction, setQueryInstruction] = useState('');
  const [querySourceLabel, setQuerySourceLabel] = useState('');

  // Target input tab (target vs prompt)
  const [targetInputTab, setTargetInputTab] = useState<TargetInputTab>('target');
  const [targetPrompt, setTargetPrompt] = useState('');
  const [targetRunId, setTargetRunId] = useState<string | null>(null);
  const [targetError, setTargetError] = useState('');
  const startAutopilotRun = useStartAutopilotRun();
  const { data: targetRunStatus } = useAgentRunStatus(targetRunId);

  const handleTargetSubmit = useCallback(() => {
    const prompt = targetPrompt.trim();
    if (!prompt || startAutopilotRun.isPending) return;
    setTargetError('');
    setTargetRunId(null);
    startAutopilotRun.mutate({ prompt }, {
      onSuccess: (data) => {
        setTargetRunId(data.run_id);
      },
      onError: (err) => {
        setTargetError(err instanceof Error ? err.message : 'Failed to start autopilot run');
      },
    });
  }, [targetPrompt, startAutopilotRun]);

  // Streaming state (scan)
  const [scanOutput, setScanOutput] = useState('');
  const [scanResult, setScanResult] = useState<Record<string, unknown> | null>(null);
  const [scanError, setScanError] = useState('');
  const [isScanStreaming, setIsScanStreaming] = useState(false);
  const scanAbortRef = useRef<AbortController | null>(null);
  const scanOutputRef = useRef<HTMLPreElement>(null);

  // Chat state
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState('');
  const [isChatStreaming, setIsChatStreaming] = useState(false);
  const chatAbortRef = useRef<AbortController | null>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);

  // Repo upload state
  const [uploadDragging, setUploadDragging] = useState(false);
  const [uploadCompressing, setUploadCompressing] = useState(false);
  const uploadDragCounter = useRef(0);
  const uploadFileInputRef = useRef<HTMLInputElement>(null);
  const uploadRepo = useUploadRepo();

  // Sessions
  const [expandedSessionUuid, setExpandedSessionUuid] = useState<string | null>(null);
  const { data: sessionsData } = useAgentSessions({ limit: 20 });
  const { data: sessionDetail } = useAgentSessionDetail(expandedSessionUuid);

  // Auto-fill repo from query param
  useEffect(() => {
    const repo = searchParams.get('repo');
    if (!repo) return;
    setShowAdvanced(true);
    setAdvancedMode('swarm');
    setScanProfile('quick');
    cloneUrlMutation.mutateAsync({ repo }).then((res) => {
      setSwarmSource(res.clone_url);
    }).catch(() => {
      setSwarmSource(`https://github.com/${repo}`);
    });
    window.history.replaceState({}, '', withDemoKey('/agentic-scan'));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Sync advancedMode with scanProfile so the correct advanced section renders
  useEffect(() => {
    if (scanProfile === 'autopilot') setAdvancedMode('autopilot');
    else setAdvancedMode('swarm');
  }, [scanProfile]);

  // Auto-enable Code Audit when source code is selected
  useEffect(() => {
    if (swarmSource) setSwarmCodeAudit(true);
  }, [swarmSource]);

  const scrollScanOutput = useCallback(() => {
    if (scanOutputRef.current) {
      scanOutputRef.current.scrollTop = scanOutputRef.current.scrollHeight;
    }
  }, []);

  const scrollChatToBottom = useCallback(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  useEffect(scrollChatToBottom, [messages, scrollChatToBottom]);

  // SSE callbacks factory
  const makeScanCallbacks = useCallback(() => ({
    onChunk: (text: string) => {
      setScanOutput((prev) => prev + text);
      setTimeout(scrollScanOutput, 0);
    },
    onDone: (result: unknown) => {
      setIsScanStreaming(false);
      scanAbortRef.current = null;
      if (result && typeof result === 'object') setScanResult(result as Record<string, unknown>);
    },
    onError: (err: Error) => {
      setIsScanStreaming(false);
      scanAbortRef.current = null;
      setScanError(err.message);
    },
  }), [scrollScanOutput]);

  const handleScanCancel = useCallback(() => {
    scanAbortRef.current?.abort();
    scanAbortRef.current = null;
    setIsScanStreaming(false);
  }, []);

  const handleChatCancel = useCallback(() => {
    chatAbortRef.current?.abort();
    chatAbortRef.current = null;
    setIsChatStreaming(false);
  }, []);

  // Profile-based submit (the main "Start Scan" action)
  const handleProfileSubmit = useCallback(() => {
    const url = targetUrl.trim();
    if (isScanStreaming || !url) return;
    setScanOutput('');
    setScanResult(null);
    setScanError('');
    setIsScanStreaming(true);

    const abort = new AbortController();
    scanAbortRef.current = abort;
    const callbacks = makeScanCallbacks();

    const sourceBody = swarmSource ? { source: swarmSource } : {};

    if (scanProfile === 'autopilot') {
      const apBody: Record<string, unknown> = { target: url, stream: true };
      if (swarmSource) apBody.source = swarmSource;
      if (autopilotIntensity) apBody.intensity = autopilotIntensity;
      fetchSSE('/api/agent/run/autopilot', apBody, callbacks, abort.signal);
    } else {
      // Custom mode — use advancedMode to decide endpoint
      handleCustomSubmit(url, abort, callbacks);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targetUrl, scanProfile, isScanStreaming, makeScanCallbacks, swarmSource, autopilotIntensity]);

  const handleCustomSubmit = useCallback((url: string, abort: AbortController, callbacks: ReturnType<typeof makeScanCallbacks>) => {
    if (advancedMode === 'swarm') {
      const body: Record<string, unknown> = { stream: true };
      if (detectedInputType === 'raw') {
        body.http_request_base64 = btoa(url);
      } else {
        body.input = url;
      }
      if (swarmInputs) body.inputs = swarmInputs.split('\n').map((s) => s.trim()).filter(Boolean);
      if (swarmSource) body.source = swarmSource;
      if (swarmModuleTags) body.module_names = swarmModuleTags.split(',').map((t) => t.trim()).filter(Boolean);
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
      if (swarmDiff) body.diff = swarmDiff;
      if (swarmLastCommits) body.last_commits = parseInt(swarmLastCommits, 10);
      if (swarmTriage) body.triage = true;
      if (swarmOnlyPhase) body.only_phase = swarmOnlyPhase;
      if (swarmSkipPhases) body.skip_phases = swarmSkipPhases.split(',').map((s) => s.trim()).filter(Boolean);
      if (swarmStartFrom) body.start_from = swarmStartFrom;
      if (swarmShowPrompt) body.show_prompt = true;
      if (swarmArchon) body.archon = swarmArchon;
      if (swarmIntensity) body.intensity = swarmIntensity;
      fetchSSE('/api/agent/run/swarm', body, callbacks, abort.signal);
    } else if (advancedMode === 'autopilot') {
      const body: Record<string, unknown> = { target: url, stream: true };
      if (autopilotAgent) body.agent = autopilotAgent;
      if (autopilotFocus) body.focus = autopilotFocus;
      if (autopilotTimeout) body.timeout = autopilotTimeout;
      if (autopilotInstruction) body.instruction = autopilotInstruction;
      if (autopilotMaxCommands) body.max_commands = parseInt(autopilotMaxCommands, 10);
      if (autopilotDryRun) body.dry_run = true;
      if (autopilotSource) body.source = autopilotSource;
      if (autopilotFiles) body.files = autopilotFiles.split(',').map((f) => f.trim()).filter(Boolean);
      if (autopilotScanUuid) body.scan_uuid = autopilotScanUuid;
      if (autopilotDiff) body.diff = autopilotDiff;
      if (autopilotArchonMode) body.archon_mode = autopilotArchonMode;
      if (autopilotNoArchon) body.no_archon = true;
      if (autopilotIntensity) body.intensity = autopilotIntensity;
      fetchSSE('/api/agent/run/autopilot', body, callbacks, abort.signal);
    } else {
      // query
      const body: Record<string, unknown> = { stream: true };
      if (scanMode === 'template') {
        if (agentName) body.agent = agentName;
        if (promptTemplate) body.prompt_template = promptTemplate;
      } else {
        if (customPrompt) body.prompt = customPrompt;
      }
      if (repoPath) body.source = repoPath;
      if (queryFiles) body.files = queryFiles.split(',').map((f) => f.trim()).filter(Boolean);
      if (append) body.append = append;
      if (querySource) body.source = querySource;
      if (queryScanUuid) body.scan_uuid = queryScanUuid;
      if (queryInstruction) body.instruction = queryInstruction;
      if (querySourceLabel) body.source_label = querySourceLabel;
      fetchSSE('/api/agent/run/query', body, callbacks, abort.signal);
    }
  }, [advancedMode, detectedInputType, swarmInputs, swarmSource, swarmModuleTags, swarmAgent, swarmVulnType, swarmMaxIterations, swarmTimeout, swarmDryRun, swarmScanUuid, swarmProjectUuid, swarmInstruction, swarmFiles, swarmFocus, swarmProfile, swarmSourceAnalysisOnly, swarmDiscover, swarmCodeAudit, swarmSkipSast, swarmDiff, swarmLastCommits, swarmTriage, swarmOnlyPhase, swarmSkipPhases, swarmStartFrom, swarmShowPrompt, swarmArchon, autopilotAgent, autopilotFocus, autopilotTimeout, autopilotInstruction, autopilotMaxCommands, autopilotDryRun, autopilotSource, autopilotFiles, autopilotScanUuid, autopilotDiff, autopilotArchonMode, autopilotNoArchon, scanMode, agentName, promptTemplate, customPrompt, repoPath, queryFiles, append, querySource, queryScanUuid, queryInstruction, querySourceLabel]);

  // Chat
  const handleChatSend = useCallback(() => {
    const text = chatInput.trim();
    if (!text || isChatStreaming) return;
    setChatInput('');
    const newMessages: ChatMessage[] = [...messages, { role: 'user', content: text }];
    setMessages(newMessages);
    setIsChatStreaming(true);

    const abort = new AbortController();
    chatAbortRef.current = abort;

    setMessages((prev) => [...prev, { role: 'assistant', content: '' }]);

    fetchSSE('/api/agent/chat/completions', {
      model: 'default',
      messages: newMessages.map((m) => ({ role: m.role, content: m.content })),
    }, {
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
        setIsChatStreaming(false);
        chatAbortRef.current = null;
      },
      onError: (err) => {
        setIsChatStreaming(false);
        chatAbortRef.current = null;
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
  }, [chatInput, isChatStreaming, messages]);

  const handleChatKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleChatSend();
    }
  }, [handleChatSend]);

  // Repo upload
  const doUpload = useCallback((file: File) => {
    uploadRepo.mutate(file, {
      onSuccess: (data) => {
        if (advancedMode === 'swarm') setSwarmSource(data.source ?? '');
        else if (advancedMode === 'autopilot') setAutopilotSource(data.source ?? '');
        else if (advancedMode === 'query') setRepoPath(data.source ?? '');
      },
    });
  }, [uploadRepo, advancedMode]);

  const handleFileUpload = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    doUpload(file);
    e.target.value = '';
  }, [doUpload]);

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

  return {
    // Hero
    targetUrl, setTargetUrl,
    scanProfile, setScanProfile,
    handleProfileSubmit,

    // Advanced
    showAdvanced, setShowAdvanced,
    advancedMode, setAdvancedMode,

    // Input detection
    detectedInputType,

    // Swarm fields
    inputMode, setInputMode,
    swarmAgent, setSwarmAgent,
    swarmModuleTags, setSwarmModuleTags,
    swarmVulnType, setSwarmVulnType,
    swarmMaxIterations, setSwarmMaxIterations,
    swarmTimeout, setSwarmTimeout,
    swarmDryRun, setSwarmDryRun,
    swarmScanUuid, setSwarmScanUuid,
    swarmProjectUuid, setSwarmProjectUuid,
    swarmInstruction, setSwarmInstruction,
    swarmFiles, setSwarmFiles,
    swarmFocus, setSwarmFocus,
    swarmProfile, setSwarmProfile,
    swarmSource, setSwarmSource,
    swarmInputs, setSwarmInputs,
    swarmSourceAnalysisOnly, setSwarmSourceAnalysisOnly,
    swarmDiscover, setSwarmDiscover,
    swarmCodeAudit, setSwarmCodeAudit,
    swarmSkipSast, setSwarmSkipSast,
    swarmDiff, setSwarmDiff,
    swarmLastCommits, setSwarmLastCommits,
    swarmTriage, setSwarmTriage,
    swarmOnlyPhase, setSwarmOnlyPhase,
    swarmSkipPhases, setSwarmSkipPhases,
    swarmStartFrom, setSwarmStartFrom,
    swarmShowPrompt, setSwarmShowPrompt,
    swarmArchon, setSwarmArchon,
    swarmIntensity, setSwarmIntensity,

    // Autopilot fields
    autopilotAgent, setAutopilotAgent,
    autopilotFocus, setAutopilotFocus,
    autopilotTimeout, setAutopilotTimeout,
    autopilotInstruction, setAutopilotInstruction,
    autopilotMaxCommands, setAutopilotMaxCommands,
    autopilotDryRun, setAutopilotDryRun,
    autopilotSource, setAutopilotSource,
    autopilotFiles, setAutopilotFiles,
    autopilotScanUuid, setAutopilotScanUuid,
    autopilotDiff, setAutopilotDiff,
    autopilotArchonMode, setAutopilotArchonMode,
    autopilotNoArchon, setAutopilotNoArchon,
    autopilotIntensity, setAutopilotIntensity,

    // Query fields
    scanMode, setScanMode,
    agentName, setAgentName,
    promptTemplate, setPromptTemplate,
    customPrompt, setCustomPrompt,
    repoPath, setRepoPath,
    queryFiles, setQueryFiles,
    append, setAppend,
    querySource, setQuerySource,
    queryScanUuid, setQueryScanUuid,
    queryInstruction, setQueryInstruction,
    querySourceLabel, setQuerySourceLabel,

    // Target input tab (prompt-based autopilot)
    targetInputTab, setTargetInputTab,
    targetPrompt, setTargetPrompt,
    targetRunId, targetRunStatus, targetError,
    startAutopilotRun, handleTargetSubmit,

    // Scan streaming
    scanOutput, scanResult, scanError,
    isScanStreaming, handleScanCancel,
    scanOutputRef,

    // Chat
    chatOpen, setChatOpen,
    messages, chatInput, setChatInput,
    isChatStreaming, handleChatSend, handleChatCancel, handleChatKeyDown,
    chatEndRef,

    // Upload
    uploadDragging, uploadCompressing, uploadFileInputRef, uploadRepo,
    handleFileUpload, onUploadDragEnter, onUploadDragLeave, onUploadDragOver, onUploadDrop,

    // Sessions
    expandedSessionUuid, setExpandedSessionUuid,
    sessionsData, sessionDetail,
  };
}
