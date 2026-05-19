'use client';

import { useEffect, useRef, useState } from 'react';
import { buildApiUrl, buildAuthHeaders } from '@/api/client';
import { isTerminalAgentStatus } from '@/api/types';

export interface AgentSessionLogsState {
  logs: string;
  isStreaming: boolean;
  error: string | null;
}

// Cap the in-memory log buffer so a long-running session can't blow up
// React state / the rendered <pre>. The slice keeps the most recent
// MAX_LOG_BYTES of output, which is what users want when tailing.
const MAX_LOG_BYTES = 512 * 1024;

function appendCapped(prev: string, text: string): string {
  const next = prev + text;
  return next.length > MAX_LOG_BYTES ? next.slice(-MAX_LOG_BYTES) : next;
}

export function useAgentSessionLogs(uuid: string | null, status?: string): AgentSessionLogsState {
  const [logs, setLogs] = useState('');
  const [isStreaming, setIsStreaming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const lastUuidRef = useRef<string | null>(null);

  // Boolean dep avoids reconnecting the SSE stream on every poll-induced
  // identity change of `status` (the parent useAgentSessionDetail polls
  // every 5s while running, replacing the response object each tick).
  const terminal = isTerminalAgentStatus(status);

  useEffect(() => {
    abortRef.current?.abort();
    abortRef.current = null;

    if (!uuid) {
      setLogs('');
      setIsStreaming(false);
      setError(null);
      lastUuidRef.current = null;
      return;
    }

    // Only blank the panel when switching to a different session. A
    // running→terminal transition reuses the same uuid, so keep what we
    // already have rendered until the terminal fetch fills it back in.
    if (uuid !== lastUuidRef.current) {
      setLogs('');
      lastUuidRef.current = uuid;
    }
    setError(null);

    const abort = new AbortController();
    abortRef.current = abort;
    const url = buildApiUrl(`/api/agent/sessions/${uuid}/logs?strip=1`);

    if (terminal) {
      setIsStreaming(false);
      (async () => {
        try {
          const res = await fetch(url, { headers: buildAuthHeaders(), signal: abort.signal });
          if (abort.signal.aborted) return;
          if (!res.ok) {
            let msg = res.statusText;
            try { const j = await res.json(); msg = j.error || msg; } catch { /* ignore */ }
            setError(`${res.status}: ${msg}`);
            return;
          }
          const text = await res.text();
          if (abort.signal.aborted) return;
          setLogs(text);
        } catch (err) {
          if ((err as Error).name !== 'AbortError') setError((err as Error).message);
        }
      })();
      return () => { abort.abort(); };
    }

    setIsStreaming(true);
    (async () => {
      try {
        const res = await fetch(url, { headers: buildAuthHeaders({ sse: true }), signal: abort.signal });
        if (!res.ok) {
          let msg = res.statusText;
          try { const j = await res.json(); msg = j.error || msg; } catch { /* ignore */ }
          setError(`${res.status}: ${msg}`);
          setIsStreaming(false);
          return;
        }
        const reader = res.body?.getReader();
        if (!reader) {
          setError('No response body');
          setIsStreaming(false);
          return;
        }
        const decoder = new TextDecoder();
        let buffer = '';
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';
          for (const line of lines) {
            if (!line.startsWith('data: ')) continue;
            const payload = line.slice(6).trim();
            if (!payload) continue;
            try {
              const parsed = JSON.parse(payload);
              if (parsed.type === 'chunk' && typeof parsed.text === 'string') {
                setLogs((prev) => appendCapped(prev, parsed.text));
              } else if (parsed.type === 'error' && typeof parsed.error === 'string') {
                setError(parsed.error);
              } else if (parsed.type === 'done') {
                setIsStreaming(false);
              }
            } catch {
              setLogs((prev) => appendCapped(prev, payload));
            }
          }
        }
        setIsStreaming(false);
      } catch (err) {
        if ((err as Error).name !== 'AbortError') {
          setError((err as Error).message);
          setIsStreaming(false);
        }
      }
    })();

    return () => { abort.abort(); };
  }, [uuid, terminal]);

  return { logs, isStreaming, error };
}
