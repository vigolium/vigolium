import { getBaseUrl, getProjectUUID } from '@/api/client';

export interface SSECallbacks {
  onChunk: (text: string) => void;
  onDone: (result: unknown) => void;
  onError: (error: Error) => void;
  onPhase?: (phase: string) => void;
}

export async function fetchSSE(
  path: string,
  body: Record<string, unknown>,
  callbacks: SSECallbacks,
  signal?: AbortSignal,
) {
  const base = getBaseUrl();
  const url = new URL(path, base).toString();

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'text/event-stream',
  };
  const projectUUID = getProjectUUID();
  if (projectUUID) headers['X-Project-UUID'] = projectUUID;

  let res: Response;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal,
    });
  } catch (err) {
    if ((err as Error).name === 'AbortError') return;
    callbacks.onError(err as Error);
    return;
  }

  if (!res.ok) {
    let msg = res.statusText;
    try {
      const errBody = await res.json();
      msg = errBody.error || msg;
    } catch { /* ignore */ }
    callbacks.onError(new Error(`${res.status}: ${msg}`));
    return;
  }

  const reader = res.body?.getReader();
  if (!reader) { callbacks.onError(new Error('No response body')); return; }

  const decoder = new TextDecoder();
  let buffer = '';
  let lastResult: unknown = null;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const payload = line.slice(6).trim();
        if (!payload || payload === '[DONE]') continue;
        try {
          const parsed = JSON.parse(payload);
          if (parsed.type === 'phase' && parsed.phase && callbacks.onPhase) {
            callbacks.onPhase(parsed.phase);
          }
          if (parsed.text) callbacks.onChunk(parsed.text);
          // OpenAI chat completions SSE delta format
          const deltaContent = parsed.choices?.[0]?.delta?.content;
          if (deltaContent) callbacks.onChunk(deltaContent);
          if (parsed.done || parsed.status === 'completed' || parsed.status === 'error') lastResult = parsed;
        } catch {
          callbacks.onChunk(payload);
        }
      }
    }
  } catch (err) {
    if ((err as Error).name === 'AbortError') return;
    callbacks.onError(err as Error);
    return;
  }

  callbacks.onDone(lastResult);
}
