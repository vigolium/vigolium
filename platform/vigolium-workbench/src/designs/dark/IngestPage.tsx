'use client';

import { useState } from 'react';
import { useIngestHttp } from '@/api/hooks';
import type { IngestRequest } from '@/api/types';
import PageShell from './PageShell';

const INPUT_MODES = [
  { value: 'url', label: 'URL' },
  { value: 'url_file', label: 'URL_FILE' },
  { value: 'curl', label: 'CURL' },
  { value: 'burp_base64', label: 'BURP_BASE64' },
  { value: 'openapi', label: 'OPENAPI' },
  { value: 'postman_collection', label: 'POSTMAN' },
];

export default function IngestPage() {
  const [inputMode, setInputMode] = useState('url');
  const [url, setUrl] = useState('');
  const [content, setContent] = useState('');
  const [contentBase64, setContentBase64] = useState('');
  const [httpRequestBase64, setHttpRequestBase64] = useState('');
  const [httpResponseBase64, setHttpResponseBase64] = useState('');
  const ingest = useIngestHttp();

  const handleSubmit = () => {
    const req: IngestRequest = { input_mode: inputMode };
    if (inputMode === 'url') req.url = url;
    else if (inputMode === 'burp_base64') {
      req.http_request_base64 = httpRequestBase64;
      req.http_response_base64 = httpResponseBase64;
    } else if (inputMode === 'url_file' || inputMode === 'curl' || inputMode === 'openapi' || inputMode === 'postman_collection') {
      req.content = content;
    }
    if (contentBase64) req.content_base64 = contentBase64;
    ingest.mutate(req);
  };

  const inputClass = "w-full bg-[#1c1b19] border border-[#2e2b26] text-[#fce8c3] text-xs px-2 py-1 focus:outline-none focus:border-[#7fd962]/50";
  const textareaClass = `${inputClass} font-mono resize-y`;

  return (
    <PageShell>
      <div className="border border-[#2e2b26] bg-[#1c1b19] overflow-hidden">
        <div className="px-3 py-1.5 border-b border-[#2e2b26]">
          <span className="text-[#7fd962] text-xs font-bold">INGEST_HTTP</span>
        </div>

        <div className="p-3 space-y-3">
          <div>
            <label className="text-[#918175] text-[10px] uppercase block mb-1">INPUT_MODE</label>
            <div className="flex gap-1 flex-wrap">
              {INPUT_MODES.map((mode) => (
                <button
                  key={mode.value}
                  onClick={() => setInputMode(mode.value)}
                  className={`px-2 py-0.5 text-xs border transition-colors ${
                    inputMode === mode.value
                      ? 'border-[#7fd962]/50 text-[#7fd962] bg-[#7fd962]/10'
                      : 'border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]'
                  }`}
                >
                  {mode.label}
                </button>
              ))}
            </div>
          </div>

          {inputMode === 'url' && (
            <div>
              <label className="text-[#918175] text-[10px] uppercase block mb-1">URL</label>
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com"
                className={inputClass}
              />
            </div>
          )}

          {(inputMode === 'url_file' || inputMode === 'curl' || inputMode === 'openapi' || inputMode === 'postman_collection') && (
            <div>
              <label className="text-[#918175] text-[10px] uppercase block mb-1">CONTENT</label>
              <textarea
                value={content}
                onChange={(e) => setContent(e.target.value)}
                rows={10}
                placeholder={
                  inputMode === 'url_file' ? 'https://example.com/page1\nhttps://example.com/page2' :
                  inputMode === 'curl' ? "curl -X GET 'https://example.com/api'" :
                  'Paste content here...'
                }
                className={textareaClass}
              />
            </div>
          )}

          {inputMode === 'burp_base64' && (
            <div className="space-y-2">
              <div>
                <label className="text-[#918175] text-[10px] uppercase block mb-1">HTTP_REQUEST_BASE64</label>
                <textarea
                  value={httpRequestBase64}
                  onChange={(e) => setHttpRequestBase64(e.target.value)}
                  rows={4}
                  placeholder="Base64-encoded HTTP request..."
                  className={textareaClass}
                />
              </div>
              <div>
                <label className="text-[#918175] text-[10px] uppercase block mb-1">HTTP_RESPONSE_BASE64</label>
                <textarea
                  value={httpResponseBase64}
                  onChange={(e) => setHttpResponseBase64(e.target.value)}
                  rows={4}
                  placeholder="Base64-encoded HTTP response..."
                  className={textareaClass}
                />
              </div>
            </div>
          )}

          <div>
            <label className="text-[#918175] text-[10px] uppercase block mb-1">CONTENT_BASE64 (optional)</label>
            <textarea
              value={contentBase64}
              onChange={(e) => setContentBase64(e.target.value)}
              rows={3}
              placeholder="Optional base64 content..."
              className={textareaClass}
            />
          </div>

          <button
            onClick={handleSubmit}
            disabled={ingest.isPending}
            className="text-xs px-4 py-1 border border-[#98bc37]/50 text-[#98bc37] hover:bg-[#98bc37]/10 disabled:opacity-50 transition-colors"
          >
            {ingest.isPending ? 'ingesting...' : '[SUBMIT]'}
          </button>

          {ingest.isSuccess && ingest.data && (
            <div className="border border-[#2e2b26] p-2 text-xs space-y-0.5">
              <div className="text-[#7fd962] font-bold">RESULT</div>
              <div><span className="text-[#918175]">imported:</span> <span className="text-[#fce8c3]">{ingest.data.imported}</span></div>
              <div><span className="text-[#918175]">skipped:</span> <span className="text-[#fce8c3]">{ingest.data.skipped}</span></div>
              <div><span className="text-[#918175]">errors:</span> <span className={ingest.data.errors > 0 ? 'text-[#ef2f27]' : 'text-[#fce8c3]'}>{ingest.data.errors}</span></div>
              <div><span className="text-[#918175]">message:</span> <span className="text-[#fce8c3]">{ingest.data.message}</span></div>
            </div>
          )}

          {ingest.isError && (
            <div className="text-xs text-[#ef2f27]">
              error: {(ingest.error as Error).message}
            </div>
          )}
        </div>
      </div>
    </PageShell>
  );
}
