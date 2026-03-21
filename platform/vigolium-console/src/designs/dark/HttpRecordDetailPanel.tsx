'use client';

import { useHttpRecord } from '@/api/hooks';
import { formatDate, formatBytes } from '@/lib/formatters';
import { METHOD_COLORS, STATUS_COLORS } from './theme';
import { Copy, Check, Filter } from 'lucide-react';
import { useState, useCallback } from 'react';

interface Props {
  uuid: string;
  onClose: () => void;
  onFilterHostname?: (hostname: string) => void;
}

function safeAtob(s: string): string {
  try {
    return atob(s);
  } catch {
    return s;
  }
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [text]);
  return (
    <button
      onClick={handleCopy}
      className="inline-flex items-center gap-1 px-1.5 py-0.5 border border-[#2e2b26] text-[#918175] hover:text-[#7fd962] hover:border-[#7fd962]/50 transition-colors text-xs"
      title={`Copy ${label}`}
    >
      {copied ? <Check className="w-3 h-3 text-[#7fd962]" /> : <Copy className="w-3 h-3" />}
      {copied ? 'copied' : label}
    </button>
  );
}

export default function HttpRecordDetailPanel({ uuid, onClose, onFilterHostname }: Props) {
  const { data: record, isLoading, isError } = useHttpRecord(uuid);

  return (
    <div className="border-l border-[#2e2b26] bg-[#1c1b19] h-full overflow-y-auto">
      <div className="px-3 py-1.5 border-b border-[#2e2b26] flex items-center justify-between sticky top-0 bg-[#1c1b19] z-10">
        <span className="text-[#7fd962] text-xs font-bold truncate mr-2">RECORD {uuid}</span>
        <button onClick={onClose} className="text-[#918175] hover:text-[#ef2f27] text-xs px-1 shrink-0">[x]</button>
      </div>

      {isLoading && (
        <div className="p-3 text-xs text-[#918175]">loading...</div>
      )}

      {isError && (
        <div className="p-3 text-xs text-[#ef2f27]">failed to load record</div>
      )}

      {record && (
        <div className="p-3 space-y-3 text-xs">
          {/* Method + Status */}
          <div className="flex gap-3 items-center">
            <span className="font-bold" style={{ color: METHOD_COLORS[record.method] || '#918175' }}>
              {record.method}
            </span>
            {record.status_code > 0 && (
              <span className="font-bold" style={{ color: STATUS_COLORS[`${Math.floor(record.status_code / 100)}xx`] || '#918175' }}>
                {record.status_code}
                {record.status_phrase && ` ${record.status_phrase}`}
              </span>
            )}
          </div>

          {/* URL + action buttons */}
          <div>
            <div className="flex items-center gap-1.5 mb-1">
              <span className="text-[#918175]">url:</span>
              <CopyButton text={record.url} label="url" />
              {onFilterHostname && (
                <button
                  onClick={() => onFilterHostname(record.hostname)}
                  className="inline-flex items-center gap-1 px-1.5 py-0.5 border border-[#2e2b26] text-[#918175] hover:text-[#68a8e4] hover:border-[#68a8e4]/50 transition-colors text-xs"
                  title="Filter by this hostname"
                >
                  <Filter className="w-3 h-3" />
                  filter host
                </button>
              )}
            </div>
            <span className="text-[#fce8c3] break-all">{record.url}</span>
          </div>

          {/* Connection, sizes & metadata */}
          <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-[#918175]">
            <div>scheme: <span className="text-[#fce8c3]">{record.scheme}</span></div>
            <div>host: <span className="text-[#fce8c3]">{record.hostname}:{record.port}</span></div>
            {record.ip && <div>ip: <span className="text-[#fce8c3]">{record.ip}</span></div>}
            <div>http_version: <span className="text-[#fce8c3]">{record.http_version}</span></div>
            <div>req_size: <span className="text-[#fce8c3]">{formatBytes(record.request_content_length)}</span></div>
            <div>res_size: <span className="text-[#fce8c3]">{formatBytes(record.response_content_length)}</span></div>
            {record.request_content_type && <div>req_ctype: <span className="text-[#fce8c3]">{record.request_content_type}</span></div>}
            {record.response_content_type && <div>res_ctype: <span className="text-[#fce8c3]">{record.response_content_type}</span></div>}
            <div>response_time: <span className="text-[#fce8c3]">{record.response_time_ms}ms</span></div>
            {record.source && <div>source: <span className="text-[#fce8c3]">{record.source}</span></div>}
            <div>risk_score: <span className="text-[#fce8c3]">{record.risk_score}</span></div>
            <div>sent_at: <span className="text-[#fce8c3]">{formatDate(record.sent_at)}</span></div>
          </div>

          {/* Parameters */}
          {record.parameters && record.parameters.length > 0 && (
            <div>
              <div className="text-[#918175] mb-0.5">parameters:</div>
              <div className="space-y-0.5">
                {record.parameters.map((p, i) => (
                  <div key={i} className="text-[#fce8c3]">
                    <span className="text-[#68a8e4]">{p.name}</span>
                    <span className="text-[#403d38]"> ({p.type})</span>
                    {p.value && <span> = {p.value}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Remarks */}
          {record.remarks && record.remarks.length > 0 && (
            <div className="flex items-center gap-1 flex-wrap">
              <span className="text-[#918175]">remarks:</span>
              {record.remarks.map((r, i) => (
                <span key={i} className="text-[#fce8c3] border border-[#2e2b26] px-1">{r}</span>
              ))}
            </div>
          )}

          {/* Raw Request */}
          {record.raw_request && (
            <div>
              <div className="flex items-center gap-1.5 mb-0.5">
                <span className="text-[#918175]">raw_request:</span>
                <CopyButton text={safeAtob(record.raw_request)} label="request" />
              </div>
              <pre className="bg-[#141310] border border-[#2e2b26] p-2 overflow-x-auto text-[#fce8c3] whitespace-pre-wrap break-all max-h-64 overflow-y-auto">
                {safeAtob(record.raw_request)}
              </pre>
            </div>
          )}

          {/* Raw Response */}
          {record.raw_response && (
            <div>
              <div className="flex items-center gap-1.5 mb-0.5">
                <span className="text-[#918175]">raw_response:</span>
                <CopyButton text={safeAtob(record.raw_response)} label="response" />
              </div>
              <pre className="bg-[#141310] border border-[#2e2b26] p-2 overflow-x-auto text-[#fce8c3] whitespace-pre-wrap break-all">
                {safeAtob(record.raw_response)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
