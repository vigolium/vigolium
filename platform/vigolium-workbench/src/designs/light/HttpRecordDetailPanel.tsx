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
      className="inline-flex items-center gap-1 px-1.5 py-0.5 border border-[#bbc3c4] text-[#708e8e] hover:text-[#0078c8] hover:border-[#0078c8]/50 transition-colors text-xs"
      title={`Copy ${label}`}
    >
      {copied ? <Check className="w-3 h-3 text-[#00b368]" /> : <Copy className="w-3 h-3" />}
      {copied ? 'copied' : label}
    </button>
  );
}

export default function HttpRecordDetailPanel({ uuid, onClose, onFilterHostname }: Props) {
  const { data: record, isLoading, isError } = useHttpRecord(uuid);

  return (
    <div className="border-l border-[#bbc3c4] bg-[#f6edda] h-full overflow-y-auto">
      <div className="px-3 py-1.5 border-b border-[#bbc3c4] flex items-center justify-between sticky top-0 bg-[#f6edda] z-10">
        <span className="text-[#0078c8] text-xs font-bold truncate mr-2">RECORD {uuid}</span>
        <button onClick={onClose} className="text-[#708e8e] hover:text-[#e34e1c] text-xs px-1 shrink-0">[x]</button>
      </div>

      {isLoading && (
        <div className="p-3 text-xs text-[#708e8e]">loading...</div>
      )}

      {isError && (
        <div className="p-3 text-xs text-[#e34e1c]">failed to load record</div>
      )}

      {record && (
        <div className="p-3 space-y-3 text-xs">
          {/* Method + Status */}
          <div className="flex gap-3 items-center">
            <span className="font-bold" style={{ color: METHOD_COLORS[record.method] || '#708e8e' }}>
              {record.method}
            </span>
            {record.status_code > 0 && (
              <span className="font-bold" style={{ color: STATUS_COLORS[`${Math.floor(record.status_code / 100)}xx`] || '#708e8e' }}>
                {record.status_code}
                {record.status_phrase && ` ${record.status_phrase}`}
              </span>
            )}
          </div>

          {/* URL + action buttons */}
          <div>
            <div className="flex items-center gap-1.5 mb-1">
              <span className="text-[#708e8e]">url:</span>
              <CopyButton text={record.url} label="url" />
              {onFilterHostname && (
                <button
                  onClick={() => onFilterHostname(record.hostname)}
                  className="inline-flex items-center gap-1 px-1.5 py-0.5 border border-[#bbc3c4] text-[#708e8e] hover:text-[#0078c8] hover:border-[#0078c8]/50 transition-colors text-xs"
                  title="Filter by this hostname"
                >
                  <Filter className="w-3 h-3" />
                  filter host
                </button>
              )}
            </div>
            <span className="text-[#005661] break-all">{record.url}</span>
          </div>

          {/* Connection, sizes & metadata */}
          <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-[#708e8e]">
            <div>scheme: <span className="text-[#005661]">{record.scheme}</span></div>
            <div>host: <span className="text-[#005661]">{record.hostname}:{record.port}</span></div>
            {record.ip && <div>ip: <span className="text-[#005661]">{record.ip}</span></div>}
            <div>http_version: <span className="text-[#005661]">{record.http_version}</span></div>
            <div>req_size: <span className="text-[#005661]">{formatBytes(record.request_content_length)}</span></div>
            <div>res_size: <span className="text-[#005661]">{formatBytes(record.response_content_length)}</span></div>
            {record.request_content_type && <div>req_ctype: <span className="text-[#005661]">{record.request_content_type}</span></div>}
            {record.response_content_type && <div>res_ctype: <span className="text-[#005661]">{record.response_content_type}</span></div>}
            <div>response_time: <span className="text-[#005661]">{record.response_time_ms}ms</span></div>
            {record.source && <div>source: <span className="text-[#005661]">{record.source}</span></div>}
            <div>risk_score: <span className="text-[#005661]">{record.risk_score}</span></div>
            <div>sent_at: <span className="text-[#005661]">{formatDate(record.sent_at)}</span></div>
          </div>

          {/* Parameters */}
          {record.parameters && record.parameters.length > 0 && (
            <div>
              <div className="text-[#708e8e] mb-0.5">parameters:</div>
              <div className="space-y-0.5">
                {record.parameters.map((p, i) => (
                  <div key={i} className="text-[#005661]">
                    <span className="text-[#0078c8]">{p.name}</span>
                    <span className="text-[#bbc3c4]"> ({p.type})</span>
                    {p.value && <span> = {p.value}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Remarks */}
          {record.remarks && record.remarks.length > 0 && (
            <div className="flex items-center gap-1 flex-wrap">
              <span className="text-[#708e8e]">remarks:</span>
              {record.remarks.map((r, i) => (
                <span key={i} className="text-[#005661] border border-[#bbc3c4] px-1">{r}</span>
              ))}
            </div>
          )}

          {/* Raw Request */}
          {record.raw_request && (
            <div>
              <div className="flex items-center gap-1.5 mb-0.5">
                <span className="text-[#708e8e]">raw_request:</span>
                <CopyButton text={safeAtob(record.raw_request)} label="request" />
              </div>
              <pre className="bg-[#ede4d1] border border-[#bbc3c4] p-2 overflow-x-auto text-[#005661] whitespace-pre-wrap break-all max-h-64 overflow-y-auto">
                {safeAtob(record.raw_request)}
              </pre>
            </div>
          )}

          {/* Raw Response */}
          {record.raw_response && (
            <div>
              <div className="flex items-center gap-1.5 mb-0.5">
                <span className="text-[#708e8e]">raw_response:</span>
                <CopyButton text={safeAtob(record.raw_response)} label="response" />
              </div>
              <pre className="bg-[#ede4d1] border border-[#bbc3c4] p-2 overflow-x-auto text-[#005661] whitespace-pre-wrap break-all">
                {safeAtob(record.raw_response)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
