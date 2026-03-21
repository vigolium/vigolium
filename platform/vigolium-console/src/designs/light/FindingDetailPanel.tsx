'use client';

import { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import Prism from 'prismjs';
import 'prismjs/components/prism-markdown';
import { Eye, Code, Copy, Check, Link } from 'lucide-react';
import { useFinding } from '@/api/hooks';
import { formatDate } from '@/lib/formatters';
import { SEVERITY_COLORS, CONFIDENCE_COLORS } from './theme';

const mdTokenStyles: Record<string, React.CSSProperties> = {
  title: { color: '#0078c8', fontWeight: 'bold' },
  bold: { color: '#005661', fontWeight: 'bold' },
  italic: { color: '#005661', fontStyle: 'italic' },
  strike: { color: '#708e8e', textDecoration: 'line-through' },
  punctuation: { color: '#708e8e' },
  'code-snippet': { color: '#7d2a00' },
  code: { color: '#7d2a00' },
  url: { color: '#0078c8' },
  'url-reference': { color: '#0078c8' },
  blockquote: { color: '#708e8e' },
  'hr': { color: '#708e8e' },
  list: { color: '#b58900' },
  'table-header': { color: '#0078c8', fontWeight: 'bold' },
  'table-data-rows': { color: '#005661' },
  'table-line': { color: '#708e8e' },
  important: { color: '#e34e1c', fontWeight: 'bold' },
};

function highlightMarkdown(code: string): string {
  const html = Prism.highlight(code, Prism.languages.markdown, 'markdown');
  let styled = html;
  for (const [token, style] of Object.entries(mdTokenStyles)) {
    const styleStr = Object.entries(style)
      .map(([k, v]) => `${k.replace(/([A-Z])/g, '-$1').toLowerCase()}:${v}`)
      .join(';');
    styled = styled.replace(
      new RegExp(`class="token ${token}"`, 'g'),
      `style="${styleStr}"`
    );
  }
  return styled;
}

interface Props {
  findingId: number;
  onClose: () => void;
}

export default function FindingDetailPanel({ findingId, onClose }: Props) {
  const { data: finding, isLoading, isError } = useFinding(findingId);
  const [descTab, setDescTab] = useState<'rendered' | 'raw'>('rendered');
  const [copied, setCopied] = useState(false);
  const [linkCopied, setLinkCopied] = useState(false);
  const [copiedExtracted, setCopiedExtracted] = useState(false);
  const [copiedRequest, setCopiedRequest] = useState(false);
  const [copiedResponse, setCopiedResponse] = useState(false);
  const [evidenceTab, setEvidenceTab] = useState(0);
  const [copiedEvidence, setCopiedEvidence] = useState(false);
  const [matchedAtExpanded, setMatchedAtExpanded] = useState(false);
  const [evidenceExpanded, setEvidenceExpanded] = useState(false);

  return (
    <div className="border-l border-[#bbc3c4] bg-[#f6edda] h-full overflow-y-auto">
      <div className="px-3 py-1.5 border-b border-[#bbc3c4] flex items-center justify-between sticky top-0 bg-[#f6edda] z-10">
        <span className="text-[#0078c8] text-xs font-bold">FINDING #{findingId}</span>
        <div className="flex items-center gap-1">
          <button
            onClick={() => { navigator.clipboard.writeText(window.location.href); setLinkCopied(true); setTimeout(() => setLinkCopied(false), 2000); }}
            className="text-[#708e8e] hover:text-[#0078c8] text-xs px-1"
            title="Copy link"
          >
            {linkCopied ? <Check className="w-3 h-3" /> : <Link className="w-3 h-3" />}
          </button>
          <button onClick={onClose} className="text-[#708e8e] hover:text-[#e34e1c] text-xs px-1">[x]</button>
        </div>
      </div>

      {isLoading && (
        <div className="p-3 text-xs text-[#708e8e]">loading...</div>
      )}

      {isError && (
        <div className="p-3 text-xs text-[#e34e1c]">failed to load finding</div>
      )}

      {finding && (
        <div className="p-3 space-y-3 text-xs">
          {/* Severity + Confidence + Type + Source */}
          <div className="flex flex-wrap gap-x-3 gap-y-0.5">
            <div>
              <span className="text-[#708e8e]">severity: </span>
              <span className="font-bold uppercase" style={{ color: SEVERITY_COLORS[finding.severity] || '#708e8e' }}>
                {finding.severity}
              </span>
            </div>
            <div>
              <span className="text-[#708e8e]">confidence: </span>
              <span style={{ color: CONFIDENCE_COLORS[finding.confidence] || '#708e8e' }}>
                {finding.confidence}
              </span>
            </div>
            {finding.module_type && (
              <div><span className="text-[#708e8e]">type: </span><span className="text-[#0078c8]">{finding.module_type}</span></div>
            )}
            {finding.finding_source && (
              <div><span className="text-[#708e8e]">source: </span><span className="text-[#005661] font-semibold">{finding.finding_source}</span></div>
            )}
          </div>

          {/* Module */}
          <div>
            <span className="text-[#708e8e]">module: </span>
            <span className="text-[#005661]">{finding.module_name}</span>
            <span className="text-[#bbc3c4]"> ({finding.module_id})</span>
          </div>

          {/* Module short description */}
          {finding.module_short && (
            <div>
              <span className="text-[#708e8e]">module_short: </span>
              <span className="text-[#708e8e] italic">{finding.module_short}</span>
            </div>
          )}

          {/* Description */}
          {finding.description && (
            <div>
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-[#708e8e]">description:</span>
                <div className="flex gap-0.5">
                  <button
                    onClick={() => setDescTab('rendered')}
                    className={`px-1.5 py-0.5 text-[10px] border ${descTab === 'rendered' ? 'border-[#0078c8] text-[#0078c8] bg-[#ede4d1]' : 'border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]'}`}
                  >
                    <Eye size={10} className="inline-block mr-0.5 -mt-px" />rendered
                  </button>
                  <button
                    onClick={() => setDescTab('raw')}
                    className={`px-1.5 py-0.5 text-[10px] border ${descTab === 'raw' ? 'border-[#0078c8] text-[#0078c8] bg-[#ede4d1]' : 'border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]'}`}
                  >
                    <Code size={10} className="inline-block mr-0.5 -mt-px" />raw
                  </button>
                  <button
                    onClick={() => { navigator.clipboard.writeText(finding.description!); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
                    className="px-1.5 py-0.5 text-[10px] border border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]"
                  >
                    {copied ? <><Check size={10} className="inline-block mr-0.5 -mt-px" />copied!</> : <><Copy size={10} className="inline-block mr-0.5 -mt-px" />copy</>}
                  </button>
                </div>
              </div>
              {descTab === 'rendered' ? (
                <div className="bg-[#ede4d1] border border-[#bbc3c4] p-2 overflow-x-auto max-h-64 overflow-y-auto text-[#005661] [&_p]:mb-1.5 [&_p]:leading-relaxed [&_h1]:text-sm [&_h1]:font-bold [&_h1]:text-[#005661] [&_h1]:mb-1.5 [&_h1]:mt-2 [&_h2]:text-xs [&_h2]:font-bold [&_h2]:text-[#005661] [&_h2]:mb-1 [&_h2]:mt-2 [&_h3]:text-xs [&_h3]:font-semibold [&_h3]:text-[#005661] [&_h3]:mb-1 [&_h3]:mt-1.5 [&_ul]:list-disc [&_ul]:pl-4 [&_ul]:mb-1.5 [&_ol]:list-decimal [&_ol]:pl-4 [&_ol]:mb-1.5 [&_li]:mb-0.5 [&_li]:leading-relaxed [&_a]:text-[#0078c8] [&_a]:underline [&_strong]:font-bold [&_strong]:text-[#005661] [&_em]:italic [&_code]:text-[#7d2a00] [&_code]:bg-[#e0d7c4] [&_code]:px-1 [&_code]:py-0.5 [&_code]:rounded-sm [&_pre]:bg-[#e0d7c4] [&_pre]:p-2 [&_pre]:rounded [&_pre]:overflow-x-auto [&_pre]:mb-1.5 [&_pre_code]:bg-transparent [&_pre_code]:p-0 [&_blockquote]:border-l-2 [&_blockquote]:border-[#708e8e] [&_blockquote]:pl-2 [&_blockquote]:text-[#708e8e] [&_blockquote]:mb-1.5 [&_hr]:border-[#bbc3c4] [&_hr]:my-2 [&_table]:w-full [&_table]:mb-1.5 [&_th]:border [&_th]:border-[#bbc3c4] [&_th]:px-1.5 [&_th]:py-0.5 [&_th]:text-left [&_td]:border [&_td]:border-[#bbc3c4] [&_td]:px-1.5 [&_td]:py-0.5">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{finding.description}</ReactMarkdown>
                </div>
              ) : (
                <pre
                  className="bg-[#ede4d1] border border-[#bbc3c4] p-2 overflow-x-auto text-[#005661] whitespace-pre-wrap break-all max-h-64 overflow-y-auto"
                  dangerouslySetInnerHTML={{ __html: highlightMarkdown(finding.description) }}
                />
              )}
            </div>
          )}

          {/* Tags */}
          {finding.tags && finding.tags.length > 0 && (
            <div>
              <span className="text-[#708e8e]">tags: </span>
              <span className="flex gap-1 flex-wrap mt-0.5">
                {finding.tags.map((tag) => (
                  <span key={tag} className="px-1.5 py-0.5 border border-[#bbc3c4] text-[#0078c8]">{tag}</span>
                ))}
              </span>
            </div>
          )}

          {/* Matched at */}
          {finding.matched_at && finding.matched_at.length > 0 && (() => {
            const MATCHED_AT_LIMIT = 20;
            const items = finding.matched_at!;
            const needsCollapse = items.length > MATCHED_AT_LIMIT;
            const visible = needsCollapse && !matchedAtExpanded ? items.slice(0, MATCHED_AT_LIMIT) : items;
            return (
              <div>
                <div className="text-[#708e8e] mb-0.5">matched_at: <span className="text-[#bbc3c4]">({items.length})</span></div>
                <ul className="space-y-0.5 text-[#005661]">
                  {visible.map((m, i) => (
                    <li key={i} className="break-all">{m}</li>
                  ))}
                </ul>
                {needsCollapse && (
                  <button
                    onClick={() => setMatchedAtExpanded((v) => !v)}
                    className="text-[#0078c8] hover:underline text-[10px] mt-1"
                  >
                    {matchedAtExpanded ? `[collapse to ${MATCHED_AT_LIMIT}]` : `[show all ${items.length}]`}
                  </button>
                )}
              </div>
            );
          })()}

          {/* Extracted results */}
          {finding.extracted_results && finding.extracted_results.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-[#708e8e]">extracted_results:</span>
                <button
                  onClick={() => { navigator.clipboard.writeText(finding.extracted_results!.join('\n')); setCopiedExtracted(true); setTimeout(() => setCopiedExtracted(false), 1500); }}
                  className="px-1.5 py-0.5 text-[10px] border border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]"
                >
                  {copiedExtracted ? <><Check size={10} className="inline-block mr-0.5 -mt-px" />copied!</> : <><Copy size={10} className="inline-block mr-0.5 -mt-px" />copy</>}
                </button>
              </div>
              <pre className="bg-[#ede4d1] border border-[#bbc3c4] p-2 overflow-x-auto text-[#005661] whitespace-pre-wrap break-all max-h-32 overflow-y-auto">
                {finding.extracted_results.join('\n')}
              </pre>
            </div>
          )}

          {/* Metadata */}
          <div className="space-y-0.5 text-[#708e8e]">
            {finding.scan_uuid && <div>scan_id: <span className="text-[#005661]">{finding.scan_uuid}</span></div>}
            <div>finding_hash: <span className="text-[#005661] break-all">{finding.finding_hash}</span></div>
            <div>found_at: <span className="text-[#005661]">{formatDate(finding.found_at)}</span></div>
          </div>

          {/* HTTP Record UUIDs */}
          {finding.http_record_uuids && finding.http_record_uuids.length > 0 && (
            <div>
              <div className="text-[#708e8e] mb-0.5">http_records:</div>
              <ul className="space-y-0.5">
                {finding.http_record_uuids.map((uuid) => (
                  <li key={uuid} className="text-[#0078c8] break-all">{uuid}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Raw Request */}
          {finding.request && (
            <div>
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-[#708e8e]">request:</span>
                <button
                  onClick={() => { navigator.clipboard.writeText(finding.request!); setCopiedRequest(true); setTimeout(() => setCopiedRequest(false), 1500); }}
                  className="px-1.5 py-0.5 text-[10px] border border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]"
                >
                  {copiedRequest ? <><Check size={10} className="inline-block mr-0.5 -mt-px" />copied!</> : <><Copy size={10} className="inline-block mr-0.5 -mt-px" />copy</>}
                </button>
              </div>
              <pre className="bg-[#ede4d1] border border-[#bbc3c4] p-2 overflow-x-auto text-[#005661] whitespace-pre-wrap break-all max-h-64 overflow-y-auto">
                {finding.request}
              </pre>
            </div>
          )}

          {/* Raw Response */}
          {finding.response && (
            <div>
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-[#708e8e]">response:</span>
                <button
                  onClick={() => { navigator.clipboard.writeText(finding.response!); setCopiedResponse(true); setTimeout(() => setCopiedResponse(false), 1500); }}
                  className="px-1.5 py-0.5 text-[10px] border border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]"
                >
                  {copiedResponse ? <><Check size={10} className="inline-block mr-0.5 -mt-px" />copied!</> : <><Copy size={10} className="inline-block mr-0.5 -mt-px" />copy</>}
                </button>
              </div>
              <pre className="bg-[#ede4d1] border border-[#bbc3c4] p-2 overflow-x-auto text-[#005661] whitespace-pre-wrap break-all max-h-64 overflow-y-auto">
                {finding.response}
              </pre>
            </div>
          )}

          {/* Additional Evidence */}
          {finding.additional_evidence && finding.additional_evidence.length > 0 && (() => {
            const EVIDENCE_LIMIT = 20;
            const allItems = finding.additional_evidence!;
            const needsCollapse = allItems.length > EVIDENCE_LIMIT;
            const visibleItems = needsCollapse && !evidenceExpanded ? allItems.slice(0, EVIDENCE_LIMIT) : allItems;
            const evidence = allItems[evidenceTab] || allItems[0];
            const parts = evidence.split('\n---------\n');
            const reqPart = parts[0] || '';
            const resPart = parts[1] || '';
            return (
              <div>
                <div className="flex items-start gap-2 mb-0.5">
                  <span className="text-[#708e8e] shrink-0 pt-0.5">additional_evidence: <span className="text-[#bbc3c4]">({allItems.length})</span></span>
                  <div className="flex flex-wrap gap-0.5">
                    {visibleItems.map((_, i) => (
                      <button
                        key={i}
                        onClick={() => setEvidenceTab(i)}
                        className={`px-1.5 py-0.5 text-[10px] border ${evidenceTab === i ? 'border-[#0078c8] text-[#0078c8] bg-[#ede4d1]' : 'border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]'}`}
                      >
                        #{i + 1}
                      </button>
                    ))}
                    {needsCollapse && (
                      <button
                        onClick={() => { setEvidenceExpanded((v) => !v); if (evidenceExpanded && evidenceTab >= EVIDENCE_LIMIT) setEvidenceTab(0); }}
                        className="px-1.5 py-0.5 text-[10px] border border-[#bbc3c4] text-[#0078c8] hover:underline"
                      >
                        {evidenceExpanded ? `[collapse to ${EVIDENCE_LIMIT}]` : `[show all ${allItems.length}]`}
                      </button>
                    )}
                    <button
                      onClick={() => { navigator.clipboard.writeText(evidence); setCopiedEvidence(true); setTimeout(() => setCopiedEvidence(false), 1500); }}
                      className="px-1.5 py-0.5 text-[10px] border border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]"
                    >
                      {copiedEvidence ? <><Check size={10} className="inline-block mr-0.5 -mt-px" />copied!</> : <><Copy size={10} className="inline-block mr-0.5 -mt-px" />copy</>}
                    </button>
                  </div>
                </div>
                <div className="border border-[#bbc3c4] bg-[#ede4d1] overflow-hidden min-h-80">
                  {reqPart && (
                    <pre className="p-2 text-[#005661] whitespace-pre-wrap break-all max-h-64 overflow-y-auto">{reqPart}</pre>
                  )}
                  {resPart && (
                    <>
                      <div className="border-t border-dashed border-[#bbc3c4] mx-2" />
                      <pre className="p-2 text-[#005661] whitespace-pre-wrap break-all max-h-64 overflow-y-auto">{resPart}</pre>
                    </>
                  )}
                </div>
              </div>
            );
          })()}
        </div>
      )}
    </div>
  );
}
