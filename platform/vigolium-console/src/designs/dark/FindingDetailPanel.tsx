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
  title: { color: '#ff9e64', fontWeight: 'bold' },
  bold: { color: '#e0af68', fontWeight: 'bold' },
  italic: { color: '#bb9af7', fontStyle: 'italic' },
  strike: { color: '#565f89', textDecoration: 'line-through' },
  punctuation: { color: '#f7768e' },
  'code-snippet': { color: '#9ece6a', backgroundColor: '#1a1b26', padding: '1px 4px', borderRadius: '2px' },
  code: { color: '#9ece6a', backgroundColor: '#1a1b26', padding: '1px 4px', borderRadius: '2px' },
  url: { color: '#7dcfff', textDecoration: 'underline' },
  'url-reference': { color: '#7dcfff' },
  blockquote: { color: '#73daca' },
  'hr': { color: '#565f89' },
  list: { color: '#ff9e64' },
  'table-header': { color: '#7aa2f7', fontWeight: 'bold' },
  'table-data-rows': { color: '#c0caf5' },
  'table-line': { color: '#565f89' },
  important: { color: '#f7768e', fontWeight: 'bold' },
};

function highlightMarkdown(code: string): string {
  // First pass: apply Prism token styles
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
  // Second pass: highlight inline code (`...`) and fenced code blocks (```...```) that Prism markdown grammar doesn't fully tokenize
  // Fenced code blocks: ```lang\n...\n```
  styled = styled.replace(
    /(```\w*\n)([\s\S]*?)(```)/g,
    '<span style="color:#f7768e">$1</span><span style="color:#9ece6a;background:#1a1b26;padding:2px 0;display:inline">$2</span><span style="color:#f7768e">$3</span>'
  );
  // Inline code: `...`  (not already inside a styled span)
  styled = styled.replace(
    /(?<!<[^>]*)(`)((?:(?!`).)+)(`)/g,
    '<span style="color:#f7768e">$1</span><span style="color:#9ece6a;background:#1a1b26;padding:1px 4px;border-radius:2px">$2</span><span style="color:#f7768e">$3</span>'
  );
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
    <div className="border-l border-[#2e2b26] bg-[#1c1b19] h-full overflow-y-auto">
      <div className="px-3 py-1.5 border-b border-[#2e2b26] flex items-center justify-between sticky top-0 bg-[#1c1b19] z-10">
        <span className="text-[#7fd962] text-xs font-bold">FINDING #{findingId}</span>
        <div className="flex items-center gap-1">
          <button
            onClick={() => { navigator.clipboard.writeText(window.location.href); setLinkCopied(true); setTimeout(() => setLinkCopied(false), 2000); }}
            className="text-[#918175] hover:text-[#68a8e4] text-xs px-1"
            title="Copy link"
          >
            {linkCopied ? <Check className="w-3 h-3" /> : <Link className="w-3 h-3" />}
          </button>
          <button onClick={onClose} className="text-[#918175] hover:text-[#ef2f27] text-xs px-1">[x]</button>
        </div>
      </div>

      {isLoading && (
        <div className="p-3 text-xs text-[#918175]">loading...</div>
      )}

      {isError && (
        <div className="p-3 text-xs text-[#ef2f27]">failed to load finding</div>
      )}

      {finding && (
        <div className="p-3 space-y-3 text-xs">
          {/* Severity + Confidence + Type + Source */}
          <div className="flex flex-wrap gap-x-3 gap-y-0.5">
            <div>
              <span className="text-[#918175]">severity: </span>
              <span className="font-bold uppercase" style={{ color: SEVERITY_COLORS[finding.severity] || '#918175' }}>
                {finding.severity}
              </span>
            </div>
            <div>
              <span className="text-[#918175]">confidence: </span>
              <span style={{ color: CONFIDENCE_COLORS[finding.confidence] || '#918175' }}>
                {finding.confidence}
              </span>
            </div>
            {finding.module_type && (
              <div><span className="text-[#918175]">type: </span><span className="text-[#68a8e4]">{finding.module_type}</span></div>
            )}
            {finding.finding_source && (
              <div><span className="text-[#918175]">source: </span><span className="text-[#2be4d0]">{finding.finding_source}</span></div>
            )}
          </div>

          {/* Module */}
          <div className="text-[#fce8c3] [&_code]:text-[#98bc37] [&_code]:bg-[#0e0d0b] [&_code]:px-1 [&_code]:py-0.5 [&_code]:rounded-sm [&_p]:inline">
            <span className="text-[#918175]">module: </span>
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{finding.module_name}</ReactMarkdown>
            <span className="text-[#403d38]"> ({finding.module_id})</span>
          </div>

          {/* Module short description */}
          {finding.module_short && (
            <div className="text-[#918175] italic [&_code]:text-[#98bc37] [&_code]:bg-[#0e0d0b] [&_code]:px-1 [&_code]:py-0.5 [&_code]:rounded-sm [&_code]:not-italic [&_p]:inline">
              <span>module_short: </span>
              <ReactMarkdown remarkPlugins={[remarkGfm]}>{finding.module_short}</ReactMarkdown>
            </div>
          )}

          {/* Tags + Matched at + Metadata — compact block */}
          <div className="space-y-0.5">
            {finding.tags && finding.tags.length > 0 && (
              <div className="flex flex-wrap items-center gap-1">
                <span className="text-[#918175]">tags:</span>
                {finding.tags.map((tag) => (
                  <span key={tag} className="px-1 py-px border border-[#2e2b26] text-[#68a8e4] text-[10px]">{tag}</span>
                ))}
              </div>
            )}
            {finding.matched_at && finding.matched_at.length > 0 && (() => {
              const MATCHED_AT_LIMIT = 20;
              const items = finding.matched_at!;
              const needsCollapse = items.length > MATCHED_AT_LIMIT;
              const visible = needsCollapse && !matchedAtExpanded ? items.slice(0, MATCHED_AT_LIMIT) : items;
              return (
                <div className="flex flex-wrap items-baseline gap-x-1">
                  <span className="text-[#918175]">matched_at: <span className="text-[#403d38]">({items.length})</span></span>
                  <span className="text-[#fce8c3] break-all">{visible.join(', ')}</span>
                  {needsCollapse && (
                    <button
                      onClick={() => setMatchedAtExpanded((v) => !v)}
                      className="text-[#68a8e4] hover:underline text-[10px]"
                    >
                      {matchedAtExpanded ? `[collapse]` : `[+${items.length - MATCHED_AT_LIMIT} more]`}
                    </button>
                  )}
                </div>
              );
            })()}
            <div className="flex flex-wrap gap-x-3 text-[#918175]">
              <span>finding_hash: <span className="text-[#fce8c3] break-all">{finding.finding_hash}</span></span>
              <span>found_at: <span className="text-[#fce8c3]">{formatDate(finding.found_at)}</span></span>
              {finding.scan_uuid && <span>scan_id: <span className="text-[#fce8c3]">{finding.scan_uuid}</span></span>}
            </div>
          </div>

          {/* Description */}
          {finding.description && (
            <div>
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-[#918175]">description:</span>
                <div className="flex gap-0.5">
                  <button
                    onClick={() => setDescTab('rendered')}
                    className={`px-1.5 py-0.5 text-[10px] border ${descTab === 'rendered' ? 'border-[#7fd962] text-[#7fd962] bg-[#141310]' : 'border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]'}`}
                  >
                    <Eye size={10} className="inline-block mr-0.5 -mt-px" />rendered
                  </button>
                  <button
                    onClick={() => setDescTab('raw')}
                    className={`px-1.5 py-0.5 text-[10px] border ${descTab === 'raw' ? 'border-[#7fd962] text-[#7fd962] bg-[#141310]' : 'border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]'}`}
                  >
                    <Code size={10} className="inline-block mr-0.5 -mt-px" />raw
                  </button>
                  <button
                    onClick={() => { navigator.clipboard.writeText(finding.description!); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
                    className="px-1.5 py-0.5 text-[10px] border border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]"
                  >
                    {copied ? <><Check size={10} className="inline-block mr-0.5 -mt-px" />copied!</> : <><Copy size={10} className="inline-block mr-0.5 -mt-px" />copy</>}
                  </button>
                </div>
              </div>
              {descTab === 'rendered' ? (
                <div className={`bg-[#141310] border border-[#2e2b26] p-2 overflow-x-auto overflow-y-auto text-[#fce8c3] ${finding.module_type === 'whitebox' ? 'max-h-[600px]' : 'max-h-64'} [&_p]:mb-1.5 [&_p]:leading-relaxed [&_h1]:text-sm [&_h1]:font-bold [&_h1]:text-[#fce8c3] [&_h1]:mb-1.5 [&_h1]:mt-2 [&_h2]:text-xs [&_h2]:font-bold [&_h2]:text-[#fce8c3] [&_h2]:mb-1 [&_h2]:mt-2 [&_h3]:text-xs [&_h3]:font-semibold [&_h3]:text-[#fce8c3] [&_h3]:mb-1 [&_h3]:mt-1.5 [&_ul]:list-disc [&_ul]:pl-4 [&_ul]:mb-1.5 [&_ol]:list-decimal [&_ol]:pl-4 [&_ol]:mb-1.5 [&_li]:mb-0.5 [&_li]:leading-relaxed [&_a]:text-[#68a8e4] [&_a]:underline [&_strong]:font-bold [&_strong]:text-[#fce8c3] [&_em]:italic [&_code]:text-[#98bc37] [&_code]:bg-[#0e0d0b] [&_code]:px-1 [&_code]:py-0.5 [&_code]:rounded-sm [&_pre]:bg-[#0e0d0b] [&_pre]:p-2 [&_pre]:rounded [&_pre]:overflow-x-auto [&_pre]:mb-1.5 [&_pre_code]:bg-transparent [&_pre_code]:p-0 [&_blockquote]:border-l-2 [&_blockquote]:border-[#918175] [&_blockquote]:pl-2 [&_blockquote]:text-[#918175] [&_blockquote]:mb-1.5 [&_hr]:border-[#2e2b26] [&_hr]:my-2 [&_table]:w-full [&_table]:mb-1.5 [&_th]:border [&_th]:border-[#2e2b26] [&_th]:px-1.5 [&_th]:py-0.5 [&_th]:text-left [&_td]:border [&_td]:border-[#2e2b26] [&_td]:px-1.5 [&_td]:py-0.5`}>
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{finding.description}</ReactMarkdown>
                </div>
              ) : (
                <pre
                  className={`bg-[#141310] border border-[#2e2b26] p-2 overflow-x-auto text-[#fce8c3] whitespace-pre-wrap break-all overflow-y-auto ${finding.module_type === 'whitebox' ? 'max-h-[600px]' : 'max-h-64'}`}
                  dangerouslySetInnerHTML={{ __html: highlightMarkdown(finding.description) }}
                />
              )}
            </div>
          )}

          {/* Extracted results */}
          {finding.extracted_results && finding.extracted_results.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-[#918175]">extracted_results:</span>
                <button
                  onClick={() => { navigator.clipboard.writeText(finding.extracted_results!.join('\n')); setCopiedExtracted(true); setTimeout(() => setCopiedExtracted(false), 1500); }}
                  className="px-1.5 py-0.5 text-[10px] border border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]"
                >
                  {copiedExtracted ? <><Check size={10} className="inline-block mr-0.5 -mt-px" />copied!</> : <><Copy size={10} className="inline-block mr-0.5 -mt-px" />copy</>}
                </button>
              </div>
              <pre className="bg-[#141310] border border-[#2e2b26] p-2 overflow-x-auto text-[#fce8c3] whitespace-pre-wrap break-all max-h-32 overflow-y-auto">
                {finding.extracted_results.join('\n')}
              </pre>
            </div>
          )}

          {/* HTTP Record UUIDs */}
          {finding.http_record_uuids && finding.http_record_uuids.length > 0 && (
            <div>
              <div className="text-[#918175] mb-0.5">http_records:</div>
              <ul className="space-y-0.5">
                {finding.http_record_uuids.map((uuid) => (
                  <li key={uuid} className="text-[#68a8e4] break-all">{uuid}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Raw Request */}
          {finding.request && (
            <div>
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-[#918175]">request:</span>
                <button
                  onClick={() => { navigator.clipboard.writeText(finding.request!); setCopiedRequest(true); setTimeout(() => setCopiedRequest(false), 1500); }}
                  className="px-1.5 py-0.5 text-[10px] border border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]"
                >
                  {copiedRequest ? <><Check size={10} className="inline-block mr-0.5 -mt-px" />copied!</> : <><Copy size={10} className="inline-block mr-0.5 -mt-px" />copy</>}
                </button>
              </div>
              <pre className="bg-[#141310] border border-[#2e2b26] p-2 overflow-x-auto text-[#fce8c3] whitespace-pre-wrap break-all max-h-64 overflow-y-auto">
                {finding.request}
              </pre>
            </div>
          )}

          {/* Raw Response */}
          {finding.response && (
            <div>
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-[#918175]">response:</span>
                <button
                  onClick={() => { navigator.clipboard.writeText(finding.response!); setCopiedResponse(true); setTimeout(() => setCopiedResponse(false), 1500); }}
                  className="px-1.5 py-0.5 text-[10px] border border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]"
                >
                  {copiedResponse ? <><Check size={10} className="inline-block mr-0.5 -mt-px" />copied!</> : <><Copy size={10} className="inline-block mr-0.5 -mt-px" />copy</>}
                </button>
              </div>
              <pre className="bg-[#141310] border border-[#2e2b26] p-2 overflow-x-auto text-[#fce8c3] whitespace-pre-wrap break-all max-h-64 overflow-y-auto">
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
                  <span className="text-[#918175] shrink-0 pt-0.5">additional_evidence: <span className="text-[#403d38]">({allItems.length})</span></span>
                  <div className="flex flex-wrap gap-0.5">
                    {visibleItems.map((_, i) => (
                      <button
                        key={i}
                        onClick={() => setEvidenceTab(i)}
                        className={`px-1.5 py-0.5 text-[10px] border ${evidenceTab === i ? 'border-[#7fd962] text-[#7fd962] bg-[#141310]' : 'border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]'}`}
                      >
                        #{i + 1}
                      </button>
                    ))}
                    {needsCollapse && (
                      <button
                        onClick={() => { setEvidenceExpanded((v) => !v); if (evidenceExpanded && evidenceTab >= EVIDENCE_LIMIT) setEvidenceTab(0); }}
                        className="px-1.5 py-0.5 text-[10px] border border-[#2e2b26] text-[#68a8e4] hover:underline"
                      >
                        {evidenceExpanded ? `[collapse to ${EVIDENCE_LIMIT}]` : `[show all ${allItems.length}]`}
                      </button>
                    )}
                    <button
                      onClick={() => { navigator.clipboard.writeText(evidence); setCopiedEvidence(true); setTimeout(() => setCopiedEvidence(false), 1500); }}
                      className="px-1.5 py-0.5 text-[10px] border border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]"
                    >
                      {copiedEvidence ? <><Check size={10} className="inline-block mr-0.5 -mt-px" />copied!</> : <><Copy size={10} className="inline-block mr-0.5 -mt-px" />copy</>}
                    </button>
                  </div>
                </div>
                <div className="border border-[#2e2b26] bg-[#141310] overflow-hidden min-h-80">
                  {reqPart && (
                    <pre className="p-2 text-[#fce8c3] whitespace-pre-wrap break-all max-h-64 overflow-y-auto">{reqPart}</pre>
                  )}
                  {resPart && (
                    <>
                      <div className="border-t border-dashed border-[#2e2b26] mx-2" />
                      <pre className="p-2 text-[#fce8c3] whitespace-pre-wrap break-all max-h-64 overflow-y-auto">{resPart}</pre>
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
