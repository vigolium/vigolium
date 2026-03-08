'use client';

import { useState, useEffect, useMemo } from 'react';
import Editor from 'react-simple-code-editor';
import Prism from 'prismjs';
import 'prismjs/components/prism-javascript';
import 'prismjs/components/prism-yaml';
import { useExtension, useUpdateExtension } from '@/api/hooks';
import { useToast } from '@/contexts/ToastContext';
import { SEVERITY_COLORS, CONFIDENCE_COLORS } from './theme';

interface Props {
  fileName: string;
  onClose: () => void;
}

const tokenStyles: Record<string, React.CSSProperties> = {
  comment: { color: '#706560', fontStyle: 'italic' },
  prolog: { color: '#706560' },
  doctype: { color: '#706560' },
  cdata: { color: '#706560' },
  punctuation: { color: '#918175' },
  property: { color: '#68a8e4' },
  tag: { color: '#ef2f27' },
  boolean: { color: '#7fd962' },
  number: { color: '#f0c674' },
  constant: { color: '#f0c674' },
  symbol: { color: '#f0c674' },
  selector: { color: '#7fd962' },
  'attr-name': { color: '#f0c674' },
  string: { color: '#7fd962' },
  char: { color: '#7fd962' },
  builtin: { color: '#2be4d0' },
  inserted: { color: '#7fd962' },
  operator: { color: '#918175' },
  entity: { color: '#f0c674' },
  url: { color: '#2be4d0' },
  variable: { color: '#fce8c3' },
  atrule: { color: '#68a8e4' },
  'attr-value': { color: '#7fd962' },
  keyword: { color: '#68a8e4' },
  function: { color: '#2be4d0' },
  'class-name': { color: '#f0c674' },
  regex: { color: '#7fd962' },
  important: { color: '#ef2f27', fontWeight: 'bold' },
  deleted: { color: '#ef2f27' },
};

function highlightCode(code: string, language: string) {
  const grammar = language === 'yaml' ? Prism.languages.yaml : Prism.languages.javascript;
  const lang = language === 'yaml' ? 'yaml' : 'javascript';
  const html = Prism.highlight(code, grammar, lang);

  // Apply inline styles to Prism tokens
  let styled = html;
  for (const [token, style] of Object.entries(tokenStyles)) {
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

export default function ExtensionDetailPanel({ fileName, onClose }: Props) {
  const { data: ext, isLoading, isError } = useExtension(fileName);
  const updateExtension = useUpdateExtension();
  const { toast } = useToast();
  const [editContent, setEditContent] = useState('');
  const [isDirty, setIsDirty] = useState(false);

  useEffect(() => {
    if (ext?.raw_content !== undefined) {
      setEditContent(ext.raw_content);
      setIsDirty(false);
    }
  }, [ext?.raw_content]);

  const language = useMemo(() => {
    if (ext?.language) return ext.language;
    if (fileName.endsWith('.yaml') || fileName.endsWith('.yml')) return 'yaml';
    return 'js';
  }, [ext?.language, fileName]);

  const handleSave = () => {
    updateExtension.mutate(
      { fileName, content: editContent },
      {
        onSuccess: (res) => {
          toast(res.message, 'success');
          setIsDirty(false);
        },
        onError: (err) => {
          toast((err as Error).message, 'error');
        },
      }
    );
  };

  return (
    <div className="border-l border-[#2e2b26] bg-[#1c1b19] h-full flex flex-col">
      <div className="px-3 py-1.5 border-b border-[#2e2b26] flex items-center justify-between bg-[#1c1b19] shrink-0">
        <span className="text-[#7fd962] text-xs font-bold truncate mr-2">{fileName}</span>
        <div className="flex items-center gap-1 shrink-0">
          {isDirty && (
            <button
              onClick={handleSave}
              disabled={updateExtension.isPending}
              className="text-[#7fd962] hover:underline text-xs px-1 disabled:opacity-50"
            >
              {updateExtension.isPending ? '[saving...]' : '[save]'}
            </button>
          )}
          <button onClick={onClose} className="text-[#918175] hover:text-[#ef2f27] text-xs px-1">[x]</button>
        </div>
      </div>

      {isLoading && (
        <div className="p-3 text-xs text-[#918175]">loading...</div>
      )}

      {isError && (
        <div className="p-3 text-xs text-[#ef2f27]">failed to load extension</div>
      )}

      {ext && (
        <>
          {/* Metadata - compact single line */}
          <div className="px-3 py-1.5 text-xs text-[#918175] shrink-0 border-b border-[#2e2b26] flex flex-wrap items-center gap-x-3 gap-y-0.5">
            <span>id: <span className="text-[#fce8c3]">{ext.id}</span></span>
            <span>name: <span className="text-[#fce8c3]">{ext.name}</span></span>
            <span>lang: <span className="text-[#fce8c3]">{ext.language}</span></span>
            <span>type: <span className={ext.type === 'active' ? 'text-[#68a8e4] font-bold' : 'text-[#baa67f] font-bold'}>{ext.type}</span></span>
            <span>severity: <span className="font-bold" style={{ color: SEVERITY_COLORS[ext.severity] || '#918175' }}>{ext.severity}</span></span>
            {ext.confidence && <span>confidence: <span className="font-bold" style={{ color: CONFIDENCE_COLORS[ext.confidence] || '#918175' }}>{ext.confidence}</span></span>}
            {ext.scan_types && ext.scan_types.length > 0 && (
              <span>scans: <span className="text-[#fce8c3]">{ext.scan_types.join(', ')}</span></span>
            )}
            {ext.tags && ext.tags.length > 0 && (
              <span className="flex items-center gap-1">tags: {ext.tags.map((tag) => (
                <span key={tag} className="text-[10px] px-1.5 py-0 bg-[#272520] border border-[#2e2b26] text-[#68a8e4]">{tag}</span>
              ))}</span>
            )}
            {ext.description && (
              <span>desc: <span className="text-[#fce8c3]">{ext.description}</span></span>
            )}
          </div>

          {/* Code editor - fills remaining space */}
          {ext.raw_content !== undefined && (
            <div className="flex-1 overflow-auto p-3">
              <Editor
                value={editContent}
                onValueChange={(code) => {
                  setEditContent(code);
                  setIsDirty(code !== ext.raw_content);
                }}
                highlight={(code) => highlightCode(code, language)}
                padding={8}
                style={{
                  fontFamily: 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace',
                  fontSize: 12,
                  lineHeight: 1.5,
                  backgroundColor: '#141310',
                  border: '1px solid #2e2b26',
                  color: '#fce8c3',
                  minHeight: '100%',
                  tabSize: 2,
                }}
                textareaClassName="focus:outline-none"
              />
            </div>
          )}
        </>
      )}
    </div>
  );
}
