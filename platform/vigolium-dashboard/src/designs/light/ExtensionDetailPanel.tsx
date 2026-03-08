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
  comment: { color: '#93a1a1', fontStyle: 'italic' },
  prolog: { color: '#93a1a1' },
  doctype: { color: '#93a1a1' },
  cdata: { color: '#93a1a1' },
  punctuation: { color: '#708e8e' },
  property: { color: '#0078c8' },
  tag: { color: '#e34e1c' },
  boolean: { color: '#00b368' },
  number: { color: '#b58900' },
  constant: { color: '#b58900' },
  symbol: { color: '#b58900' },
  selector: { color: '#00b368' },
  'attr-name': { color: '#b58900' },
  string: { color: '#00b368' },
  char: { color: '#00b368' },
  builtin: { color: '#005661' },
  inserted: { color: '#00b368' },
  operator: { color: '#708e8e' },
  entity: { color: '#b58900' },
  url: { color: '#005661' },
  variable: { color: '#005661' },
  atrule: { color: '#0078c8' },
  'attr-value': { color: '#00b368' },
  keyword: { color: '#0078c8' },
  function: { color: '#005661' },
  'class-name': { color: '#b58900' },
  regex: { color: '#00b368' },
  important: { color: '#e34e1c', fontWeight: 'bold' },
  deleted: { color: '#e34e1c' },
};

function highlightCode(code: string, language: string) {
  const grammar = language === 'yaml' ? Prism.languages.yaml : Prism.languages.javascript;
  const lang = language === 'yaml' ? 'yaml' : 'javascript';
  const html = Prism.highlight(code, grammar, lang);

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
    <div className="border-l border-[#bbc3c4] bg-[#f6edda] h-full flex flex-col">
      <div className="px-3 py-1.5 border-b border-[#bbc3c4] flex items-center justify-between bg-[#f6edda] shrink-0">
        <span className="text-[#0078c8] text-xs font-bold truncate mr-2">{fileName}</span>
        <div className="flex items-center gap-1 shrink-0">
          {isDirty && (
            <button
              onClick={handleSave}
              disabled={updateExtension.isPending}
              className="text-[#00b368] hover:underline text-xs px-1 disabled:opacity-50"
            >
              {updateExtension.isPending ? '[saving...]' : '[save]'}
            </button>
          )}
          <button onClick={onClose} className="text-[#708e8e] hover:text-[#e34e1c] text-xs px-1">[x]</button>
        </div>
      </div>

      {isLoading && (
        <div className="p-3 text-xs text-[#708e8e]">loading...</div>
      )}

      {isError && (
        <div className="p-3 text-xs text-[#e34e1c]">failed to load extension</div>
      )}

      {ext && (
        <>
          {/* Metadata - compact single line */}
          <div className="px-3 py-1.5 text-xs text-[#708e8e] shrink-0 border-b border-[#bbc3c4] flex flex-wrap items-center gap-x-3 gap-y-0.5">
            <span>id: <span className="text-[#005661]">{ext.id}</span></span>
            <span>name: <span className="text-[#005661]">{ext.name}</span></span>
            <span>lang: <span className="text-[#005661]">{ext.language}</span></span>
            <span>type: <span className={ext.type === 'active' ? 'text-[#0078c8] font-bold' : 'text-[#f49725] font-bold'}>{ext.type}</span></span>
            <span>severity: <span className="font-bold" style={{ color: SEVERITY_COLORS[ext.severity] || '#708e8e' }}>{ext.severity}</span></span>
            {ext.confidence && <span>confidence: <span className="font-bold" style={{ color: CONFIDENCE_COLORS[ext.confidence] || '#708e8e' }}>{ext.confidence}</span></span>}
            {ext.scan_types && ext.scan_types.length > 0 && (
              <span>scans: <span className="text-[#005661]">{ext.scan_types.join(', ')}</span></span>
            )}
            {ext.tags && ext.tags.length > 0 && (
              <span className="flex items-center gap-1">tags: {ext.tags.map((tag) => (
                <span key={tag} className="text-[10px] px-1.5 py-0 bg-[#f6edda] border border-[#bbc3c4] text-[#0078c8]">{tag}</span>
              ))}</span>
            )}
            {ext.description && (
              <span>desc: <span className="text-[#005661]">{ext.description}</span></span>
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
                  backgroundColor: '#ffffff',
                  border: '1px solid #bbc3c4',
                  color: '#005661',
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
