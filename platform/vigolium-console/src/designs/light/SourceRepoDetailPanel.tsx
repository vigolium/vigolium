'use client';

import { useState } from 'react';
import { Copy, Check } from 'lucide-react';
import { useSourceRepo } from '@/api/hooks';
import { formatDate } from '@/lib/formatters';

interface Props {
  id: number;
  onClose: () => void;
  onDelete: (id: number) => void;
  isDeleting?: boolean;
}

const REPO_TYPE_COLORS: Record<string, string> = {
  git: '#0078c8',
  folder: '#00b368',
  archive: '#ff5792',
};

const TAG_COLORS = ['#0078c8', '#00b368', '#ff5792', '#6a8d1c', '#c88400', '#d4620a', '#8b5fc7', '#1a9e9e'];

export default function SourceRepoDetailPanel({ id, onClose, onDelete, isDeleting }: Props) {
  const { data: repo, isLoading, isError } = useSourceRepo(id);
  const [confirmDel, setConfirmDel] = useState(false);
  const [copiedEndpoints, setCopiedEndpoints] = useState(false);

  return (
    <div className="border-l border-[#bbc3c4] bg-[#f6edda] h-full overflow-y-auto">
      <div className="px-3 py-1.5 border-b border-[#bbc3c4] flex items-center justify-between sticky top-0 bg-[#f6edda] z-10">
        <span className="text-[#0078c8] text-xs font-bold truncate mr-2">REPO #{id}</span>
        <div className="flex items-center gap-1 shrink-0">
          {!confirmDel ? (
            <button onClick={() => setConfirmDel(true)} className="text-[#708e8e] hover:text-[#e34e1c] text-xs px-1" disabled={isDeleting}>[del]</button>
          ) : (
            <>
              <button onClick={() => { onDelete(id); setConfirmDel(false); }} className="text-[#e34e1c] hover:underline text-xs px-1" disabled={isDeleting}>{isDeleting ? '...' : '[confirm]'}</button>
              <button onClick={() => setConfirmDel(false)} className="text-[#708e8e] hover:underline text-xs px-1">[cancel]</button>
            </>
          )}
          <button onClick={onClose} className="text-[#708e8e] hover:text-[#e34e1c] text-xs px-1">[x]</button>
        </div>
      </div>

      {isLoading && (
        <div className="p-3 text-xs text-[#708e8e]">loading...</div>
      )}

      {isError && (
        <div className="p-3 text-xs text-[#e34e1c]">failed to load source repo</div>
      )}

      {repo && (
        <div className="p-3 space-y-3 text-xs">
          {/* Repo type */}
          <div>
            <span className="text-[#708e8e]">repo_type: </span>
            <span className="font-bold" style={{ color: REPO_TYPE_COLORS[repo.repo_type?.toLowerCase()] || '#708e8e' }}>
              {repo.repo_type}
            </span>
          </div>

          {/* Identity */}
          <div className="space-y-0.5 text-[#708e8e]">
            <div>name: <span className="text-[#005661] break-all">{repo.name}</span></div>
            <div>hostname: <span className="text-[#005661] break-all">{repo.hostname}</span></div>
            <div>root_path: <span className="text-[#005661] break-all">{repo.root_path}</span></div>
          </div>

          {/* Tech stack */}
          {(repo.language || repo.framework) && (
            <div className="space-y-0.5 text-[#708e8e]">
              {repo.language && <div>language: <span className="text-[#005661]">{repo.language}</span></div>}
              {repo.framework && <div>framework: <span className="text-[#005661]">{repo.framework}</span></div>}
            </div>
          )}

          {/* Scan info */}
          {(repo.third_party_scan_status || repo.third_party_scan_at || repo.scan_uuid) && (
            <div className="space-y-0.5 text-[#708e8e]">
              {repo.third_party_scan_status && <div>scan_status: <span className="text-[#005661]">{repo.third_party_scan_status}</span></div>}
              {repo.third_party_scan_at && <div>scan_at: <span className="text-[#005661]">{formatDate(repo.third_party_scan_at)}</span></div>}
              {repo.scan_uuid && <div>scan_uuid: <span className="text-[#005661]">{repo.scan_uuid}</span></div>}
            </div>
          )}

          {/* Tags */}
          {repo.tags && repo.tags.length > 0 && (
            <div>
              <div className="text-[#708e8e] mb-0.5">tags:</div>
              <div className="flex flex-wrap gap-1">
                {repo.tags.map((tag, i) => {
                  const color = TAG_COLORS[i % TAG_COLORS.length];
                  return (
                    <span key={i} className="bg-[#ede4d1] border px-1.5" style={{ borderColor: color, color }}>{tag}</span>
                  );
                })}
              </div>
            </div>
          )}

          {/* Endpoints */}
          {repo.endpoints && repo.endpoints.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-[#708e8e]">endpoints:</span>
                <button
                  onClick={() => { navigator.clipboard.writeText(repo.endpoints!.join('\n')); setCopiedEndpoints(true); setTimeout(() => setCopiedEndpoints(false), 1500); }}
                  className="px-1.5 py-0.5 text-[10px] border border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]"
                >
                  {copiedEndpoints ? <><Check size={10} className="inline-block mr-0.5 -mt-px" />copied!</> : <><Copy size={10} className="inline-block mr-0.5 -mt-px" />copy</>}
                </button>
              </div>
              <pre className="bg-[#ede4d1] border border-[#bbc3c4] p-2 overflow-x-auto text-[#005661] whitespace-pre-wrap break-all max-h-96 overflow-y-auto">
                {repo.endpoints.join('\n')}
              </pre>
            </div>
          )}

          {/* Route params */}
          {repo.route_params && repo.route_params.length > 0 && (
            <div>
              <div className="text-[#708e8e] mb-0.5">route_params:</div>
              <pre className="bg-[#ede4d1] border border-[#bbc3c4] p-2 overflow-x-auto text-[#005661] whitespace-pre-wrap break-all max-h-48 overflow-y-auto">
                {repo.route_params.join('\n')}
              </pre>
            </div>
          )}

          {/* Sinks */}
          {repo.sinks && repo.sinks.length > 0 && (
            <div>
              <div className="text-[#708e8e] mb-0.5">sinks:</div>
              <pre className="bg-[#ede4d1] border border-[#bbc3c4] p-2 overflow-x-auto text-[#005661] whitespace-pre-wrap break-all max-h-48 overflow-y-auto">
                {repo.sinks.join('\n')}
              </pre>
            </div>
          )}

          {/* Metadata */}
          {repo.metadata && Object.keys(repo.metadata).length > 0 && (
            <div>
              <div className="text-[#708e8e] mb-0.5">metadata:</div>
              <pre className="bg-[#ede4d1] border border-[#bbc3c4] p-2 overflow-x-auto text-[#005661] whitespace-pre-wrap break-all max-h-48 overflow-y-auto">
                {JSON.stringify(repo.metadata, null, 2)}
              </pre>
            </div>
          )}

          {/* Timestamps */}
          <div className="space-y-0.5 text-[#708e8e]">
            <div>created_at: <span className="text-[#005661]">{formatDate(repo.created_at)}</span></div>
            <div>updated_at: <span className="text-[#005661]">{formatDate(repo.updated_at)}</span></div>
          </div>
        </div>
      )}
    </div>
  );
}
