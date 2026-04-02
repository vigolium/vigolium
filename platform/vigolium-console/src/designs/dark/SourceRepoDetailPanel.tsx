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
  git: '#68a8e4',
  folder: '#7fd962',
  archive: '#ff5c8f',
};

const TAG_COLORS = ['#68a8e4', '#7fd962', '#ff5c8f', '#98bc37', '#fbb829', '#ff8700', '#c3a5e6', '#2dc7c4'];

export default function SourceRepoDetailPanel({ id, onClose, onDelete, isDeleting }: Props) {
  const { data: repo, isLoading, isError } = useSourceRepo(id);
  const [confirmDel, setConfirmDel] = useState(false);
  const [copiedEndpoints, setCopiedEndpoints] = useState(false);

  return (
    <div className="border-l border-[#2e2b26] bg-[#1c1b19] h-full overflow-y-auto">
      <div className="px-3 py-1.5 border-b border-[#2e2b26] flex items-center justify-between sticky top-0 bg-[#1c1b19] z-10">
        <span className="text-[#7fd962] text-xs font-bold truncate mr-2">REPO #{id}</span>
        <div className="flex items-center gap-1 shrink-0">
          {!confirmDel ? (
            <button onClick={() => setConfirmDel(true)} className="text-[#918175] hover:text-[#ef2f27] text-xs px-1" disabled={isDeleting}>[del]</button>
          ) : (
            <>
              <button onClick={() => { onDelete(id); setConfirmDel(false); }} className="text-[#ef2f27] hover:underline text-xs px-1" disabled={isDeleting}>{isDeleting ? '...' : '[confirm]'}</button>
              <button onClick={() => setConfirmDel(false)} className="text-[#918175] hover:underline text-xs px-1">[cancel]</button>
            </>
          )}
          <button onClick={onClose} className="text-[#918175] hover:text-[#ef2f27] text-xs px-1">[x]</button>
        </div>
      </div>

      {isLoading && (
        <div className="p-3 text-xs text-[#918175]">loading...</div>
      )}

      {isError && (
        <div className="p-3 text-xs text-[#ef2f27]">failed to load source repo</div>
      )}

      {repo && (
        <div className="p-3 space-y-3 text-xs">
          {/* Repo type */}
          <div>
            <span className="text-[#918175]">repo_type: </span>
            <span className="font-bold" style={{ color: REPO_TYPE_COLORS[repo.repo_type?.toLowerCase()] || '#918175' }}>
              {repo.repo_type}
            </span>
          </div>

          {/* Identity */}
          <div className="space-y-0.5 text-[#918175]">
            <div>name: <span className="text-[#fce8c3] break-all">{repo.name}</span></div>
            <div>hostname: <span className="text-[#fce8c3] break-all">{repo.hostname}</span></div>
            <div>root_path: <span className="text-[#fce8c3] break-all">{repo.root_path}</span></div>
          </div>

          {/* Tech stack */}
          {(repo.language || repo.framework) && (
            <div className="space-y-0.5 text-[#918175]">
              {repo.language && <div>language: <span className="text-[#fce8c3]">{repo.language}</span></div>}
              {repo.framework && <div>framework: <span className="text-[#fce8c3]">{repo.framework}</span></div>}
            </div>
          )}

          {/* Scan info */}
          {(repo.third_party_scan_status || repo.third_party_scan_at || repo.scan_uuid) && (
            <div className="space-y-0.5 text-[#918175]">
              {repo.third_party_scan_status && <div>scan_status: <span className="text-[#fce8c3]">{repo.third_party_scan_status}</span></div>}
              {repo.third_party_scan_at && <div>scan_at: <span className="text-[#fce8c3]">{formatDate(repo.third_party_scan_at)}</span></div>}
              {repo.scan_uuid && <div>scan_uuid: <span className="text-[#fce8c3]">{repo.scan_uuid}</span></div>}
            </div>
          )}

          {/* Tags */}
          {repo.tags && repo.tags.length > 0 && (
            <div>
              <div className="text-[#918175] mb-0.5">tags:</div>
              <div className="flex flex-wrap gap-1">
                {repo.tags.map((tag, i) => {
                  const color = TAG_COLORS[i % TAG_COLORS.length];
                  return (
                    <span key={i} className="bg-[#272520] border px-1.5" style={{ borderColor: color, color }}>{tag}</span>
                  );
                })}
              </div>
            </div>
          )}

          {/* Endpoints */}
          {repo.endpoints && repo.endpoints.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-[#918175]">endpoints:</span>
                <button
                  onClick={() => { navigator.clipboard.writeText(repo.endpoints!.join('\n')); setCopiedEndpoints(true); setTimeout(() => setCopiedEndpoints(false), 1500); }}
                  className="px-1.5 py-0.5 text-[10px] border border-[#2e2b26] text-[#918175] hover:text-[#fce8c3]"
                >
                  {copiedEndpoints ? <><Check size={10} className="inline-block mr-0.5 -mt-px" />copied!</> : <><Copy size={10} className="inline-block mr-0.5 -mt-px" />copy</>}
                </button>
              </div>
              <pre className="bg-[#141310] border border-[#2e2b26] p-2 overflow-x-auto text-[#fce8c3] whitespace-pre-wrap break-all max-h-96 overflow-y-auto">
                {repo.endpoints.join('\n')}
              </pre>
            </div>
          )}

          {/* Route params */}
          {repo.route_params && repo.route_params.length > 0 && (
            <div>
              <div className="text-[#918175] mb-0.5">route_params:</div>
              <pre className="bg-[#141310] border border-[#2e2b26] p-2 overflow-x-auto text-[#fce8c3] whitespace-pre-wrap break-all max-h-48 overflow-y-auto">
                {repo.route_params.join('\n')}
              </pre>
            </div>
          )}

          {/* Sinks */}
          {repo.sinks && repo.sinks.length > 0 && (
            <div>
              <div className="text-[#918175] mb-0.5">sinks:</div>
              <pre className="bg-[#141310] border border-[#2e2b26] p-2 overflow-x-auto text-[#fce8c3] whitespace-pre-wrap break-all max-h-48 overflow-y-auto">
                {repo.sinks.join('\n')}
              </pre>
            </div>
          )}

          {/* Metadata */}
          {repo.metadata && Object.keys(repo.metadata).length > 0 && (
            <div>
              <div className="text-[#918175] mb-0.5">metadata:</div>
              <pre className="bg-[#141310] border border-[#2e2b26] p-2 overflow-x-auto text-[#fce8c3] whitespace-pre-wrap break-all max-h-48 overflow-y-auto">
                {JSON.stringify(repo.metadata, null, 2)}
              </pre>
            </div>
          )}

          {/* Timestamps */}
          <div className="space-y-0.5 text-[#918175]">
            <div>created_at: <span className="text-[#fce8c3]">{formatDate(repo.created_at)}</span></div>
            <div>updated_at: <span className="text-[#fce8c3]">{formatDate(repo.updated_at)}</span></div>
          </div>
        </div>
      )}
    </div>
  );
}
