'use client';

import { useState } from 'react';
import { useOASTInteraction } from '@/api/hooks';
import { formatDate } from '@/lib/formatters';
import { PROTOCOL_COLORS } from './theme';

interface Props {
  id: number;
  onClose: () => void;
  onDelete: (id: number) => void;
  isDeleting?: boolean;
}

function safeAtob(s: string): string {
  try {
    return atob(s);
  } catch {
    return s;
  }
}

export default function OASTInteractionDetailPanel({ id, onClose, onDelete, isDeleting }: Props) {
  const { data: interaction, isLoading, isError } = useOASTInteraction(id);
  const [confirmDel, setConfirmDel] = useState(false);

  return (
    <div className="border-l border-[#2e2b26] bg-[#1c1b19] h-full overflow-y-auto">
      <div className="px-3 py-1.5 border-b border-[#2e2b26] flex items-center justify-between sticky top-0 bg-[#1c1b19] z-10">
        <span className="text-[#7fd962] text-xs font-bold truncate mr-2">OAST #{id}</span>
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
        <div className="p-3 text-xs text-[#ef2f27]">failed to load interaction</div>
      )}

      {interaction && (
        <div className="p-3 space-y-3 text-xs">
          {/* Protocol */}
          <div>
            <span className="text-[#918175]">protocol: </span>
            <span className="font-bold" style={{ color: PROTOCOL_COLORS[interaction.protocol?.toLowerCase()] || '#918175' }}>
              {interaction.protocol}
            </span>
          </div>

          {/* IDs */}
          <div className="space-y-0.5 text-[#918175]">
            <div>unique_id: <span className="text-[#fce8c3] break-all">{interaction.unique_id}</span></div>
            <div>full_id: <span className="text-[#fce8c3] break-all">{interaction.full_id}</span></div>
          </div>

          {/* Q-Type */}
          {interaction.q_type && (
            <div>
              <span className="text-[#918175]">q_type: </span>
              <span className="text-[#fce8c3]">{interaction.q_type}</span>
            </div>
          )}

          {/* Target context */}
          <div className="space-y-0.5 text-[#918175]">
            {interaction.target_url && <div>target_url: <span className="text-[#fce8c3] break-all">{interaction.target_url}</span></div>}
            {interaction.parameter_name && <div>parameter: <span className="text-[#fce8c3]">{interaction.parameter_name}</span></div>}
            {interaction.injection_type && <div>injection_type: <span className="text-[#fce8c3]">{interaction.injection_type}</span></div>}
            {interaction.module_id && <div>module_id: <span className="text-[#fce8c3]">{interaction.module_id}</span></div>}
          </div>

          {/* Connection */}
          <div className="space-y-0.5 text-[#918175]">
            {interaction.remote_address && <div>remote_address: <span className="text-[#fce8c3]">{interaction.remote_address}</span></div>}
            <div>interacted_at: <span className="text-[#fce8c3]">{formatDate(interaction.interacted_at)}</span></div>
            {interaction.scan_uuid && <div>scan_uuid: <span className="text-[#fce8c3]">{interaction.scan_uuid}</span></div>}
          </div>

          {/* Raw Request */}
          {interaction.raw_request && (
            <div>
              <div className="text-[#918175] mb-0.5">raw_request:</div>
              <pre className="bg-[#141310] border border-[#2e2b26] p-2 overflow-x-auto text-[#fce8c3] whitespace-pre-wrap break-all max-h-64 overflow-y-auto">
                {safeAtob(interaction.raw_request)}
              </pre>
            </div>
          )}

          {/* Raw Response */}
          {interaction.raw_response && (
            <div>
              <div className="text-[#918175] mb-0.5">raw_response:</div>
              <pre className="bg-[#141310] border border-[#2e2b26] p-2 overflow-x-auto text-[#fce8c3] whitespace-pre-wrap break-all max-h-64 overflow-y-auto">
                {safeAtob(interaction.raw_response)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
