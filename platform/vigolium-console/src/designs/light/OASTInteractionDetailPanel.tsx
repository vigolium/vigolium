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
    <div className="border-l border-[#bbc3c4] bg-[#f6edda] h-full overflow-y-auto">
      <div className="px-3 py-1.5 border-b border-[#bbc3c4] flex items-center justify-between sticky top-0 bg-[#f6edda] z-10">
        <span className="text-[#0078c8] text-xs font-bold truncate mr-2">OAST #{id}</span>
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
        <div className="p-3 text-xs text-[#e34e1c]">failed to load interaction</div>
      )}

      {interaction && (
        <div className="p-3 space-y-3 text-xs">
          {/* Protocol */}
          <div>
            <span className="text-[#708e8e]">protocol: </span>
            <span className="font-bold" style={{ color: PROTOCOL_COLORS[interaction.protocol?.toLowerCase()] || '#708e8e' }}>
              {interaction.protocol}
            </span>
          </div>

          {/* IDs */}
          <div className="space-y-0.5 text-[#708e8e]">
            <div>unique_id: <span className="text-[#005661] break-all">{interaction.unique_id}</span></div>
            <div>full_id: <span className="text-[#005661] break-all">{interaction.full_id}</span></div>
          </div>

          {/* Q-Type */}
          {interaction.q_type && (
            <div>
              <span className="text-[#708e8e]">q_type: </span>
              <span className="text-[#005661]">{interaction.q_type}</span>
            </div>
          )}

          {/* Target context */}
          <div className="space-y-0.5 text-[#708e8e]">
            {interaction.target_url && <div>target_url: <span className="text-[#005661] break-all">{interaction.target_url}</span></div>}
            {interaction.parameter_name && <div>parameter: <span className="text-[#005661]">{interaction.parameter_name}</span></div>}
            {interaction.injection_type && <div>injection_type: <span className="text-[#005661]">{interaction.injection_type}</span></div>}
            {interaction.module_id && <div>module_id: <span className="text-[#005661]">{interaction.module_id}</span></div>}
          </div>

          {/* Connection */}
          <div className="space-y-0.5 text-[#708e8e]">
            {interaction.remote_address && <div>remote_address: <span className="text-[#005661]">{interaction.remote_address}</span></div>}
            <div>interacted_at: <span className="text-[#005661]">{formatDate(interaction.interacted_at)}</span></div>
            {interaction.scan_uuid && <div>scan_uuid: <span className="text-[#005661]">{interaction.scan_uuid}</span></div>}
          </div>

          {/* Raw Request */}
          {interaction.raw_request && (
            <div>
              <div className="text-[#708e8e] mb-0.5">raw_request:</div>
              <pre className="bg-[#ede4d1] border border-[#bbc3c4] p-2 overflow-x-auto text-[#005661] whitespace-pre-wrap break-all max-h-64 overflow-y-auto">
                {safeAtob(interaction.raw_request)}
              </pre>
            </div>
          )}

          {/* Raw Response */}
          {interaction.raw_response && (
            <div>
              <div className="text-[#708e8e] mb-0.5">raw_response:</div>
              <pre className="bg-[#ede4d1] border border-[#bbc3c4] p-2 overflow-x-auto text-[#005661] whitespace-pre-wrap break-all max-h-64 overflow-y-auto">
                {safeAtob(interaction.raw_response)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
