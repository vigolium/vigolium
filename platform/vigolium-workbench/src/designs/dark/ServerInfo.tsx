import type { ServerInfoResponse } from '@/api/types';

interface Props {
  serverInfo?: ServerInfoResponse;
}

export default function ServerInfo({ serverInfo }: Props) {
  if (!serverInfo) {
    return (
      <div className="border border-[#2e2b26] bg-[#1c1b19] p-3 h-full">
        <div className="text-[#7fd962] text-xs font-bold mb-2">SERVER</div>
        <div className="flex items-start gap-3">
          <div className="v-skeleton h-20 w-20 rounded-lg flex-shrink-0" />
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs flex-1 content-start">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="flex items-center gap-2">
                <span className="v-skeleton h-3 w-12" />
                <span className="v-skeleton h-3 flex-1" />
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  const items = [
    { key: 'version', value: serverInfo.version },
    { key: 'uptime', value: serverInfo.uptime },
    { key: 'queue', value: String(serverInfo.queue_depth) },
    { key: 'records', value: String(serverInfo.total_records) },
    ...(serverInfo.commit ? [{ key: 'commit', value: serverInfo.commit.slice(0, 7) }] : []),
  ];

  return (
    <div className="border border-[#2e2b26] bg-[#1c1b19] p-3 v-fade-in h-full">
      <div className="text-[#7fd962] text-xs font-bold mb-2">SERVER</div>
      <div className="flex items-start gap-3">
        <img src="/vigolium-logo-minimal.png" alt="" className="h-20 w-20 rounded-lg border border-[#7fd962]/50 shadow-[0_0_12px_rgba(127,217,98,0.3)] flex-shrink-0" />
        <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-xs flex-1 content-start">
          {items.map((item) => (
            <div key={item.key} className="flex items-center">
              <span className="text-[#918175] w-[70px] shrink-0">{item.key}: </span>
              <span className="text-[#fce8c3] truncate">{item.value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
