import type { ServerInfoResponse } from '@/api/types';

interface Props {
  serverInfo?: ServerInfoResponse;
}

export default function ServerInfo({ serverInfo }: Props) {
  if (!serverInfo) return null;

  const items = [
    { key: 'version', value: serverInfo.version },
    { key: 'uptime', value: serverInfo.uptime },
    { key: 'queue', value: String(serverInfo.queue_depth) },
    { key: 'db', value: serverInfo.db_driver || 'sqlite' },
    { key: 'records', value: String(serverInfo.total_records) },
    { key: 'findings', value: String(serverInfo.total_findings) },
    ...(serverInfo.commit ? [{ key: 'commit', value: serverInfo.commit.slice(0, 7) }] : []),
  ];

  return (
    <div className="border border-[#bbc3c4] bg-[#f6edda] p-3">
      <div className="text-[#0078c8] text-xs font-bold mb-2">SERVER</div>
      <div className="flex items-start gap-3">
        <img src="/vigolium-logo-minimal.png" alt="" className="h-20 w-20 rounded-lg border border-[#00b368]/50 shadow-[0_0_12px_rgba(0,179,104,0.3)] flex-shrink-0" />
        <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-xs flex-1 content-start">
          {items.map((item) => (
            <div key={item.key} className="flex items-center">
              <span className="text-[#708e8e] w-[70px] shrink-0">{item.key}: </span>
              <span className="text-[#005661] truncate">{item.value}</span>
            </div>
          ))}
          {serverInfo.service_addr && (
            <div className="flex items-center">
              <span className="text-[#708e8e] w-[70px] shrink-0">addr: </span>
              <span className="text-[#004d57] truncate">{serverInfo.service_addr}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
