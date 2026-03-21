import type { StatsResponse, ServerInfoResponse } from '@/api/types';
import { formatNumber } from '@/lib/formatters';

interface Props {
  stats?: StatsResponse;
  serverInfo?: ServerInfoResponse;
}

export default function SummaryCards({ stats }: Props) {
  const critHigh =
    (stats?.findings.by_severity?.critical || 0) +
    (stats?.findings.by_severity?.high || 0);

  const totalModules =
    (stats?.modules.active.total || 0) + (stats?.modules.passive.total || 0);
  const enabledModules =
    (stats?.modules.active.enabled || 0) + (stats?.modules.passive.enabled || 0);

  const items = [
    { label: 'FINDINGS', value: formatNumber(stats?.findings.total || 0) },
    {
      label: 'CRIT/HIGH',
      value: formatNumber(critHigh),
      color: critHigh > 0 ? '#E53935' : '#98bc37',
    },
    { label: 'RECORDS', value: formatNumber(stats?.http_records.total || 0) },
    { label: 'MODULES', value: `${enabledModules}/${totalModules}` },
  ];

  return (
    <div className="border border-[#2e2b26] bg-[#1c1b19] px-4 py-1.5 text-xs flex items-center gap-2 flex-wrap">
      {items.map((item, i) => (
        <span key={item.label} className="flex items-center gap-1">
          {i > 0 && <span className="text-[#403d38] mr-1">|</span>}
          <span className="text-[#918175]">{item.label}:</span>
          <span style={{ color: item.color || '#7fd962' }} className="font-bold">
            {item.value}
          </span>
        </span>
      ))}
    </div>
  );
}
