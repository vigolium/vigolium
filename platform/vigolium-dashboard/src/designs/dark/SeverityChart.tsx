import type { StatsResponse } from '@/api/types';
import { SEVERITY_ORDER } from '@/lib/constants';
import { SEVERITY_COLORS } from './theme';

interface Props {
  stats?: StatsResponse;
}

export default function SeverityChart({ stats }: Props) {
  const data = SEVERITY_ORDER.map((sev) => ({
    severity: sev,
    count: stats?.findings.by_severity?.[sev] || 0,
  }));

  const maxCount = Math.max(...data.map((d) => d.count), 1);
  const maxBarWidth = 30;
  const hasData = data.some((d) => d.count > 0);

  return (
    <div className="border border-[#2e2b26] bg-[#1c1b19] p-3">
      <div className="text-[#7fd962] text-xs font-bold mb-2">SEVERITY DISTRIBUTION</div>
      {hasData ? (
        <div className="space-y-0.5 text-xs">
          {data.map((d) => {
            const barLen = Math.round((d.count / maxCount) * maxBarWidth);
            const bar = '\u2588'.repeat(barLen);
            const color = SEVERITY_COLORS[d.severity] || '#918175';
            return (
              <div key={d.severity} className="flex items-center gap-2">
                <span className="text-[#918175] w-[72px] text-right">
                  {d.severity}
                </span>
                <span style={{ color }} className="whitespace-pre">
                  {bar || '\u2591'}
                </span>
                <span className="text-[#baa67f]">{d.count}</span>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="text-[#403d38] text-xs py-4">No findings data</div>
      )}
    </div>
  );
}
