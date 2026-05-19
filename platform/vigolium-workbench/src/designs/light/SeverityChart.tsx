import type { StatsResponse } from '@/api/types';
import { SEVERITY_ORDER } from '@/lib/constants';
import { SEVERITY_COLORS } from './theme';

interface Props {
  stats?: StatsResponse;
}

export default function SeverityChart({ stats }: Props) {
  const loading = !stats;
  const data = SEVERITY_ORDER.map((sev) => ({
    severity: sev,
    count: stats?.findings.by_severity?.[sev] || 0,
  }));

  const maxCount = Math.max(...data.map((d) => d.count), 1);
  const maxBarWidth = 30;
  const hasData = data.some((d) => d.count > 0);

  return (
    <div className="border border-[#bbc3c4] bg-[#f6edda] p-3 h-full">
      <div className="text-[#0078c8] text-xs font-bold mb-2">SEVERITY DISTRIBUTION</div>
      {loading ? (
        <div className="space-y-0.5 text-xs">
          {SEVERITY_ORDER.map((sev, i) => (
            <div key={sev} className="flex items-center gap-2">
              <span className="text-[#708e8e] w-[72px] text-right">{sev}</span>
              <span
                className="v-skeleton inline-block h-3"
                style={{ width: `${28 - i * 4}%` }}
              />
            </div>
          ))}
        </div>
      ) : hasData ? (
        <div className="space-y-0.5 text-xs v-fade-in">
          {data.map((d) => {
            const barLen = Math.round((d.count / maxCount) * maxBarWidth);
            const bar = '\u2588'.repeat(barLen);
            const color = SEVERITY_COLORS[d.severity] || '#708e8e';
            return (
              <div key={d.severity} className="flex items-center gap-2">
                <span className="text-[#708e8e] w-[72px] text-right">
                  {d.severity}
                </span>
                <span style={{ color }} className="whitespace-pre">
                  {bar || '\u2591'}
                </span>
                <span className="text-[#004d57] tabular-nums">{d.count}</span>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="text-[#bbc3c4] text-xs py-4 v-fade-in">No findings data</div>
      )}
    </div>
  );
}
