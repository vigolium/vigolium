import { useMemo } from 'react';
import type { Finding } from '@/api/types';
import { CONFIDENCE_COLORS, CHART_COLORS } from './theme';

interface Props {
  findings?: Finding[];
}

const PIE_RADIUS = 36;
const PIE_CIRCUMFERENCE = 2 * Math.PI * PIE_RADIUS;
const PIE_SIZE = 100;
const PIE_CENTER = PIE_SIZE / 2;

function DonutChart({ data, colors }: { data: [string, number][]; colors: Record<string, string> | string[] }) {
  const total = data.reduce((s, d) => s + d[1], 0);
  if (total === 0) return null;

  let accumulated = 0;
  const segments = data.map(([label, count], i) => {
    const ratio = count / total;
    const length = ratio * PIE_CIRCUMFERENCE;
    const offset = -accumulated;
    accumulated += length;
    const color = Array.isArray(colors) ? colors[i % colors.length] : (colors[label] || '#918175');
    return { label, length, offset, color };
  });

  return (
    <svg width={PIE_SIZE} height={PIE_SIZE} viewBox={`0 0 ${PIE_SIZE} ${PIE_SIZE}`} className="shrink-0">
      {/* Background ring */}
      <circle cx={PIE_CENTER} cy={PIE_CENTER} r={PIE_RADIUS} fill="none" stroke="#2e2b26" strokeWidth="16" opacity="0.5" />
      {segments.map((seg) => (
        <circle
          key={seg.label}
          cx={PIE_CENTER}
          cy={PIE_CENTER}
          r={PIE_RADIUS}
          fill="none"
          stroke={seg.color}
          strokeWidth="16"
          strokeDasharray={`${seg.length} ${PIE_CIRCUMFERENCE}`}
          strokeDashoffset={seg.offset}
          transform={`rotate(-90 ${PIE_CENTER} ${PIE_CENTER})`}
        />
      ))}
      <text x={PIE_CENTER} y={PIE_CENTER} textAnchor="middle" dominantBaseline="central" className="text-[11px] font-bold" fill="#fce8c3">
        {total}
      </text>
    </svg>
  );
}

export default function FindingsChart({ findings }: Props) {
  const confidenceData = useMemo(() => {
    if (!findings?.length) return [];
    const counts: Record<string, number> = {};
    for (const f of findings) {
      counts[f.confidence] = (counts[f.confidence] || 0) + 1;
    }
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [findings]);

  const moduleData = useMemo(() => {
    if (!findings?.length) return [];
    const counts: Record<string, number> = {};
    for (const f of findings) {
      counts[f.module_name] = (counts[f.module_name] || 0) + 1;
    }
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);
  }, [findings]);

  const maxBarWidth = 16;
  const hasData = (findings?.length ?? 0) > 0;

  return (
    <div className="border border-[#2e2b26] bg-[#1c1b19] p-3">
      <div className="text-[#7fd962] text-xs font-bold mb-2">FINDINGS BREAKDOWN</div>
      {hasData ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          {/* Confidence Distribution */}
          <div>
            <div className="text-[#918175] text-[10px] font-bold uppercase mb-1">By Confidence</div>
            <div className="flex items-start gap-4">
              <DonutChart data={confidenceData} colors={CONFIDENCE_COLORS} />
              <div className="space-y-0.5 text-xs flex-1 min-w-0 pt-1">
                {confidenceData.map(([label, count]) => {
                  const max = Math.max(...confidenceData.map((d) => d[1]), 1);
                  const total = confidenceData.reduce((s, d) => s + d[1], 0);
                  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
                  const barLen = Math.round((count / max) * maxBarWidth);
                  const bar = '\u2588'.repeat(barLen);
                  const color = CONFIDENCE_COLORS[label] || '#918175';
                  return (
                    <div key={label} className="flex items-center gap-2 overflow-hidden">
                      <span className="text-[#918175] w-[72px] shrink-0 text-right truncate">{label}</span>
                      <span style={{ color }} className="whitespace-pre">{bar || '\u2591'}</span>
                      <span className="text-[#baa67f] shrink-0">{count}</span>
                      <span className="text-[#918175] shrink-0">({pct}%)</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Top Modules */}
          <div>
            <div className="text-[#918175] text-[10px] font-bold uppercase mb-1">Top Modules</div>
            <div className="flex items-start gap-4">
              <DonutChart data={moduleData} colors={CHART_COLORS} />
              <div className="space-y-0.5 text-xs flex-1 min-w-0 pt-1">
                {moduleData.map(([label, count], i) => {
                  const max = Math.max(...moduleData.map((d) => d[1]), 1);
                  const total = moduleData.reduce((s, d) => s + d[1], 0);
                  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
                  const barLen = Math.round((count / max) * maxBarWidth);
                  const bar = '\u2588'.repeat(barLen);
                  const color = CHART_COLORS[i % CHART_COLORS.length];
                  return (
                    <div key={label} className="flex items-center gap-2 overflow-hidden">
                      <span className="text-[#918175] w-[90px] shrink-0 text-right truncate" title={label}>{label}</span>
                      <span style={{ color }} className="whitespace-pre">{bar || '\u2591'}</span>
                      <span className="text-[#baa67f] shrink-0">{count}</span>
                      <span className="text-[#918175] shrink-0">({pct}%)</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="text-[#403d38] text-xs py-4">No findings data</div>
      )}
    </div>
  );
}
