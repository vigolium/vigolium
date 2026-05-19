import { useEffect, useMemo, useState } from 'react';
import type { HTTPRecord } from '@/api/types';
import { STATUS_COLORS, CHART_COLORS } from './theme';

interface Props {
  records?: HTTPRecord[];
}

const PIE_RADIUS = 36;
const PIE_CIRCUMFERENCE = 2 * Math.PI * PIE_RADIUS;
const PIE_SIZE = 100;
const PIE_CENTER = PIE_SIZE / 2;

function DonutChart({ data, colors }: { data: [string, number][]; colors: Record<string, string> | string[] }) {
  const total = data.reduce((s, d) => s + d[1], 0);
  const [animated, setAnimated] = useState(false);

  useEffect(() => {
    const id = requestAnimationFrame(() => setAnimated(true));
    return () => cancelAnimationFrame(id);
  }, []);

  if (total === 0) return null;

  let accumulated = 0;
  const segments = data.map(([label, count], i) => {
    const ratio = count / total;
    const length = ratio * PIE_CIRCUMFERENCE;
    const offset = -accumulated;
    accumulated += length;
    const color = Array.isArray(colors) ? colors[i % colors.length] : (colors[label] || '#708e8e');
    return { label, length, offset, color };
  });

  return (
    <svg width={PIE_SIZE} height={PIE_SIZE} viewBox={`0 0 ${PIE_SIZE} ${PIE_SIZE}`} className="shrink-0">
      {/* Background ring */}
      <circle cx={PIE_CENTER} cy={PIE_CENTER} r={PIE_RADIUS} fill="none" stroke="#bbc3c4" strokeWidth="16" opacity="0.2" />
      {segments.map((seg) => (
        <circle
          key={seg.label}
          cx={PIE_CENTER}
          cy={PIE_CENTER}
          r={PIE_RADIUS}
          fill="none"
          stroke={seg.color}
          strokeWidth="16"
          className="v-donut-segment"
          strokeDasharray={animated ? `${seg.length} ${PIE_CIRCUMFERENCE}` : `0 ${PIE_CIRCUMFERENCE}`}
          strokeDashoffset={seg.offset}
          transform={`rotate(-90 ${PIE_CENTER} ${PIE_CENTER})`}
        />
      ))}
      <text x={PIE_CENTER} y={PIE_CENTER} textAnchor="middle" dominantBaseline="central" className="text-[11px] font-bold" fill="#005661">
        {total}
      </text>
    </svg>
  );
}

function DonutSkeleton() {
  return (
    <svg width={PIE_SIZE} height={PIE_SIZE} viewBox={`0 0 ${PIE_SIZE} ${PIE_SIZE}`} className="shrink-0">
      <circle cx={PIE_CENTER} cy={PIE_CENTER} r={PIE_RADIUS} fill="none" stroke="#bbc3c4" strokeWidth="16" opacity="0.3" />
      <circle
        cx={PIE_CENTER}
        cy={PIE_CENTER}
        r={PIE_RADIUS}
        fill="none"
        stroke="#708e8e"
        strokeWidth="16"
        strokeDasharray={`${PIE_CIRCUMFERENCE * 0.18} ${PIE_CIRCUMFERENCE}`}
        opacity="0.5"
        transform={`rotate(-90 ${PIE_CENTER} ${PIE_CENTER})`}
        style={{ transformOrigin: `${PIE_CENTER}px ${PIE_CENTER}px`, animation: 'spin 1.6s linear infinite' }}
      />
    </svg>
  );
}

function ChartSkeleton() {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
      {[0, 1].map((col) => (
        <div key={col}>
          <div className="text-[#708e8e] text-[10px] font-bold uppercase mb-1 opacity-60">
            <span className="v-skeleton inline-block h-2 w-24 align-middle" />
          </div>
          <div className="flex items-start gap-4">
            <DonutSkeleton />
            <div className="space-y-1 flex-1 min-w-0 pt-1">
              {[0, 1, 2, 3].map((i) => (
                <div key={i} className="flex items-center gap-2">
                  <span className="v-skeleton inline-block h-3 w-14" />
                  <span className="v-skeleton inline-block h-3 flex-1" style={{ maxWidth: `${60 - i * 10}%` }} />
                </div>
              ))}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

export default function HttpRecordsChart({ records }: Props) {
  const statusData = useMemo(() => {
    if (!records?.length) return [];
    const counts: Record<string, number> = {};
    for (const r of records) {
      const cat = `${Math.floor(r.status_code / 100)}xx`;
      counts[cat] = (counts[cat] || 0) + 1;
    }
    return Object.entries(counts).sort((a, b) => a[0].localeCompare(b[0]));
  }, [records]);

  const contentTypeData = useMemo(() => {
    if (!records?.length) return [];
    const counts: Record<string, number> = {};
    for (const r of records) {
      const ct = (r.response_content_type || 'unknown').split(';')[0].trim();
      counts[ct] = (counts[ct] || 0) + 1;
    }
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6);
  }, [records]);

  const maxBarWidth = 16;
  const loading = records === undefined;
  const hasData = (records?.length ?? 0) > 0;

  return (
    <div className="border border-[#bbc3c4] bg-[#f6edda] p-3 h-full">
      <div className="text-[#0078c8] text-xs font-bold mb-2">HTTP RECORDS BREAKDOWN</div>
      {loading ? (
        <ChartSkeleton />
      ) : hasData ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 v-fade-in">
          {/* Status Code Distribution */}
          <div>
            <div className="text-[#708e8e] text-[10px] font-bold uppercase mb-1">By Status Code</div>
            <div className="flex items-start gap-4">
              <DonutChart data={statusData} colors={STATUS_COLORS} />
              <div className="space-y-0.5 text-xs flex-1 min-w-0 pt-1">
                {statusData.map(([label, count]) => {
                  const max = Math.max(...statusData.map((d) => d[1]), 1);
                  const total = statusData.reduce((s, d) => s + d[1], 0);
                  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
                  const barLen = Math.round((count / max) * maxBarWidth);
                  const bar = '\u2588'.repeat(barLen);
                  const color = STATUS_COLORS[label] || '#708e8e';
                  return (
                    <div key={label} className="flex items-center gap-2 overflow-hidden">
                      <span className="text-[#708e8e] w-[72px] shrink-0 text-right truncate">{label}</span>
                      <span style={{ color }} className="whitespace-pre">{bar || '\u2591'}</span>
                      <span className="text-[#004d57] shrink-0">{count}</span>
                      <span className="text-[#708e8e] shrink-0">({pct}%)</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Top Content Types */}
          <div>
            <div className="text-[#708e8e] text-[10px] font-bold uppercase mb-1">Top Content Types</div>
            <div className="flex items-start gap-4">
              <DonutChart data={contentTypeData} colors={CHART_COLORS} />
              <div className="space-y-0.5 text-xs flex-1 min-w-0 pt-1">
                {contentTypeData.map(([label, count], i) => {
                  const max = Math.max(...contentTypeData.map((d) => d[1]), 1);
                  const total = contentTypeData.reduce((s, d) => s + d[1], 0);
                  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
                  const barLen = Math.round((count / max) * maxBarWidth);
                  const bar = '\u2588'.repeat(barLen);
                  const color = CHART_COLORS[i % CHART_COLORS.length];
                  return (
                    <div key={label} className="flex items-center gap-2 overflow-hidden">
                      <span className="text-[#708e8e] w-[90px] shrink-0 text-right truncate" title={label}>{label}</span>
                      <span style={{ color }} className="whitespace-pre">{bar || '\u2591'}</span>
                      <span className="text-[#004d57] shrink-0">{count}</span>
                      <span className="text-[#708e8e] shrink-0">({pct}%)</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="text-[#bbc3c4] text-xs py-4 v-fade-in">No HTTP records data</div>
      )}
    </div>
  );
}
