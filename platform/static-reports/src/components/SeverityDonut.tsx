import { useMemo } from "react";

export interface SeverityDonutProps {
  counts: Record<string, number>;
  size?: number;
  innerLabel?: string;
}

const SEV_ORDER = ["critical", "high", "medium", "low", "suspect", "info", "n/a"] as const;

function sevCssVar(k: string): string {
  return `var(--sev-${k === "n/a" ? "na" : k})`;
}

/**
 * Pure-SVG donut — colours come from `--sev-*` CSS vars so it flips
 * automatically with theme changes.
 */
export default function SeverityDonut({ counts, size = 140, innerLabel = "FINDINGS" }: SeverityDonutProps) {
  const total = SEV_ORDER.reduce((sum, k) => sum + (counts[k] || 0), 0);
  const cx = size / 2;
  const cy = size / 2;
  const r = size / 2 - 10;
  const innerR = r * 0.6;

  const slices = useMemo(() => {
    if (total === 0) return [];
    let angle = -Math.PI / 2;
    const out: { k: string; d: string }[] = [];
    for (const k of SEV_ORDER) {
      const v = counts[k] || 0;
      if (!v) continue;
      const next = angle + (v / total) * Math.PI * 2;
      const x0 = cx + r * Math.cos(angle);
      const y0 = cy + r * Math.sin(angle);
      const x1 = cx + r * Math.cos(next);
      const y1 = cy + r * Math.sin(next);
      const large = next - angle > Math.PI ? 1 : 0;
      out.push({
        k,
        d: `M${cx} ${cy} L${x0.toFixed(2)} ${y0.toFixed(2)} A${r} ${r} 0 ${large} 1 ${x1.toFixed(2)} ${y1.toFixed(2)} Z`,
      });
      angle = next;
    }
    return out;
  }, [counts, total, cx, cy, r]);

  if (total === 0) {
    return (
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--v-border)" strokeWidth={2} />
        <text
          x={cx}
          y={cy + 4}
          textAnchor="middle"
          fontSize={11}
          fill="var(--v-text-muted)"
        >
          no findings
        </text>
      </svg>
    );
  }

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      {slices.map((s) => (
        <path key={s.k} d={s.d} fill={sevCssVar(s.k)} />
      ))}
      <circle cx={cx} cy={cy} r={innerR} fill="var(--v-surface)" />
      <text
        x={cx}
        y={cy - 2}
        textAnchor="middle"
        fontSize={size > 100 ? 18 : 14}
        fontWeight={700}
        fill="var(--v-text)"
      >
        {total}
      </text>
      <text
        x={cx}
        y={cy + (size > 100 ? 12 : 10)}
        textAnchor="middle"
        fontSize={size > 100 ? 8 : 7}
        fill="var(--v-text-muted)"
      >
        {innerLabel}
      </text>
    </svg>
  );
}
