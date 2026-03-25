import {
  BarChart as RechartsBar,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { useTheme } from "../utils/theme";
import { getColors } from "../utils/chartTheme";

interface Props {
  data: { endpoint: string; count: number }[];
}

function EditorialTooltip({ active, payload, label }: { active?: boolean; payload?: { value: number; name: string }[]; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-cream border border-warm-border px-3 py-2 text-sm font-sans shadow-sm">
      <p className="font-serif font-bold text-charcoal text-xs mb-1">{label}</p>
      {payload.map((entry, i) => (
        <p key={i} className="text-charcoal-light text-xs">
          {entry.name}: {entry.value}
        </p>
      ))}
    </div>
  );
}

export default function BarChartComponent({ data }: Props) {
  const { theme } = useTheme();
  const colors = getColors(theme);

  return (
    <ResponsiveContainer width="100%" height={300}>
      <RechartsBar data={data} margin={{ top: 10, right: 20, left: 0, bottom: 5 }}>
        <CartesianGrid strokeDasharray="2 4" stroke={colors.border} />
        <XAxis
          dataKey="endpoint"
          tick={{ fill: colors.muted, fontSize: 11, fontFamily: "IBM Plex Mono" }}
          axisLine={{ stroke: colors.border }}
          tickLine={false}
          interval={0}
          angle={-30}
          textAnchor="end"
          height={80}
        />
        <YAxis
          tick={{ fill: colors.muted, fontSize: 12, fontFamily: "IBM Plex Mono" }}
          axisLine={{ stroke: colors.border }}
          tickLine={false}
          allowDecimals={false}
        />
        <Tooltip content={<EditorialTooltip />} />
        <Bar
          dataKey="count"
          name="Count"
          fill={colors.terracotta}
          radius={[3, 3, 0, 0]}
          fillOpacity={0.9}
        />
      </RechartsBar>
    </ResponsiveContainer>
  );
}
