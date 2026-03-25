import {
  PieChart as RechartsPie,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { useTheme } from "../utils/theme";
import { getColors, getStatusColors, getChartColors, getSeverityColors } from "../utils/chartTheme";

interface Props {
  data: { status: string; count: number }[];
  colorMap?: "status" | "severity";
}

function EditorialTooltip({ active, payload }: { active?: boolean; payload?: { name: string; value: number }[] }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-cream border border-warm-border px-3 py-2 text-sm font-sans shadow-sm">
      {payload.map((entry, i) => (
        <p key={i} className="text-charcoal-light text-xs">
          {entry.name}: {entry.value}
        </p>
      ))}
    </div>
  );
}

export default function PieChartComponent({ data, colorMap }: Props) {
  const { theme } = useTheme();
  const colors = getColors(theme);
  const statusColors = getStatusColors(theme);
  const sevColors = getSeverityColors(theme);
  const chartColors = getChartColors(theme);

  function getColor(key: string, index: number): string {
    if (colorMap === "severity") return sevColors[key] || chartColors[index % chartColors.length];
    if (colorMap === "status") return statusColors[key] || chartColors[index % chartColors.length];
    return chartColors[index % chartColors.length];
  }

  return (
    <ResponsiveContainer width="100%" height={300}>
      <RechartsPie>
        <Pie
          data={data}
          dataKey="count"
          nameKey="status"
          cx="50%"
          cy="50%"
          innerRadius={65}
          outerRadius={105}
          paddingAngle={2}
          strokeWidth={0}
        >
          {data.map((entry, index) => (
            <Cell key={entry.status} fill={getColor(entry.status, index)} />
          ))}
        </Pie>
        <Tooltip content={<EditorialTooltip />} />
        <Legend
          formatter={(value: string) => (
            <span style={{ color: colors.charcoal, fontFamily: "IBM Plex Mono", fontSize: 12 }}>
              {value}
            </span>
          )}
        />
      </RechartsPie>
    </ResponsiveContainer>
  );
}
