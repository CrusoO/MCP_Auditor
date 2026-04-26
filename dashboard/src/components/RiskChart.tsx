"use client";
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis,
  Tooltip, CartesianGrid, ReferenceLine,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import type { RiskPoint } from "@/lib/api";

interface Props { data: RiskPoint[]; loading: boolean }

const STATUS_COLORS: Record<string, string> = {
  BLOCKED:  "#f87171",
  REDACTED: "#fbbf24",
  ALLOWED:  "#34d399",
  ERROR:    "#fb923c",
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const CustomTooltip = ({ active, payload }: any) => {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload as RiskPoint;
  const color = STATUS_COLORS[d.status] ?? "#a1a1aa";
  return (
    <div className="rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-xs shadow-xl">
      <p className="font-mono text-zinc-400">{new Date(d.timestamp).toLocaleTimeString()}</p>
      <p className="mt-1 font-semibold" style={{ color }}>
        {d.status} · {d.tool_name}
      </p>
      <p className="mt-0.5 tabular-nums text-zinc-300">
        Risk: <span className="font-bold">{d.risk_score.toFixed(3)}</span>
      </p>
    </div>
  );
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const CustomDot = (props: any) => {
  const { cx, cy, payload } = props;
  const color = STATUS_COLORS[(payload as RiskPoint).status] ?? "#a1a1aa";
  if ((payload as RiskPoint).risk_score < 0.05) return null;
  return <circle cx={cx} cy={cy} r={3} fill={color} stroke="transparent" />;
};

export function RiskChart({ data, loading }: Props) {
  return (
    <Card className="border-zinc-800 bg-zinc-900">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm text-zinc-300">Risk Score Timeline</CardTitle>
        <p className="text-xs text-zinc-600">Last {data.length} intercepted calls</p>
      </CardHeader>
      <CardContent className="p-4 pt-0">
        {loading ? (
          <Skeleton className="h-40 w-full" />
        ) : data.length === 0 ? (
          <div className="flex h-40 items-center justify-center text-sm text-zinc-600">
            No data yet — make some tool calls.
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={160}>
            <AreaChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
              <defs>
                <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f87171" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#f87171" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
              <XAxis dataKey="timestamp" hide />
              <YAxis domain={[0, 1]} tickCount={3} tick={{ fontSize: 10, fill: "#52525b" }} />
              <Tooltip content={<CustomTooltip />} />
              <ReferenceLine y={0.7} stroke="#f97316" strokeDasharray="4 2" strokeWidth={1} />
              <Area
                type="monotone"
                dataKey="risk_score"
                stroke="#f87171"
                strokeWidth={1.5}
                fill="url(#riskGrad)"
                dot={<CustomDot />}
                activeDot={{ r: 4, fill: "#f87171" }}
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
