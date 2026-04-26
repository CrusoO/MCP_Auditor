"use client";
import { ShieldX, ShieldCheck, Eye, AlertTriangle, Activity, TrendingUp } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import type { Stats } from "@/lib/api";

interface Props { stats: Stats | null; loading: boolean }

export function StatsCards({ stats, loading }: Props) {
  const cards = [
    {
      label: "Total Calls",
      value: stats?.total_calls ?? 0,
      sub: "all time",
      icon: Activity,
      color: "text-blue-400",
      ring: "ring-blue-500/20 bg-blue-500/10",
    },
    {
      label: "Blocked",
      value: stats?.blocked ?? 0,
      sub: `${stats?.block_rate ?? 0}% block rate`,
      icon: ShieldX,
      color: "text-red-400",
      ring: "ring-red-500/20 bg-red-500/10",
    },
    {
      label: "Redacted",
      value: stats?.redacted ?? 0,
      sub: "secrets stripped",
      icon: Eye,
      color: "text-amber-400",
      ring: "ring-amber-500/20 bg-amber-500/10",
    },
    {
      label: "Allowed",
      value: stats?.allowed ?? 0,
      sub: "clean calls",
      icon: ShieldCheck,
      color: "text-emerald-400",
      ring: "ring-emerald-500/20 bg-emerald-500/10",
    },
    {
      label: "High Risk",
      value: stats?.high_risk_count ?? 0,
      sub: "score ≥ 0.7",
      icon: AlertTriangle,
      color: "text-orange-400",
      ring: "ring-orange-500/20 bg-orange-500/10",
    },
    {
      label: "Avg Risk Score",
      value: stats?.avg_risk_score?.toFixed(3) ?? "0.000",
      sub: "across all calls",
      icon: TrendingUp,
      color: "text-purple-400",
      ring: "ring-purple-500/20 bg-purple-500/10",
      isFloat: true,
    },
  ];

  return (
    <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 xl:grid-cols-6">
      {cards.map(({ label, value, sub, icon: Icon, color, ring }) => (
        <Card key={label} className="border-zinc-800 bg-zinc-900">
          <CardContent className="p-4">
            {loading ? (
              <div className="space-y-2">
                <Skeleton className="h-4 w-20" />
                <Skeleton className="h-8 w-16" />
                <Skeleton className="h-3 w-24" />
              </div>
            ) : (
              <>
                <div className={`mb-3 inline-flex h-8 w-8 items-center justify-center rounded-lg ring-1 ${ring}`}>
                  <Icon className={`h-4 w-4 ${color}`} />
                </div>
                <p className={`text-2xl font-bold tabular-nums ${color}`}>{value}</p>
                <p className="mt-0.5 text-xs text-zinc-500">{label}</p>
                <p className="text-[10px] text-zinc-600">{sub}</p>
              </>
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
