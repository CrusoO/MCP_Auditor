"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { RefreshCw, WifiOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { StatsCards } from "@/components/StatsCards";
import { RiskChart } from "@/components/RiskChart";
import { AuditTable } from "@/components/AuditTable";
import { api, type Stats, type PaginatedAudit, type RiskPoint } from "@/lib/api";
import { cn } from "@/lib/utils";

const REFRESH_MS = 8_000;

export default function DashboardPage() {
  const [stats,    setStats]    = useState<Stats | null>(null);
  const [trend,    setTrend]    = useState<RiskPoint[]>([]);
  const [audit,    setAudit]    = useState<PaginatedAudit | null>(null);
  const [loadingS, setLoadingS] = useState(true);
  const [loadingA, setLoadingA] = useState(true);
  const [page,     setPage]     = useState(1);
  const [agentF,   setAgentF]   = useState("");
  const [toolF,    setToolF]    = useState("");
  const [statusF,  setStatusF]  = useState("");
  const [spinning, setSpinning] = useState(false);
  const [error,    setError]    = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchAll = useCallback(async (p = page) => {
    setSpinning(true);
    try {
      const [s, t, a] = await Promise.all([
        api.stats(),
        api.riskTrend(60),
        api.audit({ page: p, limit: 15, status: statusF, agent: agentF, tool: toolF }),
      ]);
      setStats(s);
      setTrend(t);
      setAudit(a);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Backend unreachable — retrying…");
    } finally {
      setLoadingS(false);
      setLoadingA(false);
      setSpinning(false);
    }
  }, [page, statusF, agentF, toolF]);

  useEffect(() => {
    fetchAll(page);
    timer.current = setInterval(() => fetchAll(page), REFRESH_MS);
    return () => { if (timer.current) clearInterval(timer.current); };
  }, [fetchAll, page]);

  return (
    <div className="p-6 space-y-6">
      {/* Error banner */}
      {error && (
        <div className="flex items-center gap-3 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          <WifiOff className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-zinc-100">Overview</h1>
          <p className="text-xs text-zinc-500">Live governance metrics · auto-refreshes every {REFRESH_MS / 1000}s</p>
        </div>
        <Button
          size="sm" variant="ghost"
          className="gap-2 text-zinc-500 hover:text-zinc-200"
          onClick={() => fetchAll(page)}
        >
          <RefreshCw className={cn("h-3.5 w-3.5", spinning && "animate-spin")} />
          Refresh
        </Button>
      </div>

      {/* Stats row */}
      <StatsCards stats={stats} loading={loadingS} />

      {/* Risk timeline */}
      <RiskChart data={trend} loading={loadingS} />

      {/* Recent calls table */}
      <AuditTable
        data={audit}
        loading={loadingA}
        page={page}
        onPage={(p) => { setPage(p); fetchAll(p); }}
        agentFilter={agentF}
        toolFilter={toolF}
        statusFilter={statusF}
        onAgentFilter={setAgentF}
        onToolFilter={setToolF}
        onStatusFilter={setStatusF}
      />
    </div>
  );
}
