"use client";
import { useCallback, useEffect, useState } from "react";
import { RefreshCw, WifiOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { AuditTable } from "@/components/AuditTable";
import { api, type PaginatedAudit } from "@/lib/api";
import { cn } from "@/lib/utils";

export default function AuditPage() {
  const [data,    setData]    = useState<PaginatedAudit | null>(null);
  const [loading, setLoading] = useState(true);
  const [page,    setPage]    = useState(1);
  const [agentF,  setAgentF]  = useState("");
  const [toolF,   setToolF]   = useState("");
  const [statusF, setStatusF] = useState("");
  const [spinning, setSpinning] = useState(false);
  const [error,   setError]   = useState<string | null>(null);

  const fetchAudit = useCallback(async (p = page) => {
    setSpinning(true);
    try {
      const result = await api.audit({ page: p, limit: 25, status: statusF, agent: agentF, tool: toolF });
      setData(result);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Backend unreachable — retrying…");
    } finally { setLoading(false); setSpinning(false); }
  }, [page, statusF, agentF, toolF]);

  useEffect(() => { fetchAudit(page); }, [fetchAudit, page]);

  return (
    <div className="p-6 space-y-6">
      {error && (
        <div className="flex items-center gap-3 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          <WifiOff className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-zinc-100">Audit Log</h1>
          <p className="text-xs text-zinc-500">
            Full immutable ledger of every intercepted tool call
            {data ? ` · ${data.total} total records` : ""}
          </p>
        </div>
        <Button size="sm" variant="ghost" className="gap-2 text-zinc-500 hover:text-zinc-200"
          onClick={() => fetchAudit(page)}>
          <RefreshCw className={cn("h-3.5 w-3.5", spinning && "animate-spin")} />
          Refresh
        </Button>
      </div>

      <AuditTable
        data={data}
        loading={loading}
        page={page}
        onPage={(p) => { setPage(p); fetchAudit(p); }}
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
