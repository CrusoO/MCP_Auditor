"use client";
import { useState } from "react";
import { ChevronLeft, ChevronRight, Search, Eye } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { cn, formatDate, statusColor, statusDot, riskColor } from "@/lib/utils";
import type { Handshake, PaginatedAudit } from "@/lib/api";

interface Props {
  data: PaginatedAudit | null;
  loading: boolean;
  page: number;
  onPage: (p: number) => void;
  agentFilter: string;
  toolFilter: string;
  statusFilter: string;
  onAgentFilter: (v: string) => void;
  onToolFilter: (v: string) => void;
  onStatusFilter: (v: string) => void;
}

const STATUSES = ["", "BLOCKED", "ALLOWED", "REDACTED", "ERROR"];

function DetailModal({ row, onClose }: { row: Handshake; onClose: () => void }) {
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="border-zinc-800 bg-zinc-950 text-zinc-100 max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-zinc-100">
            <span className={cn("inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-semibold", statusColor(row.status))}>
              <span className={cn("h-1.5 w-1.5 rounded-full", statusDot(row.status))} />
              {row.status}
            </span>
            <span className="font-mono text-sm">{row.tool_name}</span>
          </DialogTitle>
        </DialogHeader>

        <div className="grid gap-4 text-sm">
          <Row label="ID"             value={row.id} mono />
          <Row label="Timestamp"      value={formatDate(row.timestamp)} />
          <Row label="Agent Identity" value={row.agent_identity} mono />
          <Row label="Session"        value={row.session_id ?? "—"} mono />
          <Row label="Risk Score"     value={
            <span className={riskColor(row.risk_score)}>{row.risk_score.toFixed(4)}</span>
          } />
          <Row label="Latency"        value={row.latency_ms ? `${row.latency_ms.toFixed(1)} ms` : "—"} />

          {row.reasoning && (
            <div>
              <p className="mb-1 text-xs text-zinc-500">Reasoning</p>
              <pre className="whitespace-pre-wrap rounded-md border border-zinc-800 bg-zinc-900 p-3 font-mono text-xs text-zinc-300 leading-relaxed">
                {row.reasoning}
              </pre>
            </div>
          )}

          <div>
            <p className="mb-1 text-xs text-zinc-500">Input Payload (redacted)</p>
            <pre className="rounded-md border border-zinc-800 bg-zinc-900 p-3 font-mono text-xs text-zinc-300 overflow-x-auto">
              {JSON.stringify(row.input_payload, null, 2)}
            </pre>
          </div>

          {row.output_payload && (
            <div>
              <p className="mb-1 text-xs text-zinc-500">Output Payload (masked)</p>
              <pre className="rounded-md border border-zinc-800 bg-zinc-900 p-3 font-mono text-xs text-zinc-300 overflow-x-auto">
                {JSON.stringify(row.output_payload, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

function Row({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex gap-3">
      <span className="w-32 shrink-0 text-xs text-zinc-500">{label}</span>
      <span className={cn("text-xs text-zinc-300 break-all", mono && "font-mono")}>{value}</span>
    </div>
  );
}

export function AuditTable({
  data, loading, page, onPage,
  agentFilter, toolFilter, statusFilter,
  onAgentFilter, onToolFilter, onStatusFilter,
}: Props) {
  const [detail, setDetail] = useState<Handshake | null>(null);

  return (
    <>
      {detail && <DetailModal row={detail} onClose={() => setDetail(null)} />}

      <Card className="border-zinc-800 bg-zinc-900">
        <CardHeader className="pb-3">
          <div className="flex flex-wrap items-center gap-2">
            <CardTitle className="text-sm text-zinc-300 mr-auto">Audit Records</CardTitle>

            {/* Status filter chips */}
            <div className="flex gap-1">
              {STATUSES.map((s) => (
                <button
                  key={s || "all"}
                  onClick={() => { onStatusFilter(s); onPage(1); }}
                  className={cn(
                    "rounded-md px-2.5 py-1 text-xs font-medium transition-colors border",
                    statusFilter === s
                      ? s ? statusColor(s) : "border-zinc-600 bg-zinc-700 text-zinc-200"
                      : "border-zinc-800 text-zinc-500 hover:border-zinc-700 hover:text-zinc-400"
                  )}
                >
                  {s || "ALL"}
                </button>
              ))}
            </div>

            {/* Search inputs */}
            <div className="relative">
              <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-zinc-500" />
              <Input
                value={agentFilter}
                onChange={(e) => { onAgentFilter(e.target.value); onPage(1); }}
                placeholder="Agent…"
                className="h-7 w-36 border-zinc-700 bg-zinc-950 pl-7 text-xs text-zinc-300 placeholder:text-zinc-600"
              />
            </div>
            <div className="relative">
              <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-zinc-500" />
              <Input
                value={toolFilter}
                onChange={(e) => { onToolFilter(e.target.value); onPage(1); }}
                placeholder="Tool…"
                className="h-7 w-32 border-zinc-700 bg-zinc-950 pl-7 text-xs text-zinc-300 placeholder:text-zinc-600"
              />
            </div>
          </div>
        </CardHeader>

        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-zinc-800">
                  {["Time", "Agent", "Tool", "Status", "Risk", "Latency", ""].map((h) => (
                    <th key={h} className="px-4 py-2.5 text-left font-medium text-zinc-500">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {loading
                  ? Array.from({ length: 8 }).map((_, i) => (
                      <tr key={i} className="border-b border-zinc-800/50">
                        {Array.from({ length: 7 }).map((_, j) => (
                          <td key={j} className="px-4 py-3">
                            <Skeleton className="h-3 w-full" />
                          </td>
                        ))}
                      </tr>
                    ))
                  : data?.items.length === 0
                  ? (
                    <tr>
                      <td colSpan={7} className="py-16 text-center text-zinc-600">
                        No records found.
                      </td>
                    </tr>
                  )
                  : data?.items.map((row) => (
                    <tr
                      key={row.id}
                      className="border-b border-zinc-800/50 transition-colors hover:bg-zinc-800/40 cursor-pointer"
                      onClick={() => setDetail(row)}
                    >
                      <td className="px-4 py-3 font-mono text-zinc-500 whitespace-nowrap">
                        {formatDate(row.timestamp)}
                      </td>
                      <td className="px-4 py-3 font-mono text-zinc-400 max-w-[140px] truncate">
                        {row.agent_identity}
                      </td>
                      <td className="px-4 py-3 font-mono text-zinc-300">{row.tool_name}</td>
                      <td className="px-4 py-3">
                        <span className={cn(
                          "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-semibold",
                          statusColor(row.status)
                        )}>
                          <span className={cn("h-1.5 w-1.5 rounded-full", statusDot(row.status))} />
                          {row.status}
                        </span>
                      </td>
                      <td className={cn("px-4 py-3 font-mono font-semibold tabular-nums", riskColor(row.risk_score))}>
                        {row.risk_score.toFixed(3)}
                      </td>
                      <td className="px-4 py-3 text-zinc-600 tabular-nums">
                        {row.latency_ms ? `${row.latency_ms.toFixed(0)}ms` : "—"}
                      </td>
                      <td className="px-4 py-3">
                        <Eye className="h-3.5 w-3.5 text-zinc-600 hover:text-zinc-400" />
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {data && data.total > 0 && (
            <div className="flex items-center justify-between border-t border-zinc-800 px-4 py-3">
              <span className="text-xs text-zinc-600">
                {data.total} record{data.total !== 1 ? "s" : ""} · page {data.page}/{data.pages}
              </span>
              <div className="flex gap-1">
                <Button
                  size="sm" variant="ghost"
                  className="h-7 w-7 p-0 text-zinc-500 hover:text-zinc-200"
                  disabled={page <= 1}
                  onClick={() => onPage(page - 1)}
                >
                  <ChevronLeft className="h-4 w-4" />
                </Button>
                <Button
                  size="sm" variant="ghost"
                  className="h-7 w-7 p-0 text-zinc-500 hover:text-zinc-200"
                  disabled={page >= (data.pages ?? 1)}
                  onClick={() => onPage(page + 1)}
                >
                  <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </>
  );
}
