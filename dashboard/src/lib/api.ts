// All calls go through Next.js rewrites → /api/* is proxied to the backend.
// This works in both Docker and local dev with zero config changes.
const BASE = "/api";

export interface Stats {
  total_calls: number;
  blocked: number;
  allowed: number;
  redacted: number;
  error: number;
  avg_risk_score: number;
  high_risk_count: number;
  block_rate: number;
}

export interface Handshake {
  id: string;
  timestamp: string;
  agent_identity: string;
  tool_name: string;
  status: string;
  risk_score: number;
  reasoning: string | null;
  latency_ms: number | null;
  session_id: string | null;
  input_payload: Record<string, unknown>;
  output_payload: Record<string, unknown> | null;
}

export interface PaginatedAudit {
  items: Handshake[];
  total: number;
  page: number;
  pages: number;
  limit: number;
}

export interface AgentStat {
  agent_identity: string;
  total_calls: number;
  blocked_calls: number;
  avg_risk_score: number;
  block_rate: number;
}

export interface RiskPoint {
  timestamp: string;
  risk_score: number;
  status: string;
  tool_name: string;
}

export interface PolicyDecision {
  action: "ALLOW" | "BLOCK" | "REDACT";
  reason: string;
  risk_score: number;
  triggered_rules: string[];
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export const api = {
  stats: () => get<Stats>("/v1/dashboard/stats"),

  audit: (params: {
    page?: number;
    limit?: number;
    status?: string;
    agent?: string;
    tool?: string;
  }) => {
    const q = new URLSearchParams();
    if (params.page)   q.set("page",   String(params.page));
    if (params.limit)  q.set("limit",  String(params.limit));
    if (params.status) q.set("status", params.status);
    if (params.agent)  q.set("agent",  params.agent);
    if (params.tool)   q.set("tool",   params.tool);
    return get<PaginatedAudit>(`/v1/dashboard/audit?${q}`);
  },

  agents: (limit = 10) =>
    get<AgentStat[]>(`/v1/dashboard/agents?limit=${limit}`),

  riskTrend: (limit = 60) =>
    get<RiskPoint[]>(`/v1/dashboard/risk-trend?limit=${limit}`),

  evaluatePolicy: async (body: {
    tool_name: string;
    tool_args: Record<string, unknown>;
    user_intent: string;
  }): Promise<PolicyDecision> => {
    const r = await fetch(`${BASE}/v1/policy/evaluate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      let msg = `${r.status} ${r.statusText}`;
      try {
        const e = await r.json();
        if (typeof e?.detail === "string") msg = e.detail;
        else if (typeof e === "string") msg = e;
        else msg = JSON.stringify(e);
      } catch { /* use HTTP status as fallback */ }
      throw new Error(msg);
    }
    return r.json() as Promise<PolicyDecision>;
  },
};
