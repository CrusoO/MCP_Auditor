"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldCheck, LayoutDashboard, ScrollText, FlaskConical, Github } from "lucide-react";
import { cn } from "@/lib/utils";

const nav = [
  { href: "/",        label: "Overview",      icon: LayoutDashboard },
  { href: "/audit",   label: "Audit Log",     icon: ScrollText },
  { href: "/policy",  label: "Policy Tester", icon: FlaskConical },
];

export function Sidebar() {
  const path = usePathname();

  return (
    <aside className="fixed inset-y-0 left-0 z-40 flex w-60 flex-col border-r border-zinc-800 bg-zinc-950">
      {/* Brand */}
      <div className="flex h-16 items-center gap-3 border-b border-zinc-800 px-5">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-red-500/20 ring-1 ring-red-500/40">
          <ShieldCheck className="h-4 w-4 text-red-400" />
        </div>
        <div>
          <p className="text-sm font-semibold text-zinc-100">AgentGuard</p>
          <p className="text-[10px] text-zinc-500">Zero-Trust Gateway</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-0.5 p-3">
        {nav.map(({ href, label, icon: Icon }) => {
          const active = path === href;
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                active
                  ? "bg-zinc-800 text-zinc-100"
                  : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200"
              )}
            >
              <Icon className={cn("h-4 w-4", active ? "text-red-400" : "text-zinc-500")} />
              {label}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="border-t border-zinc-800 p-4">
        <div className="flex items-center gap-2 text-xs text-zinc-600">
          <div className="h-1.5 w-1.5 animate-pulse-slow rounded-full bg-emerald-400" />
          <span>Gateway live</span>
        </div>
        <a
          href="http://localhost:8000/docs"
          target="_blank"
          rel="noreferrer"
          className="mt-2 flex items-center gap-2 text-xs text-zinc-600 hover:text-zinc-400 transition-colors"
        >
          <Github className="h-3 w-3" />
          API Docs
        </a>
      </div>
    </aside>
  );
}
