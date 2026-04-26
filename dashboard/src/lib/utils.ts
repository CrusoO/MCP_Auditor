import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString("en-US", {
    month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: false,
  });
}

export function riskColor(score: number): string {
  if (score >= 0.9) return "text-red-400";
  if (score >= 0.7) return "text-orange-400";
  if (score >= 0.4) return "text-amber-400";
  return "text-emerald-400";
}

export function riskBg(score: number): string {
  if (score >= 0.9) return "bg-red-500/10 border-red-500/20 text-red-400";
  if (score >= 0.7) return "bg-orange-500/10 border-orange-500/20 text-orange-400";
  if (score >= 0.4) return "bg-amber-500/10 border-amber-500/20 text-amber-400";
  return "bg-emerald-500/10 border-emerald-500/20 text-emerald-400";
}

export function statusColor(status: string): string {
  switch (status?.toUpperCase()) {
    case "BLOCKED":  return "bg-red-500/10 border-red-500/30 text-red-400";
    case "ALLOWED":  return "bg-emerald-500/10 border-emerald-500/30 text-emerald-400";
    case "REDACTED": return "bg-amber-500/10 border-amber-500/30 text-amber-400";
    case "ERROR":    return "bg-orange-500/10 border-orange-500/30 text-orange-400";
    default:         return "bg-zinc-500/10 border-zinc-500/30 text-zinc-400";
  }
}

export function statusDot(status: string): string {
  switch (status?.toUpperCase()) {
    case "BLOCKED":  return "bg-red-400";
    case "ALLOWED":  return "bg-emerald-400";
    case "REDACTED": return "bg-amber-400";
    case "ERROR":    return "bg-orange-400";
    default:         return "bg-zinc-400";
  }
}
