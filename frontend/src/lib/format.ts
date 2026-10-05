import type { IncidentStatus, Severity } from "@/lib/types";

export function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatCount(value: number): string {
  return new Intl.NumberFormat().format(value);
}

export function formatDuration(seconds: number): string {
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

// Colours are paired with text labels everywhere, so colour is never the only signal.
export const SEVERITY_STYLE: Record<Severity, string> = {
  info: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
  low: "bg-sky-500/15 text-sky-300 ring-sky-500/30",
  medium: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
  high: "bg-orange-500/20 text-orange-300 ring-orange-500/40",
  critical: "bg-red-500/20 text-red-300 ring-red-500/50",
};

export const STATUS_STYLE: Record<IncidentStatus, string> = {
  OPEN: "bg-red-500/15 text-red-300 ring-red-500/30",
  INVESTIGATING: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
  RESOLVED: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
  FALSE_POSITIVE: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
};

export const SEVERITY_COLOR: Record<Severity, string> = {
  info: "#64748b",
  low: "#38bdf8",
  medium: "#f59e0b",
  high: "#f97316",
  critical: "#ef4444",
};
