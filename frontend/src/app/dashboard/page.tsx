"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { Bar, BarChart, Cell, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ErrorBox, Loading, PageHeader, Panel, SeverityBadge, StatCard, StatusBadge } from "@/components/ui";
import { apiGet } from "@/lib/api";
import { SEVERITY_COLOR, formatCount, formatDuration, formatTime } from "@/lib/format";
import type { Incident, Metrics, Page, SystemStatus } from "@/lib/types";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export default function DashboardPage() {
  const metrics = useQuery({
    queryKey: ["metrics"],
    queryFn: () => apiGet<Metrics>("/api/v1/metrics"),
    refetchInterval: 15_000,
  });
  const status = useQuery({
    queryKey: ["system-status"],
    queryFn: () => apiGet<SystemStatus>("/api/v1/system/status"),
    refetchInterval: 30_000,
  });
  const open = useQuery({
    queryKey: ["incidents", "recent-open"],
    queryFn: () => apiGet<Page<Incident>>("/api/v1/incidents", { status: "OPEN", limit: 5 }),
    refetchInterval: 15_000,
  });

  const error = metrics.error ?? status.error ?? open.error;
  if (error) return <ErrorBox error={error} />;
  if (!metrics.data || !status.data || !open.data) return <Loading />;

  const bySeverity = SEVERITY_ORDER.map((severity) => ({
    severity,
    count: metrics.data.events_by_severity[severity] ?? 0,
  }));
  const openCount = metrics.data.incidents_by_status.OPEN ?? 0;
  const criticalOpen = open.data.items.filter((i) => i.severity === "critical").length;

  return (
    <>
      <PageHeader title="Dashboard">
        <p className="text-xs text-[var(--muted)]">
          Refreshes every 15 s · {status.data.persistence} storage · up{" "}
          {formatDuration(status.data.uptime_seconds)}
        </p>
      </PageHeader>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Open incidents" value={formatCount(openCount)} tone={openCount > 0 ? "danger" : "ok"} />
        <StatCard label="Critical (open)" value={formatCount(criticalOpen)} tone={criticalOpen > 0 ? "danger" : "neutral"} />
        <StatCard label="Events stored" value={formatCount(metrics.data.events_stored)} />
        <StatCard label="Incidents total" value={formatCount(metrics.data.incidents_total)} />
      </div>

      <div className="mt-6 grid gap-4 xl:grid-cols-3">
        <Panel title="Events by severity" className="xl:col-span-1">
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={bySeverity}>
                <CartesianGrid stroke="#223041" vertical={false} />
                <XAxis dataKey="severity" stroke="#8b98a8" />
                <YAxis stroke="#8b98a8" allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#17202b", border: "1px solid #223041" }} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {bySeverity.map((row) => (
                    <Cell key={row.severity} fill={SEVERITY_COLOR[row.severity]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel title="Open incidents" className="xl:col-span-2">
          {open.data.items.length === 0 ? (
            <p className="py-8 text-center text-sm text-[var(--muted)]">No open incidents.</p>
          ) : (
            <ul className="divide-y divide-[var(--border)]">
              {open.data.items.map((incident) => (
                <li key={incident.incident_id} className="flex flex-wrap items-center gap-3 py-3">
                  <SeverityBadge severity={incident.severity} />
                  <Link href={`/incidents/${incident.incident_id}`} className="min-w-0 flex-1 truncate text-sm hover:underline">
                    {incident.title}
                  </Link>
                  <StatusBadge status={incident.status} />
                  <span className="text-xs text-[var(--muted)]">{formatTime(incident.last_seen)}</span>
                </li>
              ))}
            </ul>
          )}
          <p className="mt-3 text-right text-sm">
            <Link href="/incidents" className="text-sky-300 hover:underline">
              All incidents →
            </Link>
          </p>
        </Panel>
      </div>
    </>
  );
}
