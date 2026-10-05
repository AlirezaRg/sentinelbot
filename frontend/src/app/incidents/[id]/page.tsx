"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useParams } from "next/navigation";
import { ErrorBox, Loading, PageHeader, Panel, SeverityBadge, StatCard, StatusBadge } from "@/components/ui";
import { apiGet, apiPost } from "@/lib/api";
import { formatTime } from "@/lib/format";
import type { Analysis, Incident, IncidentStatus } from "@/lib/types";

export default function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();

  const incident = useQuery({
    queryKey: ["incident", id],
    queryFn: () => apiGet<Incident>(`/api/v1/incidents/${id}`),
    refetchInterval: 15_000,
  });

  // The analysis is computed on demand and is not stored, so it is requested only when shown.
  const analysis = useQuery({
    queryKey: ["incident-analysis", id],
    queryFn: () => apiGet<Analysis>(`/api/v1/incidents/${id}/analysis`),
    enabled: incident.isSuccess,
    staleTime: 5 * 60_000,
  });

  const resolve = useMutation({
    mutationFn: (resolution: "RESOLVED" | "FALSE_POSITIVE") =>
      apiPost<Incident>(`/api/v1/incidents/${id}/resolve`, { resolution }),
    onSuccess: (updated) => {
      queryClient.setQueryData(["incident", id], updated);
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
    },
  });

  if (incident.error) return <ErrorBox error={incident.error} />;
  if (!incident.data) return <Loading />;
  const item = incident.data;
  const closed: IncidentStatus[] = ["RESOLVED", "FALSE_POSITIVE"];
  const isClosed = closed.includes(item.status);

  return (
    <>
      <p className="mb-2 text-sm">
        <Link href="/incidents" className="text-sky-300 hover:underline">← Incidents</Link>
      </p>
      <PageHeader title={item.title}>
        <div className="flex items-center gap-2">
          <SeverityBadge severity={item.severity} />
          <StatusBadge status={item.status} />
        </div>
      </PageHeader>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Risk score" value={`${item.risk_score}/100`} tone={item.risk_score >= 80 ? "danger" : "neutral"} />
        <StatCard label="Detections" value={item.event_count} />
        <StatCard label="Host" value={item.host_id} />
        <StatCard label="Source" value={item.source_ip ?? "—"} />
      </div>

      <div className="mt-6 grid gap-4 xl:grid-cols-3">
        <Panel title="Timeline" className="xl:col-span-2">
          <ol className="space-y-3 text-sm">
            <li><span className="text-[var(--muted)]">First seen</span> · {formatTime(item.first_seen)}</li>
            <li><span className="text-[var(--muted)]">Last seen</span> · {formatTime(item.last_seen)}</li>
            <li><span className="text-[var(--muted)]">Rules</span> · {item.rules.join(", ") || "—"}</li>
            <li><span className="text-[var(--muted)]">Accounts</span> · {item.usernames.join(", ") || "—"}</li>
          </ol>
          <p className="mt-4 text-sm text-[var(--muted)]">{item.description}</p>
        </Panel>

        <Panel title="Actions">
          <ul className="mb-4 list-disc space-y-2 pl-5 text-sm">
            {item.recommended_actions.map((action) => (
              <li key={action}>{action}</li>
            ))}
          </ul>
          <div className="flex flex-col gap-2">
            <button
              type="button"
              disabled={isClosed || resolve.isPending}
              onClick={() => resolve.mutate("RESOLVED")}
              className="rounded-md bg-emerald-600/80 px-3 py-2 text-sm font-medium disabled:opacity-40"
            >
              Mark resolved
            </button>
            <button
              type="button"
              disabled={isClosed || resolve.isPending}
              onClick={() => resolve.mutate("FALSE_POSITIVE")}
              className="rounded-md border border-[var(--border)] px-3 py-2 text-sm disabled:opacity-40"
            >
              Mark false positive
            </button>
            {resolve.error && <ErrorBox error={resolve.error} />}
          </div>
        </Panel>
      </div>

      <div className="mt-6">
        <Panel title="AI analysis (explanation only; it does not act on the host)">
          {analysis.error ? (
            <ErrorBox error={analysis.error} />
          ) : !analysis.data ? (
            <Loading label="Analysing…" />
          ) : (
            <div className="grid gap-5 text-sm md:grid-cols-2">
              <div className="space-y-3">
                <p>{analysis.data.summary}</p>
                <p className="text-[var(--muted)]">{analysis.data.severity_assessment}</p>
                <p>
                  <span className="text-[var(--muted)]">Confidence</span>{" "}
                  <span className="tabular-nums">{Math.round(analysis.data.confidence * 100)}%</span> ·{" "}
                  {analysis.data.confidence_note}
                </p>
                <p className="text-xs text-[var(--muted)]">
                  Provider: {analysis.data.provider}
                  {analysis.data.fallback_reason ? ` (fallback: ${analysis.data.fallback_reason})` : ""}
                </p>
              </div>
              <div className="space-y-3">
                <Block title="Evidence" items={analysis.data.evidence} />
                <Block title="Possible false positives" items={analysis.data.false_positive_explanations} />
                <Block title="Investigate" items={analysis.data.investigation_steps} />
                <Block title="Remediation (after confirmation)" items={analysis.data.remediation} />
              </div>
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}

function Block({ title, items }: { title: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <div>
      <p className="mb-1 text-xs uppercase tracking-wide text-[var(--muted)]">{title}</p>
      <ul className="list-disc space-y-1 pl-5">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </div>
  );
}
