"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";
import { Empty, ErrorBox, Loading, PageHeader, Pager, Panel, SeverityBadge, StatusBadge, inputClass } from "@/components/ui";
import { apiGet } from "@/lib/api";
import { formatTime } from "@/lib/format";
import type { Incident, Page } from "@/lib/types";

const LIMIT = 25;

export default function IncidentsPage() {
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [sort, setSort] = useState("last_seen");
  const [offset, setOffset] = useState(0);

  const query = useQuery({
    queryKey: ["incidents", { status, severity, sort, offset }],
    queryFn: () =>
      apiGet<Page<Incident>>("/api/v1/incidents", {
        status: status || undefined,
        severity: severity || undefined,
        sort,
        order: "desc",
        limit: LIMIT,
        offset,
      }),
    refetchInterval: 15_000,
  });

  return (
    <>
      <PageHeader title="Incidents" />
      <div className="mb-4 flex flex-wrap gap-3">
        <select aria-label="Status" className={inputClass} value={status} onChange={(e) => { setStatus(e.target.value); setOffset(0); }}>
          <option value="">Any status</option>
          <option value="OPEN">Open</option>
          <option value="INVESTIGATING">Investigating</option>
          <option value="RESOLVED">Resolved</option>
          <option value="FALSE_POSITIVE">False positive</option>
        </select>
        <select aria-label="Severity" className={inputClass} value={severity} onChange={(e) => { setSeverity(e.target.value); setOffset(0); }}>
          <option value="">Any severity</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <select aria-label="Sort" className={inputClass} value={sort} onChange={(e) => setSort(e.target.value)}>
          <option value="last_seen">Most recent</option>
          <option value="risk_score">Highest risk</option>
          <option value="event_count">Most detections</option>
        </select>
      </div>

      {query.error ? (
        <ErrorBox error={query.error} />
      ) : !query.data ? (
        <Loading />
      ) : (
        <Panel>
          {query.data.items.length === 0 ? (
            <Empty>No incidents match these filters.</Empty>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs uppercase text-[var(--muted)]">
                  <tr>
                    <th className="py-2 pr-3">Severity</th>
                    <th className="py-2 pr-3">Incident</th>
                    <th className="py-2 pr-3">Host</th>
                    <th className="py-2 pr-3">Risk</th>
                    <th className="py-2 pr-3">Status</th>
                    <th className="py-2 pr-3">Last seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border)]">
                  {query.data.items.map((incident) => (
                    <tr key={incident.incident_id} className="hover:bg-[var(--surface-raised)]">
                      <td className="py-2 pr-3"><SeverityBadge severity={incident.severity} /></td>
                      <td className="py-2 pr-3">
                        <Link href={`/incidents/${incident.incident_id}`} className="hover:underline">
                          {incident.title}
                        </Link>
                      </td>
                      <td className="py-2 pr-3">{incident.host_id}</td>
                      <td className="py-2 pr-3 tabular-nums">{incident.risk_score}</td>
                      <td className="py-2 pr-3"><StatusBadge status={incident.status} /></td>
                      <td className="py-2 pr-3 text-[var(--muted)]">{formatTime(incident.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <Pager total={query.data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
        </Panel>
      )}
    </>
  );
}
