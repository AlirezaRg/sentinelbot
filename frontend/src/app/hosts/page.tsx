"use client";

import { useQuery } from "@tanstack/react-query";
import { Empty, ErrorBox, Loading, PageHeader, Panel } from "@/components/ui";
import { apiGet } from "@/lib/api";
import { formatTime } from "@/lib/format";
import type { HostRecord, Page } from "@/lib/types";

export default function HostsPage() {
  const query = useQuery({
    queryKey: ["hosts"],
    queryFn: () => apiGet<Page<HostRecord>>("/api/v1/hosts", { limit: 200 }),
    refetchInterval: 30_000,
  });

  return (
    <>
      <PageHeader title="Hosts" />
      {query.error ? (
        <ErrorBox error={query.error} />
      ) : !query.data ? (
        <Loading />
      ) : (
        <Panel>
          {query.data.items.length === 0 ? (
            <Empty>No hosts have reported yet. Start the agent and send its events to the API.</Empty>
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-[var(--muted)]">
                <tr>
                  <th className="py-2 pr-3">Host</th>
                  <th className="py-2 pr-3">Events</th>
                  <th className="py-2 pr-3">Open incidents</th>
                  <th className="py-2 pr-3">First seen</th>
                  <th className="py-2 pr-3">Last seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)]">
                {query.data.items.map((host) => (
                  <tr key={host.host_id}>
                    <td className="py-2 pr-3 font-medium">{host.host_id}</td>
                    <td className="py-2 pr-3 tabular-nums">{host.event_count}</td>
                    <td className="py-2 pr-3 tabular-nums">
                      <span className={host.open_incidents > 0 ? "text-red-300" : ""}>{host.open_incidents}</span>
                    </td>
                    <td className="py-2 pr-3 text-[var(--muted)]">{formatTime(host.first_seen)}</td>
                    <td className="py-2 pr-3 text-[var(--muted)]">{formatTime(host.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      )}
    </>
  );
}
