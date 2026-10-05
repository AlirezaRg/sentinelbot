"use client";

import { useQuery } from "@tanstack/react-query";
import { Empty, ErrorBox, Loading, PageHeader, Panel, StatCard } from "@/components/ui";
import { apiGet } from "@/lib/api";
import { formatTime } from "@/lib/format";
import type { EventRecord, ListeningPort, Page } from "@/lib/types";

interface NetworkMetadata {
  listening_ports?: ListeningPort[];
  connection_count?: number;
  listening_port_count?: number;
}

export default function NetworkPage() {
  // The latest network snapshot per host carries the listening ports and connection count.
  const query = useQuery({
    queryKey: ["network-snapshot"],
    queryFn: () =>
      apiGet<Page<EventRecord>>("/api/v1/events", {
        event_type: "network_snapshot",
        order: "desc",
        limit: 1,
      }),
    refetchInterval: 30_000,
  });

  if (query.error) return <ErrorBox error={query.error} />;
  if (!query.data) return <Loading />;

  const latest = query.data.items[0];
  const meta = (latest?.metadata ?? {}) as NetworkMetadata;
  const ports = meta.listening_ports ?? [];

  return (
    <>
      <PageHeader title="Network" />
      {!latest ? (
        <Empty>No network snapshot yet.</Empty>
      ) : (
        <>
          <p className="mb-4 text-sm text-[var(--muted)]">
            Host {latest.host_id} · snapshot at {formatTime(latest.timestamp)}
          </p>
          <div className="grid gap-4 sm:grid-cols-2">
            <StatCard label="Listening sockets" value={meta.listening_port_count ?? ports.length} />
            <StatCard label="Active connections" value={meta.connection_count ?? 0} />
          </div>
          <div className="mt-6">
            <Panel title="Listening ports">
              <table className="w-full text-left text-sm">
                <thead className="text-xs uppercase text-[var(--muted)]">
                  <tr>
                    <th className="py-2 pr-3">Protocol</th>
                    <th className="py-2 pr-3">Port</th>
                    <th className="py-2 pr-3">Address</th>
                    <th className="py-2 pr-3">Process</th>
                    <th className="py-2 pr-3">PID</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border)]">
                  {ports.map((port) => (
                    <tr key={`${port.protocol}-${port.local_port}-${port.local_address}`}>
                      <td className="py-2 pr-3 uppercase">{port.protocol}</td>
                      <td className="py-2 pr-3 tabular-nums">{port.local_port ?? "—"}</td>
                      <td className="py-2 pr-3 font-mono text-xs">{port.local_address ?? "—"}</td>
                      <td className="py-2 pr-3">{port.process ?? "—"}</td>
                      <td className="py-2 pr-3 tabular-nums">{port.pid ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
          </div>
        </>
      )}
    </>
  );
}
