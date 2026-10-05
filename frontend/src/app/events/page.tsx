"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Empty, ErrorBox, Loading, PageHeader, Pager, Panel, SeverityBadge, inputClass } from "@/components/ui";
import { apiGet } from "@/lib/api";
import { formatTime } from "@/lib/format";
import type { EventRecord, Page } from "@/lib/types";

const LIMIT = 50;
const EVENT_TYPES = [
  "system_info", "system_metrics", "process_snapshot", "network_snapshot", "collector_error",
  "ssh_login_failed", "ssh_login_success", "ssh_root_login", "sudo_command",
  "ssh_bruteforce_detected", "suspicious_root_login_detected", "auth_burst_detected",
  "privileged_process_detected", "unexpected_listening_port_detected",
];

export default function EventsPage() {
  const [eventType, setEventType] = useState("");
  const [severity, setSeverity] = useState("");
  const [host, setHost] = useState("");
  const [sourceIp, setSourceIp] = useState("");
  const [offset, setOffset] = useState(0);
  const [openId, setOpenId] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["events", { eventType, severity, host, sourceIp, offset }],
    queryFn: () =>
      apiGet<Page<EventRecord>>("/api/v1/events", {
        event_type: eventType || undefined,
        severity: severity || undefined,
        host_id: host || undefined,
        source_ip: sourceIp || undefined,
        order: "desc",
        limit: LIMIT,
        offset,
      }),
    refetchInterval: 20_000,
  });

  const reset = (apply: () => void) => {
    apply();
    setOffset(0);
  };

  return (
    <>
      <PageHeader title="Events" />
      <div className="mb-4 flex flex-wrap gap-3">
        <select aria-label="Event type" className={inputClass} value={eventType} onChange={(e) => reset(() => setEventType(e.target.value))}>
          <option value="">Any type</option>
          {EVENT_TYPES.map((type) => <option key={type} value={type}>{type}</option>)}
        </select>
        <select aria-label="Severity" className={inputClass} value={severity} onChange={(e) => reset(() => setSeverity(e.target.value))}>
          <option value="">Any severity</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <input aria-label="Host" placeholder="Host" className={inputClass} value={host} onChange={(e) => reset(() => setHost(e.target.value))} />
        <input aria-label="Source IP" placeholder="Source IP" className={inputClass} value={sourceIp} onChange={(e) => reset(() => setSourceIp(e.target.value))} />
      </div>

      {query.error ? (
        <ErrorBox error={query.error} />
      ) : !query.data ? (
        <Loading />
      ) : (
        <Panel>
          {query.data.items.length === 0 ? (
            <Empty>No events match these filters.</Empty>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs uppercase text-[var(--muted)]">
                  <tr>
                    <th className="py-2 pr-3">Time</th>
                    <th className="py-2 pr-3">Severity</th>
                    <th className="py-2 pr-3">Type</th>
                    <th className="py-2 pr-3">Host</th>
                    <th className="py-2 pr-3">Source</th>
                    <th className="py-2 pr-3">Message</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border)]">
                  {query.data.items.map((event) => (
                    <tr
                      key={event.event_id}
                      className="cursor-pointer hover:bg-[var(--surface-raised)]"
                      onClick={() => setOpenId(openId === event.event_id ? null : event.event_id)}
                    >
                      <td className="whitespace-nowrap py-2 pr-3 text-[var(--muted)]">{formatTime(event.timestamp)}</td>
                      <td className="py-2 pr-3"><SeverityBadge severity={event.severity} /></td>
                      <td className="py-2 pr-3 font-mono text-xs">{event.event_type}</td>
                      <td className="py-2 pr-3">{event.host_id}</td>
                      <td className="py-2 pr-3 font-mono text-xs">{event.source_ip ?? "—"}</td>
                      <td className="py-2 pr-3">
                        {event.message}
                        {openId === event.event_id && (
                          <pre className="mt-2 max-h-64 overflow-auto rounded bg-[var(--background)] p-3 text-xs text-[var(--muted)]">
                            {JSON.stringify(event.metadata, null, 2)}
                          </pre>
                        )}
                      </td>
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
