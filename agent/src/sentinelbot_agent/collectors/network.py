"""Network collector: listening sockets and active connections, with owning process names."""

from __future__ import annotations

import socket
from collections.abc import Callable, Iterable
from typing import Any

import psutil

from sentinelbot_agent.collectors.base import Collector
from sentinelbot_agent.config import AgentConfig
from sentinelbot_agent.models import Event, EventType

ConnectionSource = Callable[[], Iterable[Any]]
ProcessNameLookup = Callable[[int], str | None]


def _default_connections() -> Iterable[Any]:
    return psutil.net_connections(kind="inet")


def _default_process_name(pid: int) -> str | None:
    try:
        return psutil.Process(pid).name()
    except psutil.Error:
        return None


class NetworkCollector(Collector):
    """Emits one ``network_snapshot`` event with ``listening_ports`` and ``connections``.

    On Linux, socket-to-process mapping needs elevated privileges for other users'
    sockets; those rows carry ``pid=None`` rather than failing the collection.
    """

    name = "network"

    def __init__(
        self,
        config: AgentConfig,
        connection_source: ConnectionSource = _default_connections,
        process_name_lookup: ProcessNameLookup = _default_process_name,
    ) -> None:
        super().__init__(config)
        self._connection_source = connection_source
        self._process_name_lookup = process_name_lookup

    def collect(self) -> list[Event]:
        names: dict[int, str | None] = {}
        listening: list[dict[str, Any]] = []
        active: list[dict[str, Any]] = []

        for conn in self._connection_source():
            protocol = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
            local_address, local_port = _endpoint(conn.laddr)
            remote_address, remote_port = _endpoint(conn.raddr)
            record: dict[str, Any] = {
                "protocol": protocol,
                "local_address": local_address,
                "local_port": local_port,
                "remote_address": remote_address,
                "remote_port": remote_port,
                "status": conn.status,
                "pid": conn.pid,
                "process": self._process_name(conn.pid, names),
            }
            if _is_listening(protocol, conn.status, remote_address):
                listening.append(record)
            else:
                active.append(record)

        listening.sort(key=lambda r: (r["protocol"], r["local_port"] or 0))
        total_active = len(active)
        metadata: dict[str, Any] = {
            "listening_port_count": len(listening),
            "connection_count": total_active,
            "connections_truncated": total_active > self._config.max_connections,
            "listening_ports": listening,
            "connections": active[: self._config.max_connections],
        }
        message = f"{len(listening)} listening sockets, {total_active} active connections"
        return [self._event(EventType.NETWORK_SNAPSHOT, message, metadata)]

    def _process_name(self, pid: int | None, cache: dict[int, str | None]) -> str | None:
        if pid is None:
            return None
        if pid not in cache:
            cache[pid] = self._process_name_lookup(pid)
        return cache[pid]


def _endpoint(address: Any) -> tuple[str | None, int | None]:
    """Split a psutil address tuple; psutil uses an empty tuple when there is no endpoint."""
    if not address:
        return None, None
    return str(address.ip), int(address.port)


def _is_listening(protocol: str, status: str, remote_address: str | None) -> bool:
    if protocol == "tcp":
        return status == psutil.CONN_LISTEN
    # UDP has no listen state; an unconnected UDP socket is the closest equivalent.
    return remote_address is None
