"""Network collector using synthetic socket records. No sockets are opened."""

from __future__ import annotations

import socket
from collections import namedtuple
from types import SimpleNamespace
from typing import Any

import psutil
import pytest

from sentinelbot_agent.collectors.network import NetworkCollector
from sentinelbot_agent.config import AgentConfig
from sentinelbot_agent.models import EventType

Addr = namedtuple("Addr", ["ip", "port"])


def _conn(
    *,
    kind: int = socket.SOCK_STREAM,
    laddr: tuple[str, int] | tuple[()] = ("0.0.0.0", 22),
    raddr: tuple[str, int] | tuple[()] = (),
    status: str = psutil.CONN_LISTEN,
    pid: int | None = 100,
) -> Any:
    return SimpleNamespace(
        type=kind,
        laddr=Addr(*laddr) if laddr else (),
        raddr=Addr(*raddr) if raddr else (),
        status=status,
        pid=pid,
    )


def _collector(
    config: AgentConfig,
    connections: list[Any],
    names: dict[int, str] | None = None,
    lookups: list[int] | None = None,
) -> NetworkCollector:
    names = names or {}

    def lookup(pid: int) -> str | None:
        if lookups is not None:
            lookups.append(pid)
        return names.get(pid)

    return NetworkCollector(
        config, connection_source=lambda: connections, process_name_lookup=lookup
    )


def test_separates_listening_sockets_from_active_connections(config: AgentConfig) -> None:
    connections = [
        _conn(laddr=("0.0.0.0", 22), status=psutil.CONN_LISTEN, pid=100),
        _conn(laddr=("10.0.0.5", 443), raddr=("203.0.113.9", 51514), status="ESTABLISHED", pid=200),
        _conn(kind=socket.SOCK_DGRAM, laddr=("0.0.0.0", 5353), status="NONE", pid=300),
    ]

    (event,) = _collector(config, connections, {100: "sshd", 200: "nginx", 300: "avahi"}).collect()

    assert event.event_type is EventType.NETWORK_SNAPSHOT
    listening = event.metadata["listening_ports"]
    assert {(r["protocol"], r["local_port"]) for r in listening} == {("tcp", 22), ("udp", 5353)}
    active = event.metadata["connections"]
    assert len(active) == 1
    assert active[0]["remote_address"] == "203.0.113.9"
    assert active[0]["remote_port"] == 51514
    assert active[0]["process"] == "nginx"
    assert event.metadata["listening_port_count"] == 2
    assert event.metadata["connection_count"] == 1


def test_connected_udp_socket_is_not_listening(config: AgentConfig) -> None:
    connected_udp = _conn(
        kind=socket.SOCK_DGRAM,
        laddr=("10.0.0.5", 40000),
        raddr=("8.8.8.8", 53),
        status="NONE",
        pid=None,
    )

    (event,) = _collector(config, [connected_udp]).collect()

    assert event.metadata["listening_ports"] == []
    assert event.metadata["connection_count"] == 1


def test_unknown_pid_gives_no_process_name(config: AgentConfig) -> None:
    (event,) = _collector(config, [_conn(pid=None)]).collect()

    assert event.metadata["listening_ports"][0]["pid"] is None
    assert event.metadata["listening_ports"][0]["process"] is None


def test_process_names_are_looked_up_once_per_pid(config: AgentConfig) -> None:
    lookups: list[int] = []
    connections = [_conn(laddr=("0.0.0.0", 80), pid=500), _conn(laddr=("0.0.0.0", 443), pid=500)]

    _collector(config, connections, {500: "httpd"}, lookups).collect()

    assert lookups == [500]


def test_active_connections_are_capped(config: AgentConfig) -> None:
    capped = AgentConfig(host_id="h", cpu_sample_seconds=0.0, max_connections=1)
    connections = [
        _conn(laddr=("10.0.0.5", 1000 + i), raddr=("198.51.100.1", 443), status="ESTABLISHED")
        for i in range(3)
    ]

    (event,) = _collector(capped, connections).collect()

    assert event.metadata["connection_count"] == 3
    assert len(event.metadata["connections"]) == 1
    assert event.metadata["connections_truncated"] is True


def test_permission_error_propagates_to_agent(config: AgentConfig) -> None:
    def denied() -> list[Any]:
        raise psutil.AccessDenied()

    collector = NetworkCollector(config, connection_source=denied)

    with pytest.raises(psutil.AccessDenied):
        collector.collect()
