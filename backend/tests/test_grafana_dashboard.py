"""The Grafana dashboard must only query metrics the API really exports.

A panel that queries a misspelled or removed metric shows "No data" forever, which is hard to
notice. This test fails instead.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from sentinelbot_backend.metrics import ApiMetrics

REPO = Path(__file__).resolve().parents[2]
DASHBOARD = REPO / "monitoring" / "grafana" / "dashboards" / "sentinelbot.json"
PROVISIONING = REPO / "monitoring" / "grafana" / "provisioning"

pytestmark = pytest.mark.skipif(not DASHBOARD.exists(), reason="monitoring/ not present")


def _exported_series_names() -> set[str]:
    metrics = ApiMetrics()
    metrics.attach_state(lambda: {"OPEN": 0})
    names: set[str] = set()
    for family in metrics.registry.collect():
        names.update(
            {
                family.name,
                f"{family.name}_total",
                f"{family.name}_bucket",
                f"{family.name}_count",
                f"{family.name}_sum",
                f"{family.name}_created",
            }
        )
    return names


def _panels(dashboard: dict[str, Any]) -> list[dict[str, Any]]:
    return [p for p in dashboard["panels"] if isinstance(p, dict)]


def test_dashboard_is_valid_json_with_expected_title() -> None:
    dashboard = json.loads(DASHBOARD.read_text(encoding="utf-8"))

    assert dashboard["title"] == "SentinelBot Overview"
    assert len(_panels(dashboard)) >= 15


def test_every_query_uses_an_exported_metric() -> None:
    dashboard = json.loads(DASHBOARD.read_text(encoding="utf-8"))
    exported = _exported_series_names()

    used: set[str] = set()
    for panel in _panels(dashboard):
        for target in panel.get("targets", []):
            used.update(re.findall(r"\b(sentinel_[a-z_]+)", target["expr"]))

    unknown = sorted(used - exported)
    assert unknown == [], f"dashboard uses metrics the API does not export: {unknown}"


def test_datasource_is_provisioned_with_the_uid_the_dashboard_uses() -> None:
    datasource = (PROVISIONING / "datasources" / "prometheus.yml").read_text(encoding="utf-8")

    assert "uid: prometheus" in datasource
    assert "type: prometheus" in datasource


def test_dashboard_provider_points_at_the_mounted_directory() -> None:
    provider = (PROVISIONING / "dashboards" / "sentinelbot.yml").read_text(encoding="utf-8")

    assert "/var/lib/grafana/dashboards" in provider
