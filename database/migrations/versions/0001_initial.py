"""Initial schema: hosts, events, incidents, detection_rules, alerts.

Revision ID: 0001
Revises:
Create Date: 2026-10-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "hosts",
        sa.Column("host_id", sa.String(255), primary_key=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
    )
    op.create_index("ix_hosts_last_seen", "hosts", ["last_seen"])

    op.create_table(
        "events",
        sa.Column("event_id", sa.Uuid(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("host_id", sa.String(255), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("username", sa.String(255), nullable=True),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
    )
    op.create_index("ix_events_timestamp", "events", ["timestamp"])
    op.create_index("ix_events_host_id", "events", ["host_id"])
    op.create_index("ix_events_event_type", "events", ["event_type"])
    op.create_index("ix_events_severity", "events", ["severity"])
    op.create_index("ix_events_source_ip", "events", ["source_ip"])
    op.create_index("ix_events_host_timestamp", "events", ["host_id", "timestamp"])

    op.create_table(
        "incidents",
        sa.Column("incident_id", sa.String(64), primary_key=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("host_id", sa.String(255), nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("usernames", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rules", sa.JSON(), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("related_event_ids", sa.JSON(), nullable=False),
        sa.Column("recommended_actions", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
    )
    op.create_index("ix_incidents_severity", "incidents", ["severity"])
    op.create_index("ix_incidents_risk_score", "incidents", ["risk_score"])
    op.create_index("ix_incidents_host_id", "incidents", ["host_id"])
    op.create_index("ix_incidents_source_ip", "incidents", ["source_ip"])
    op.create_index("ix_incidents_last_seen", "incidents", ["last_seen"])
    op.create_index("ix_incidents_status", "incidents", ["status"])

    op.create_table(
        "detection_rules",
        sa.Column("rule_id", sa.String(64), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("settings", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "incident_id",
            sa.String(64),
            sa.ForeignKey("incidents.incident_id"),
            nullable=False,
        ),
        sa.Column("channel", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_alerts_incident_id", "alerts", ["incident_id"])


def downgrade() -> None:
    op.drop_table("alerts")
    op.drop_table("detection_rules")
    op.drop_table("incidents")
    op.drop_table("events")
    op.drop_table("hosts")
