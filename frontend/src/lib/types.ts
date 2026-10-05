// Shapes of the API responses. Keep in sync with backend/src/sentinelbot_backend/schemas.py.

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type IncidentStatus = "OPEN" | "INVESTIGATING" | "RESOLVED" | "FALSE_POSITIVE";

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface Incident {
  incident_id: string;
  title: string;
  description: string;
  severity: Severity;
  risk_score: number;
  host_id: string;
  source_ip: string | null;
  usernames: string[];
  first_seen: string;
  last_seen: string;
  rules: string[];
  event_count: number;
  related_event_ids: string[];
  recommended_actions: string[];
  status: IncidentStatus;
}

export interface EventRecord {
  event_id: string;
  timestamp: string;
  host_id: string;
  event_type: string;
  severity: Severity;
  source: string;
  source_ip: string | null;
  username: string | null;
  message: string;
  metadata: Record<string, unknown>;
}

export interface HostRecord {
  host_id: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  open_incidents: number;
}

export interface Metrics {
  events_stored: number;
  events_by_severity: Record<string, number>;
  events_by_type: Record<string, number>;
  incidents_total: number;
  incidents_by_status: Record<string, number>;
}

export interface SystemStatus {
  status: string;
  version: string;
  started_at: string;
  uptime_seconds: number;
  events_stored: number;
  event_capacity: number;
  incidents_stored: number;
  persistence: "memory" | "file" | "postgresql";
  api_key_configured: boolean;
}

export interface Analysis {
  summary: string;
  why_suspicious: string[];
  severity_assessment: string;
  evidence: string[];
  false_positive_explanations: string[];
  investigation_steps: string[];
  remediation: string[];
  confidence: number;
  confidence_note: string;
  provider: "rules" | "anthropic";
  fallback_reason: string | null;
}

export interface ListeningPort {
  protocol: string;
  local_port: number | null;
  local_address: string | null;
  process: string | null;
  pid: number | null;
}
