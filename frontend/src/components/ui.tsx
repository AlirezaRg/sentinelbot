import Link from "next/link";
import type { ReactNode } from "react";
import { ApiError } from "@/lib/api";
import { SEVERITY_STYLE, STATUS_STYLE } from "@/lib/format";
import type { IncidentStatus, Severity } from "@/lib/types";

export function PageHeader({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
      {children}
    </div>
  );
}

export function Panel({
  title,
  children,
  className = "",
}: {
  title?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-lg border border-[var(--border)] bg-[var(--surface)] p-4 ${className}`}
    >
      {title && <h2 className="mb-3 text-sm font-medium text-[var(--muted)]">{title}</h2>}
      {children}
    </section>
  );
}

export function StatCard({
  label,
  value,
  tone = "neutral",
}: {
  label: string;
  value: ReactNode;
  tone?: "neutral" | "warn" | "danger" | "ok";
}) {
  const color = {
    neutral: "text-[var(--foreground)]",
    warn: "text-amber-300",
    danger: "text-red-300",
    ok: "text-emerald-300",
  }[tone];
  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--surface)] p-4">
      <p className="text-xs uppercase tracking-wide text-[var(--muted)]">{label}</p>
      <p className={`mt-2 text-3xl font-semibold tabular-nums ${color}`}>{value}</p>
    </div>
  );
}

export function Badge({ children, className }: { children: ReactNode; className: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${className}`}
    >
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge className={SEVERITY_STYLE[severity]}>{severity.toUpperCase()}</Badge>;
}

export function StatusBadge({ status }: { status: IncidentStatus }) {
  return <Badge className={STATUS_STYLE[status]}>{status.replace("_", " ")}</Badge>;
}

export function ErrorBox({ error }: { error: unknown }) {
  const isAuth = error instanceof ApiError && (error.status === 401 || error.status === 503);
  const message = error instanceof Error ? error.message : "Something went wrong.";
  return (
    <div
      role="alert"
      className="rounded-lg border border-red-500/40 bg-red-500/10 p-4 text-sm text-red-200"
    >
      <p>{message}</p>
      {isAuth && (
        <p className="mt-2">
          <Link href="/settings" className="underline">
            Open Settings
          </Link>{" "}
          to check the API key.
        </p>
      )}
    </div>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <p role="status" className="text-sm text-[var(--muted)]">
      {label}
    </p>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-8 text-center text-sm text-[var(--muted)]">{children}</p>;
}

export function Pager({
  total,
  limit,
  offset,
  onChange,
}: {
  total: number;
  limit: number;
  offset: number;
  onChange: (offset: number) => void;
}) {
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + limit, total);
  return (
    <div className="mt-4 flex items-center justify-between text-sm text-[var(--muted)]">
      <span>
        {from}–{to} of {total}
      </span>
      <div className="flex gap-2">
        <button
          type="button"
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - limit))}
          className="rounded-md border border-[var(--border)] px-3 py-1 disabled:opacity-40"
        >
          Previous
        </button>
        <button
          type="button"
          disabled={offset + limit >= total}
          onClick={() => onChange(offset + limit)}
          className="rounded-md border border-[var(--border)] px-3 py-1 disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  );
}

export const inputClass =
  "rounded-md border border-[var(--border)] bg-[var(--surface-raised)] px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-sky-500/50";
