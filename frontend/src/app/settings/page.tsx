"use client";

import { useEffect, useState } from "react";
import { PageHeader, Panel, inputClass } from "@/components/ui";
import { ApiError, apiGet, clearApiKey, getApiKey, setApiKey } from "@/lib/api";
import type { SystemStatus } from "@/lib/types";

type Check = { state: "idle" } | { state: "ok"; detail: string } | { state: "error"; detail: string };

export default function SettingsPage() {
  const [key, setKey] = useState("");
  const [saved, setSaved] = useState(false);
  const [check, setCheck] = useState<Check>({ state: "idle" });

  useEffect(() => {
    setKey(getApiKey() ?? "");
  }, []);

  async function testConnection() {
    try {
      const status = await apiGet<SystemStatus>("/api/v1/system/status");
      setCheck({
        state: "ok",
        detail: `Connected to API ${status.version} (${status.persistence} storage, ${status.events_stored} events).`,
      });
    } catch (error) {
      const detail =
        error instanceof ApiError && error.status === 401
          ? "The API rejected this key."
          : error instanceof Error
            ? error.message
            : "Connection failed.";
      setCheck({ state: "error", detail });
    }
  }

  return (
    <>
      <PageHeader title="Settings" />
      <div className="max-w-2xl space-y-6">
        <Panel title="API key">
          <p className="mb-3 text-sm text-[var(--muted)]">
            The key is stored in this browser only, so the console can call the API. Anyone who can
            use this browser can use the key. Use a separate machine or a private browser profile for
            shared computers.
          </p>
          <div className="flex flex-col gap-3 sm:flex-row">
            <input
              type="password"
              aria-label="API key"
              autoComplete="off"
              className={`${inputClass} flex-1`}
              value={key}
              onChange={(e) => {
                setKey(e.target.value);
                setSaved(false);
              }}
            />
            <button
              type="button"
              onClick={() => {
                setApiKey(key);
                setSaved(true);
              }}
              className="rounded-md bg-sky-600/80 px-4 py-2 text-sm font-medium"
            >
              Save
            </button>
            <button
              type="button"
              onClick={() => {
                clearApiKey();
                setKey("");
                setSaved(false);
              }}
              className="rounded-md border border-[var(--border)] px-4 py-2 text-sm"
            >
              Forget
            </button>
          </div>
          {saved && <p className="mt-3 text-sm text-emerald-300">Saved in this browser.</p>}
        </Panel>

        <Panel title="Connection">
          <button
            type="button"
            onClick={testConnection}
            className="rounded-md border border-[var(--border)] px-4 py-2 text-sm"
          >
            Test connection
          </button>
          {check.state !== "idle" && (
            <p
              role="status"
              className={`mt-3 text-sm ${check.state === "ok" ? "text-emerald-300" : "text-red-300"}`}
            >
              {check.detail}
            </p>
          )}
        </Panel>
      </div>
    </>
  );
}
