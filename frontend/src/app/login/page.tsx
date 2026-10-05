"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { ApiError, signIn } from "@/lib/api";
import { inputClass } from "@/components/ui";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await signIn(username, password);
      router.replace("/dashboard");
    } catch (err) {
      setError(err instanceof ApiError && err.status === 401 ? "Wrong username or password." : err instanceof Error ? err.message : "Sign-in failed.");
    } finally {
      setBusy(false);
      setPassword("");
    }
  }

  return (
    <div className="mx-auto mt-24 max-w-sm rounded-lg border border-[var(--border)] bg-[var(--surface)] p-6">
      <h1 className="mb-1 text-xl font-semibold">Sign in to SentinelBot</h1>
      <p className="mb-5 text-sm text-[var(--muted)]">Use the account created by an administrator.</p>
      <form onSubmit={submit} className="flex flex-col gap-3">
        <input
          aria-label="Username"
          autoComplete="username"
          required
          className={inputClass}
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <input
          aria-label="Password"
          type="password"
          autoComplete="current-password"
          required
          className={inputClass}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <button
          type="submit"
          disabled={busy}
          className="rounded-md bg-sky-600/80 px-4 py-2 text-sm font-medium disabled:opacity-50"
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>
        {error && (
          <p role="alert" className="text-sm text-red-300">
            {error}
          </p>
        )}
      </form>
    </div>
  );
}
