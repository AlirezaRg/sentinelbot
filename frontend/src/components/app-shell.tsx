"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { clearApiKey, getSessionUser, hasCredentials, signOut } from "@/lib/api";

const NAV = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/incidents", label: "Incidents" },
  { href: "/events", label: "Events" },
  { href: "/hosts", label: "Hosts" },
  { href: "/network", label: "Network" },
  { href: "/containers", label: "Containers" },
  { href: "/settings", label: "Settings" },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  // Read browser storage only after mount, so server and client render the same markup.
  const [ready, setReady] = useState(false);
  const [user, setUser] = useState<{ username: string; role: string } | null>(null);
  const onLogin = pathname === "/login";

  useEffect(() => {
    setReady(true);
    setUser(getSessionUser());
    if (!onLogin && !hasCredentials()) router.replace("/login");
  }, [onLogin, router]);

  if (onLogin) return <main className="p-6">{children}</main>;

  return (
    <div className="flex min-h-screen">
      <aside className="flex w-56 shrink-0 flex-col border-r border-[var(--border)] bg-[var(--surface)] p-4">
        <div className="mb-6 px-2">
          <p className="text-lg font-semibold tracking-tight">SentinelBot</p>
          <p className="text-xs text-[var(--muted)]">Host security console</p>
        </div>
        <nav aria-label="Main" className="flex flex-col gap-1">
          {NAV.map((item) => {
            const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active ? "page" : undefined}
                className={`rounded-md px-3 py-2 text-sm transition-colors ${
                  active
                    ? "bg-[var(--surface-raised)] text-[var(--foreground)] ring-1 ring-[var(--border)]"
                    : "text-[var(--muted)] hover:bg-[var(--surface-raised)] hover:text-[var(--foreground)]"
                }`}
              >
                {item.label}
              </Link>
            );
          })}
        </nav>
        {ready && (
          <div className="mt-auto border-t border-[var(--border)] pt-4 text-sm">
            {user ? (
              <p className="mb-2 text-[var(--muted)]">
                {user.username} · <span className="uppercase">{user.role}</span>
              </p>
            ) : (
              <p className="mb-2 text-[var(--muted)]">API key session</p>
            )}
            <button
              type="button"
              onClick={() => {
                // Clears both a user session and a stored API key, so no credentials remain.
                signOut();
                clearApiKey();
                router.replace("/login");
              }}
              className="w-full rounded-md border border-[var(--border)] px-3 py-1.5 text-left hover:bg-[var(--surface-raised)]"
            >
              Sign out
            </button>
          </div>
        )}
      </aside>
      <main className="min-w-0 flex-1 p-6">{children}</main>
    </div>
  );
}
