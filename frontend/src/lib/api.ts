// Browser-side API client.
//
// Two ways to authenticate, both stored only in this browser's localStorage:
// - a signed-in user's token (the normal path, from the sign-in page);
// - the service API key (for an operator's own machine, from the Settings page).
// A token takes precedence. A rejected token signs the user out.

const BASE = "/backend";
const KEY_STORAGE = "sentinel.apiKey";
const TOKEN_STORAGE = "sentinel.token";
const ROLE_STORAGE = "sentinel.role";
const USER_STORAGE = "sentinel.user";

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

function readStorage(name: string): string | null {
  try {
    return window.localStorage.getItem(name);
  } catch {
    return null;
  }
}

function writeStorage(name: string, value: string | null): void {
  try {
    if (value === null) window.localStorage.removeItem(name);
    else window.localStorage.setItem(name, value);
  } catch {
    // Storage can be blocked (private mode). The user then signs in again each visit.
  }
}

export function getApiKey(): string | null {
  return readStorage(KEY_STORAGE);
}

export function setApiKey(key: string): void {
  writeStorage(KEY_STORAGE, key.trim());
}

export function clearApiKey(): void {
  writeStorage(KEY_STORAGE, null);
}

export function getToken(): string | null {
  return readStorage(TOKEN_STORAGE);
}

export interface Session {
  token: string;
  username: string;
  role: string;
}

export function saveSession(session: Session): void {
  writeStorage(TOKEN_STORAGE, session.token);
  writeStorage(USER_STORAGE, session.username);
  writeStorage(ROLE_STORAGE, session.role);
}

export function getSessionUser(): { username: string; role: string } | null {
  const username = readStorage(USER_STORAGE);
  const role = readStorage(ROLE_STORAGE);
  return username && role ? { username, role } : null;
}

export function signOut(): void {
  writeStorage(TOKEN_STORAGE, null);
  writeStorage(USER_STORAGE, null);
  writeStorage(ROLE_STORAGE, null);
}

/** True when the browser has either a user session or an API key. */
export function hasCredentials(): boolean {
  return getToken() !== null || getApiKey() !== null;
}

type Params = Record<string, string | number | undefined>;

function buildUrl(path: string, params?: Params): string {
  const query = new URLSearchParams();
  for (const [name, value] of Object.entries(params ?? {})) {
    if (value !== undefined && value !== "") query.set(name, String(value));
  }
  const suffix = query.toString();
  return `${BASE}${path}${suffix ? `?${suffix}` : ""}`;
}

function authHeaders(): Record<string, string> {
  const token = getToken();
  if (token) return { Authorization: `Bearer ${token}` };
  const key = getApiKey();
  if (key) return { "X-API-Key": key };
  throw new ApiError(401, "Not signed in.");
}

async function request<T>(method: "GET" | "POST", url: string, body?: unknown): Promise<T> {
  const headers = {
    ...authHeaders(),
    ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
  };
  const response = await fetch(url, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    cache: "no-store",
  });
  if (!response.ok) {
    if (response.status === 401 && getToken()) {
      // The token expired or was revoked: sign out and send the user to the sign-in page.
      signOut();
      window.location.assign("/login");
    }
    throw new ApiError(response.status, await errorDetail(response));
  }
  return (await response.json()) as T;
}

async function errorDetail(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { detail?: unknown };
    if (typeof body.detail === "string") return body.detail;
    if (body.detail !== undefined) return JSON.stringify(body.detail);
  } catch {
    // Not JSON; fall through to the status text.
  }
  return response.statusText || `HTTP ${response.status}`;
}

export function apiGet<T>(path: string, params?: Params): Promise<T> {
  return request<T>("GET", buildUrl(path, params));
}

export function apiPost<T>(path: string, body?: unknown): Promise<T> {
  return request<T>("POST", buildUrl(path), body);
}

/** Sign-in needs no credentials; it is the request that produces them. */
export async function signIn(username: string, password: string): Promise<Session> {
  const response = await fetch(`${BASE}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
    cache: "no-store",
  });
  if (!response.ok) {
    throw new ApiError(response.status, await errorDetail(response));
  }
  const data = (await response.json()) as { access_token: string; role: string };
  const session = { token: data.access_token, username, role: data.role };
  saveSession(session);
  return session;
}
