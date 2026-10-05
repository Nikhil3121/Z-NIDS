/**
 * API client.
 *
 * - The access token lives only in memory (never localStorage), so an XSS
 *   payload cannot read a long-lived credential from storage.
 * - The refresh token is an HttpOnly SameSite=Strict cookie scoped to /api/v1/auth;
 *   refresh calls add the X-ZNIDS-CSRF header the backend requires.
 * - A 401 triggers one refresh attempt (shared by concurrent requests), then a retry.
 * - Every error becomes an ApiError carrying the backend's { code, message, request_id }.
 */
import { z } from "zod";

export const API_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, "") ?? "";
const PREFIX = `${API_BASE}/api/v1`;

const ErrorBody = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    request_id: z.string().nullable().optional(),
    details: z.unknown().optional(),
  }),
});

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;
  readonly details: unknown;

  constructor(status: number, code: string, message: string, requestId: string | null, details?: unknown) {
    super(message);
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.details = details;
  }
}

let accessToken: string | null = null;
let refreshInFlight: Promise<boolean> | null = null;
const listeners = new Set<(token: string | null) => void>();

export function setAccessToken(token: string | null): void {
  accessToken = token;
  listeners.forEach((l) => l(token));
}

export function getAccessToken(): string | null {
  return accessToken;
}

export function onTokenChange(listener: (token: string | null) => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

const ValidationDetails = z.array(z.object({ loc: z.array(z.union([z.string(), z.number()])), msg: z.string() }).loose()).min(1);

/** Turn FastAPI's 422 details into "email: not a valid email address …" instead of a generic message. */
function validationMessage(details: unknown): string | null {
  const parsed = ValidationDetails.safeParse(details);
  if (!parsed.success) return null;
  const { loc, msg } = parsed.data[0];
  const field = loc.filter((p) => p !== "body" && p !== "query").join(".");
  const text = msg.replace(/^Value error, /, "");
  return field ? `${field}: ${text}` : text;
}

async function toApiError(res: Response): Promise<ApiError> {
  let parsed: z.infer<typeof ErrorBody> | null;
  try {
    parsed = ErrorBody.parse(await res.json());
  } catch {
    parsed = null;
  }
  if (parsed) {
    const e = parsed.error;
    return new ApiError(res.status, e.code, validationMessage(e.details) ?? e.message, e.request_id ?? null, e.details);
  }
  return new ApiError(res.status, "HTTP_ERROR", res.statusText || "Request failed", res.headers.get("x-request-id"));
}

/** Exchange the refresh cookie for a new access token. Returns false if the session is gone. */
export async function refreshSession(): Promise<RefreshResult | null> {
  const res = await fetch(`${PREFIX}/auth/refresh`, {
    method: "POST",
    credentials: "include",
    headers: { "X-ZNIDS-CSRF": "1" },
  });
  if (!res.ok) {
    setAccessToken(null);
    return null;
  }
  const body = (await res.json()) as RefreshResult;
  setAccessToken(body.access_token);
  return body;
}

export type RefreshResult = { access_token: string; expires_in: number; user: unknown };

async function refreshOnce(): Promise<boolean> {
  refreshInFlight ??= refreshSession()
    .then((r) => r !== null)
    .finally(() => {
      refreshInFlight = null;
    });
  return refreshInFlight;
}

type Query = Record<string, string | number | boolean | null | undefined>;

export function buildUrl(path: string, query?: Query): string {
  const url = `${PREFIX}${path}`;
  if (!query) return url;
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null && v !== "") params.set(k, String(v));
  }
  const qs = params.toString();
  return qs ? `${url}?${qs}` : url;
}

export interface RequestOptions {
  method?: string;
  query?: Query;
  body?: unknown;
  signal?: AbortSignal;
  raw?: boolean;
}

export async function api<T>(path: string, schema: z.ZodType<T> | null, opts: RequestOptions = {}): Promise<T> {
  const send = () => {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
    let body: BodyInit | undefined;
    if (opts.body instanceof FormData) {
      body = opts.body;
    } else if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(opts.body);
    }
    return fetch(buildUrl(path, opts.query), {
      method: opts.method ?? "GET",
      headers,
      body,
      signal: opts.signal,
      credentials: "include",
    });
  };

  let res = await send();
  if (res.status === 401 && !path.startsWith("/auth/")) {
    if (await refreshOnce()) res = await send();
  }
  if (!res.ok) throw await toApiError(res);
  if (res.status === 204) return undefined as T;
  if (opts.raw) return (await res.text()) as T;
  const data: unknown = await res.json();
  if (!schema) return data as T;
  const result = schema.safeParse(data);
  if (!result.success) {
    // A contract mismatch is a bug: surface it loudly instead of rendering garbage.
    console.error("API response failed validation", path, result.error.issues.slice(0, 5));
    throw new ApiError(0, "INVALID_RESPONSE", "The server returned data in an unexpected format.", null);
  }
  return result.data;
}

export const get = <T>(path: string, schema: z.ZodType<T> | null, query?: Query, signal?: AbortSignal) =>
  api(path, schema, { query, signal });
export const post = <T>(path: string, schema: z.ZodType<T> | null, body?: unknown) =>
  api(path, schema, { method: "POST", body });
export const patch = <T>(path: string, schema: z.ZodType<T> | null, body?: unknown) =>
  api(path, schema, { method: "PATCH", body });
export const put = <T>(path: string, schema: z.ZodType<T> | null, body?: unknown) =>
  api(path, schema, { method: "PUT", body });
export const del = <T>(path: string, schema: z.ZodType<T> | null) => api(path, schema, { method: "DELETE" });

export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return "Something went wrong.";
}
