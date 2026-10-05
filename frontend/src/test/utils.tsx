import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";

import { createMemoryRouter, RouterProvider, type RouteObject } from "react-router";
import { vi } from "vitest";

import { AuthProvider } from "@/auth/AuthProvider";
import type { Me } from "@/lib/schemas";

export type Handler = (url: URL, init: RequestInit) => Response | Promise<Response>;

export const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

export const apiError = (status: number, code: string, message: string) =>
  json({ error: { code, message, request_id: "req-test" } }, status);

/**
 * Replace global fetch with a route table: keys are "METHOD /api/v1/path".
 * Unmatched requests fail the test loudly rather than hanging.
 */
export function mockFetch(routes: Record<string, Handler>) {
  const calls: { method: string; url: URL; init: RequestInit }[] = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(String(input), "http://localhost");
    const method = (init.method ?? "GET").toUpperCase();
    calls.push({ method, url, init });
    const handler = routes[`${method} ${url.pathname}`];
    if (!handler) return apiError(599, "UNMOCKED", `No mock for ${method} ${url.pathname}`);
    return handler(url, init);
  });
  vi.stubGlobal("fetch", fn);
  return { fn, calls };
}

export function makeUser(permissions: string[], overrides: Partial<Me> = {}): Me {
  return {
    id: 1, email: "analyst@znids.test", name: "Test Analyst", role: { id: 3, name: "SECURITY_ANALYST" },
    is_active: true, last_login: null, created_at: "2026-09-01T00:00:00Z", permissions, ...overrides,
  };
}

/** Refresh handler that restores a session for `user` (or none when null). */
export const refreshAs = (user: Me | null): Handler => () =>
  user ? json({ access_token: "test-access", expires_in: 900, user }) : apiError(401, "UNAUTHENTICATED", "No session");

export function renderApp(routes: RouteObject[], initialPath: string): ReturnType<typeof render> & { qc: QueryClient } {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const router = createMemoryRouter(routes, { initialEntries: [initialPath] });
  const utils = render(
    <QueryClientProvider client={qc}>
      <AuthProvider>
        <RouterProvider router={router} />
      </AuthProvider>
    </QueryClientProvider>,
  );
  return { ...utils, qc };
}

