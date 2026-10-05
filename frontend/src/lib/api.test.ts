import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { api, ApiError, buildUrl, get, setAccessToken } from "@/lib/api";
import { apiError, json, mockFetch } from "@/test/utils";

afterEach(() => {
  vi.unstubAllGlobals();
  setAccessToken(null);
});

describe("api client", () => {
  it("builds query strings and drops empty values", () => {
    expect(buildUrl("/events", { a: 1, b: "", c: undefined, d: null, e: true })).toBe("/api/v1/events?a=1&e=true");
  });

  it("sends the in-memory bearer token", async () => {
    setAccessToken("tok-1");
    const { calls } = mockFetch({ "GET /api/v1/x": () => json({ ok: true }) });
    await get("/x", z.object({ ok: z.boolean() }));
    expect((calls[0].init.headers as Record<string, string>).Authorization).toBe("Bearer tok-1");
  });

  it("maps backend error bodies to ApiError", async () => {
    mockFetch({ "GET /api/v1/x": () => apiError(403, "FORBIDDEN", "Missing permission") });
    const err = await get("/x", null).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 403, code: "FORBIDDEN", message: "Missing permission", requestId: "req-test" });
  });

  it("shows the field-level reason for validation errors instead of a generic message", async () => {
    mockFetch({
      "POST /api/v1/auth/login": () => json({ error: { code: "VALIDATION_ERROR", message: "Request validation failed", request_id: "r",
        details: [{ loc: ["body", "email"], msg: "Value error, not a valid email address: An email address must have an @-sign.", type: "value_error" }] } }, 422),
    });
    await expect(api("/auth/login", null, { method: "POST", body: {} })).rejects.toMatchObject({
      code: "VALIDATION_ERROR", message: "email: not a valid email address: An email address must have an @-sign.",
    });
  });

  it("refreshes once on 401 and retries, sharing the refresh across concurrent requests", async () => {
    setAccessToken("expired");
    let refreshes = 0;
    const { calls } = mockFetch({
      "GET /api/v1/x": (_u, init) =>
        (init.headers as Record<string, string>).Authorization === "Bearer fresh" ? json({ ok: true }) : apiError(401, "UNAUTHENTICATED", "expired"),
      "POST /api/v1/auth/refresh": (_u, init) => {
        refreshes += 1;
        expect((init.headers as Record<string, string>)["X-ZNIDS-CSRF"]).toBe("1");
        return json({ access_token: "fresh", expires_in: 900, user: {} });
      },
    });
    const schema = z.object({ ok: z.boolean() });
    const [a, b] = await Promise.all([get("/x", schema), get("/x", schema)]);
    expect(a.ok && b.ok).toBe(true);
    expect(refreshes).toBe(1);
    expect(calls.filter((c) => c.url.pathname === "/api/v1/x")).toHaveLength(4);
  });

  it("does not loop when the refresh fails", async () => {
    mockFetch({
      "GET /api/v1/x": () => apiError(401, "UNAUTHENTICATED", "expired"),
      "POST /api/v1/auth/refresh": () => apiError(401, "UNAUTHENTICATED", "no session"),
    });
    await expect(get("/x", null)).rejects.toMatchObject({ status: 401 });
  });

  it("rejects responses that do not match the schema", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    mockFetch({ "GET /api/v1/x": () => json({ ok: "yes" }) });
    await expect(api("/x", z.object({ ok: z.boolean() }))).rejects.toMatchObject({ code: "INVALID_RESPONSE" });
  });
});
