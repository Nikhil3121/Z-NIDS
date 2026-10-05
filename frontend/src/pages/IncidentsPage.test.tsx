import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { RequireAuth } from "@/auth/guards";
import { setAccessToken } from "@/lib/api";
import IncidentsPage from "@/pages/IncidentsPage";
import { apiError, json, makeUser, mockFetch, refreshAs, renderApp } from "@/test/utils";

afterEach(() => {
  vi.unstubAllGlobals();
  setAccessToken(null);
});

const incident = (id: number, overrides: Record<string, unknown> = {}) => ({
  id, reference: `INC-${1000 + id}`, title: `Incident ${id}`, severity: "high", status: "NEW", classification: "POTENTIAL_UNKNOWN",
  risk_score: 78.5, correlation_rule: "unknown_single", primary_src_ip: "10.20.1.87", first_seen: "2026-09-23T10:00:00Z",
  last_seen: "2026-09-23T10:05:00Z", assigned_to: null, resolution: null, is_demo: true,
  created_at: "2026-09-23T10:00:00Z", updated_at: "2026-09-23T10:05:00Z", ...overrides,
});

const routes = [{ path: "/incidents", element: <RequireAuth permission="incidents:view"><IncidentsPage /></RequireAuth> }];

describe("incidents page", () => {
  it("shows a loading state, then the incidents returned by the API", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    mockFetch({
      "POST /api/v1/auth/refresh": refreshAs(makeUser(["incidents:view"])),
      "GET /api/v1/incidents": async () => {
        await gate;
        return json({ items: [incident(3), incident(4, { assigned_to: { id: 1, name: "Test Analyst", email: "a@b" } })], total: 2, page: 1, page_size: 25, pages: 1 });
      },
    });
    renderApp(routes, "/incidents");
    expect(await screen.findByText("Loading")).toBeInTheDocument();
    release();
    expect(await screen.findByRole("link", { name: "INC-1003" })).toHaveAttribute("href", "/incidents/3");
    expect(screen.getByText("Test Analyst")).toBeInTheDocument();
    expect(screen.getAllByText("unassigned")).toHaveLength(1);
  });

  it("sends filters to the API", async () => {
    const { calls } = mockFetch({
      "POST /api/v1/auth/refresh": refreshAs(makeUser(["incidents:view"])),
      "GET /api/v1/incidents": () => json({ items: [], total: 0, page: 1, page_size: 25, pages: 0 }),
    });
    renderApp(routes, "/incidents");
    const user = userEvent.setup();
    await user.selectOptions(await screen.findByLabelText("Severity"), "critical");
    await user.selectOptions(screen.getByLabelText("Status"), "INVESTIGATING");
    await user.type(screen.getByLabelText("Search incidents"), "INC-1004");
    await waitFor(() => {
      const last = calls.filter((c) => c.url.pathname === "/api/v1/incidents").at(-1)!.url.searchParams;
      expect(last.get("severity")).toBe("critical");
      expect(last.get("status")).toBe("INVESTIGATING");
      expect(last.get("active_only")).toBeNull();
      expect(last.get("q")).toBe("INC-1004");
    });
  });

  it("renders the API error message", async () => {
    mockFetch({
      "POST /api/v1/auth/refresh": refreshAs(makeUser(["incidents:view"])),
      "GET /api/v1/incidents": () => apiError(500, "INTERNAL_ERROR", "Database unavailable"),
    });
    renderApp(routes, "/incidents");
    expect(await screen.findByText(/Database unavailable/)).toBeInTheDocument();
  });
});
