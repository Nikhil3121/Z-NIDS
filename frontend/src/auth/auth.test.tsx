import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { RequireAuth } from "@/auth/guards";
import { setAccessToken } from "@/lib/api";
import LoginPage from "@/pages/auth/LoginPage";
import { apiError, json, makeUser, mockFetch, refreshAs, renderApp } from "@/test/utils";

afterEach(() => {
  vi.unstubAllGlobals();
  setAccessToken(null);
});

const routes = [
  { path: "/login", element: <LoginPage /> },
  { path: "/", element: <RequireAuth><p>dashboard home</p></RequireAuth> },
  { path: "/audit", element: <RequireAuth permission="audit:view"><p>audit page</p></RequireAuth> },
];

describe("authentication", () => {
  it("redirects to the login page when there is no session", async () => {
    mockFetch({ "POST /api/v1/auth/refresh": refreshAs(null) });
    renderApp(routes, "/");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });

  it("restores a session from the refresh cookie", async () => {
    mockFetch({ "POST /api/v1/auth/refresh": refreshAs(makeUser(["events:view"])) });
    renderApp(routes, "/");
    expect(await screen.findByText("dashboard home")).toBeInTheDocument();
  });

  it("signs in and returns to the requested page", async () => {
    const user = makeUser(["audit:view"]);
    const { calls } = mockFetch({
      "POST /api/v1/auth/refresh": refreshAs(null),
      "POST /api/v1/auth/login": () => json({ access_token: "a1", expires_in: 900, user }),
    });
    renderApp(routes, "/audit");
    await screen.findByRole("heading", { name: "Sign in" });
    await userEvent.type(screen.getByLabelText("Email"), "analyst@znids.test");
    await userEvent.type(screen.getByLabelText("Password"), "correct horse battery");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("audit page")).toBeInTheDocument();
    const login = calls.find((c) => c.url.pathname === "/api/v1/auth/login");
    expect(JSON.parse(String(login?.init.body))).toEqual({ email: "analyst@znids.test", password: "correct horse battery" });
  });

  it("shows the server's error on failed sign-in", async () => {
    mockFetch({
      "POST /api/v1/auth/refresh": refreshAs(null),
      "POST /api/v1/auth/login": () => apiError(401, "INVALID_CREDENTIALS", "Invalid email or password."),
    });
    renderApp(routes, "/login");
    await userEvent.type(await screen.findByLabelText("Email"), "a@b.test");
    await userEvent.type(screen.getByLabelText("Password"), "wrong-password");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid email or password.");
  });

  it("shows a friendly message when rate limited", async () => {
    mockFetch({
      "POST /api/v1/auth/refresh": refreshAs(null),
      "POST /api/v1/auth/login": () => apiError(429, "RATE_LIMITED", "Too many requests"),
    });
    renderApp(routes, "/login");
    await userEvent.type(await screen.findByLabelText("Email"), "a@b.test");
    await userEvent.type(screen.getByLabelText("Password"), "whatever-password");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/Too many attempts/);
  });
});

describe("protected routes", () => {
  it("denies a page when the role lacks the permission", async () => {
    mockFetch({ "POST /api/v1/auth/refresh": refreshAs(makeUser(["events:view"])) });
    renderApp(routes, "/audit");
    expect(await screen.findByRole("heading", { name: "Access denied" })).toBeInTheDocument();
    expect(screen.queryByText("audit page")).not.toBeInTheDocument();
  });

  it("allows the page when the permission is present", async () => {
    mockFetch({ "POST /api/v1/auth/refresh": refreshAs(makeUser(["audit:view"])) });
    renderApp(routes, "/audit");
    await waitFor(() => expect(screen.getByText("audit page")).toBeInTheDocument());
  });
});
