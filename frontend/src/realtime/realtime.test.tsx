import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuthProvider } from "@/auth/AuthProvider";
import { setAccessToken } from "@/lib/api";
import { RealtimeProvider, useRealtime } from "@/realtime/RealtimeProvider";
import { makeUser, mockFetch, refreshAs } from "@/test/utils";

class FakeSocket {
  static OPEN = 1;
  static instances: FakeSocket[] = [];
  readyState = 0;
  sent: string[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  url: string;
  constructor(url: string) {
    this.url = url;
    FakeSocket.instances.push(this);
  }
  send(data: string) {
    this.sent.push(data);
  }
  close() {
    this.readyState = 3;
  }
  open() {
    this.readyState = 1;
    this.onopen?.();
  }
  push(msg: unknown) {
    this.onmessage?.({ data: JSON.stringify(msg) });
  }
}

function Status() {
  const { status, last } = useRealtime();
  return <p>status:{status} events:{last.length}</p>;
}

beforeEach(() => {
  FakeSocket.instances = [];
  vi.stubGlobal("WebSocket", FakeSocket);
});
afterEach(() => {
  vi.unstubAllGlobals();
  setAccessToken(null);
});

describe("realtime", () => {
  it("authenticates in the first message and invalidates queries on events", async () => {
    mockFetch({ "POST /api/v1/auth/refresh": refreshAs(makeUser(["events:view"])) });
    const qc = new QueryClient();
    const spy = vi.spyOn(qc, "invalidateQueries");
    render(
      <QueryClientProvider client={qc}>
        <AuthProvider><RealtimeProvider><Status /></RealtimeProvider></AuthProvider>
      </QueryClientProvider>,
    );
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1));
    const ws = FakeSocket.instances[0];
    expect(ws.url).toMatch(/\/api\/v1\/ws$/);
    expect(ws.url).not.toContain("test-access");

    act(() => ws.open());
    expect(JSON.parse(ws.sent[0])).toEqual({ type: "auth", token: "test-access" });

    act(() => ws.push({ type: "ready", data: {} }));
    expect(await screen.findByText(/status:live/)).toBeInTheDocument();

    act(() => ws.push({ type: "security.alert.created", data: { id: 7 } }));
    expect(spy).toHaveBeenCalledWith({ queryKey: ["alerts"] });
    expect(spy).toHaveBeenCalledWith({ queryKey: ["dashboard"] });
    expect(await screen.findByText(/events:1/)).toBeInTheDocument();
  });

  it("does not connect without a session", async () => {
    mockFetch({ "POST /api/v1/auth/refresh": refreshAs(null) });
    render(
      <QueryClientProvider client={new QueryClient()}>
        <AuthProvider><RealtimeProvider><Status /></RealtimeProvider></AuthProvider>
      </QueryClientProvider>,
    );
    await screen.findByText(/status:offline/);
    expect(FakeSocket.instances).toHaveLength(0);
  });
});
