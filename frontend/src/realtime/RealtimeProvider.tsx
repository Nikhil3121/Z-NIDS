/**
 * Authenticated WebSocket connection to /api/v1/ws.
 *
 * The access token is sent in the first message (not the URL, so it never lands
 * in logs). Incoming typed events invalidate the relevant React Query caches, so
 * pages update from the server instead of polling. Reconnects with backoff.
 */
import { useQueryClient } from "@tanstack/react-query";
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";

import { useAuth } from "@/auth/AuthProvider";
import { getAccessToken, onTokenChange } from "@/lib/api";

export type ConnectionState = "connecting" | "live" | "offline";
export interface RealtimeMessage {
  type: string;
  ts?: string;
  data: Record<string, unknown>;
}

interface RealtimeState {
  status: ConnectionState;
  last: RealtimeMessage[];
  subscribe: (fn: (m: RealtimeMessage) => void) => () => void;
}

const Ctx = createContext<RealtimeState>({ status: "offline", last: [], subscribe: () => () => undefined });

const INVALIDATIONS: Record<string, string[][]> = {
  "security.alert.created": [["alerts"], ["dashboard"], ["unknown"]],
  "security.alert.updated": [["alerts"], ["dashboard"], ["unknown"]],
  "security.incident.created": [["incidents"], ["dashboard"]],
  "security.incident.updated": [["incidents"], ["incident"], ["dashboard"]],
  "network.event.created": [["dashboard"], ["events"], ["detections"], ["live"]],
  "asset.updated": [["assets"]],
  "model.drift.detected": [["drift"], ["alerts"]],
  "response.action.updated": [["response"], ["incident"]],
  "notification.created": [["notifications"]],
};

function wsUrl(): string {
  const { protocol, host } = window.location;
  return `${protocol === "https:" ? "wss" : "ws"}://${host}/api/v1/ws`;
}

export function RealtimeProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const qc = useQueryClient();
  const [status, setStatus] = useState<ConnectionState>("offline");
  const [last, setLast] = useState<RealtimeMessage[]>([]);
  const subscribers = useRef(new Set<(m: RealtimeMessage) => void>());
  const [tokenTick, setTokenTick] = useState(0);

  useEffect(() => onTokenChange(() => setTokenTick((t) => t + 1)), []);

  useEffect(() => {
    if (!user) return;
    let ws: WebSocket | null = null;
    let retry = 0;
    let stopped = false;
    let timer: number | undefined;
    let ping: number | undefined;

    const connect = () => {
      const token = getAccessToken();
      if (!token || stopped) return;
      setStatus("connecting");
      ws = new WebSocket(wsUrl());
      ws.onopen = () => ws?.send(JSON.stringify({ type: "auth", token }));
      ws.onmessage = (ev) => {
        let msg: RealtimeMessage;
        try {
          msg = JSON.parse(String(ev.data)) as RealtimeMessage;
        } catch {
          return;
        }
        if (msg.type === "ready") {
          retry = 0;
          setStatus("live");
          ping = window.setInterval(() => ws?.readyState === WebSocket.OPEN && ws.send("ping"), 25_000);
          return;
        }
        if (msg.type === "pong" || msg.type === "error") return;
        for (const key of INVALIDATIONS[msg.type] ?? []) void qc.invalidateQueries({ queryKey: key });
        setLast((prev) => [msg, ...prev].slice(0, 50));
        subscribers.current.forEach((fn) => fn(msg));
      };
      ws.onclose = () => {
        window.clearInterval(ping);
        setStatus("offline");
        if (stopped) return;
        retry += 1;
        timer = window.setTimeout(connect, Math.min(30_000, 1000 * 2 ** Math.min(retry, 5)));
      };
    };
    connect();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      window.clearInterval(ping);
      ws?.close();
    };
  }, [user, qc, tokenTick]);

  const subscribe = (fn: (m: RealtimeMessage) => void) => {
    subscribers.current.add(fn);
    return () => {
      subscribers.current.delete(fn);
    };
  };

  return <Ctx.Provider value={{ status, last, subscribe }}>{children}</Ctx.Provider>;
}

export function useRealtime(): RealtimeState {
  return useContext(Ctx);
}
