import { useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { API_BASE, post, refreshSession, setAccessToken } from "@/lib/api";
import { Me, TokenResponse } from "@/lib/schemas";

interface AuthState {
  user: Me | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  can: (permission: string) => boolean;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const qc = useQueryClient();
  const refreshTimer = useRef<number | null>(null);

  const schedule = useCallback((expiresIn: number) => {
    // Refresh a minute before expiry; the backend rotates the refresh cookie each time.
    const arm = (seconds: number) => {
      if (refreshTimer.current) window.clearTimeout(refreshTimer.current);
      refreshTimer.current = window.setTimeout(async () => {
        const r = await refreshSession();
        if (r) {
          setUser(Me.parse(r.user));
          arm(r.expires_in);
        } else {
          setUser(null);
        }
      }, Math.max(15, seconds - 60) * 1000);
    };
    arm(expiresIn);
  }, []);

  useEffect(() => {
    // Restore a session from the HttpOnly refresh cookie on page load.
    let cancelled = false;
    refreshSession()
      .then((r) => {
        if (!cancelled && r) {
          setUser(Me.parse(r.user));
          schedule(r.expires_in);
        }
      })
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
      if (refreshTimer.current) window.clearTimeout(refreshTimer.current);
    };
  }, [schedule]);

  const login = useCallback(
    async (email: string, password: string) => {
      const r = await post("/auth/login", TokenResponse, { email, password });
      setAccessToken(r.access_token);
      setUser(r.user);
      schedule(r.expires_in);
    },
    [schedule],
  );

  const logout = useCallback(async () => {
    try {
      await fetch(`${API_BASE}/api/v1/auth/logout`, { method: "POST", credentials: "include", headers: { "X-ZNIDS-CSRF": "1" } });
    } finally {
      setAccessToken(null);
      setUser(null);
      qc.clear();
      if (refreshTimer.current) window.clearTimeout(refreshTimer.current);
    }
  }, [qc]);

  const can = useCallback((permission: string) => Boolean(user?.permissions.includes(permission)), [user]);

  const value = useMemo(() => ({ user, loading, login, logout, can }), [user, loading, login, logout, can]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
