import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import {
  Activity,
  Bell,
  Bot,
  Boxes,
  BrainCircuit,
  ClipboardList,
  Crosshair,
  FileBarChart,
  FlaskConical,
  Gauge,
  LineChart,
  ListTree,
  LogOut,
  Menu,
  Moon,
  Network,
  Radar,
  ScrollText,
  Server,
  Settings,
  ShieldAlert,
  Siren,
  Sun,
  Users,
  X,
} from "lucide-react";
import { useEffect, useState, type ComponentType } from "react";
import { NavLink, Outlet, useLocation } from "react-router";

import { useAuth } from "@/auth/AuthProvider";
import { get } from "@/lib/api";
import { SystemInfo } from "@/lib/schemas";
import { useRealtime } from "@/realtime/RealtimeProvider";
import { z } from "zod";

type Item = { to: string; label: string; icon: ComponentType<{ className?: string }>; perm?: string };
const NAV: { group: string; items: Item[] }[] = [
  {
    group: "Monitor",
    items: [
      { to: "/", label: "Dashboard", icon: Gauge, perm: "events:view" },
      { to: "/live", label: "Live Monitoring", icon: Activity, perm: "events:view" },
      { to: "/events", label: "Events Explorer", icon: ListTree, perm: "events:view" },
      { to: "/topology", label: "Network Topology", icon: Network, perm: "events:view" },
    ],
  },
  {
    group: "Detect",
    items: [
      { to: "/detections", label: "Detection Center", icon: Radar, perm: "detections:view" },
      { to: "/unknown", label: "Unknown Attack Center", icon: Crosshair, perm: "detections:view" },
      { to: "/alerts", label: "Alerts", icon: ShieldAlert, perm: "alerts:view" },
      { to: "/mitre", label: "MITRE ATT&CK", icon: Boxes, perm: "detections:view" },
      { to: "/threat-intel", label: "Threat Intelligence", icon: ScrollText, perm: "threat_intel:view" },
    ],
  },
  {
    group: "Respond",
    items: [
      { to: "/incidents", label: "Incidents", icon: Siren, perm: "incidents:view" },
      { to: "/assistant", label: "AI Assistant", icon: Bot, perm: "assistant:use" },
      { to: "/assets", label: "Assets", icon: Server, perm: "assets:view" },
      { to: "/reports", label: "Reports", icon: FileBarChart, perm: "reports:view" },
    ],
  },
  {
    group: "Models",
    items: [
      { to: "/models", label: "ML Models", icon: BrainCircuit, perm: "models:view" },
      { to: "/models/evaluation", label: "Model Evaluation", icon: FlaskConical, perm: "models:view" },
      { to: "/models/drift", label: "Model Drift", icon: LineChart, perm: "models:view" },
    ],
  },
  {
    group: "Administration",
    items: [
      { to: "/notifications", label: "Notifications", icon: Bell },
      { to: "/audit", label: "Audit Logs", icon: ClipboardList, perm: "audit:view" },
      { to: "/users", label: "User Management", icon: Users, perm: "users:manage" },
      { to: "/settings", label: "Settings", icon: Settings },
    ],
  },
];

function useTheme(): [boolean, () => void] {
  const [dark, setDark] = useState(() => {
    try {
      return (localStorage.getItem("znids-theme") ?? "dark") === "dark";
    } catch {
      return true;
    }
  });
  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    try {
      localStorage.setItem("znids-theme", dark ? "dark" : "light");
    } catch {
      /* private mode: theme just won't persist */
    }
  }, [dark]);
  return [dark, () => setDark((d) => !d)];
}

export function AppLayout() {
  const { user, can, logout } = useAuth();
  const { status } = useRealtime();
  const [dark, toggleTheme] = useTheme();
  const [open, setOpen] = useState(false);
  const location = useLocation();
  const info = useQuery({ queryKey: ["system-info"], queryFn: () => get("/system/info", SystemInfo), staleTime: 300_000 });
  const unread = useQuery({
    queryKey: ["notifications", "unread"],
    queryFn: () => get("/notifications/unread-count", z.object({ unread: z.number() })),
  });

  // Close the mobile drawer whenever the route changes.
  const [lastPath, setLastPath] = useState(location.pathname);
  if (lastPath !== location.pathname) {
    setLastPath(location.pathname);
    setOpen(false);
  }

  const nav = (
    <nav aria-label="Main" className="flex-1 space-y-4 overflow-y-auto px-2 py-3">
      {NAV.map((g) => {
        const items = g.items.filter((i) => !i.perm || can(i.perm));
        if (!items.length) return null;
        return (
          <div key={g.group}>
            <div className="px-2 pb-1 text-[11px] font-semibold uppercase tracking-wider text-muted">{g.group}</div>
            {items.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                end={to === "/" || to === "/models"}
                className={({ isActive }) =>
                  clsx(
                    "flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm",
                    isActive ? "bg-accent-soft font-medium text-accent" : "text-ink/85 hover:bg-surface-2",
                  )
                }
              >
                <Icon className="size-4 shrink-0" />
                {label}
              </NavLink>
            ))}
          </div>
        );
      })}
    </nav>
  );

  return (
    <div className="flex h-full">
      <aside
        className={clsx(
          "fixed inset-y-0 left-0 z-40 flex w-60 flex-col border-r border-line bg-surface transition-transform lg:static lg:translate-x-0",
          open ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className="flex h-14 items-center gap-2 border-b border-line px-4">
          <ShieldAlert className="size-5 text-accent" aria-hidden />
          <div>
            <div className="text-sm font-bold tracking-wide">Z-NIDS</div>
            <div className="text-[10px] text-muted">Zero-Day NIDS &amp; Response</div>
          </div>
          <button className="ml-auto lg:hidden" onClick={() => setOpen(false)} aria-label="Close menu">
            <X className="size-5" />
          </button>
        </div>
        {nav}
      </aside>
      {open && <div className="fixed inset-0 z-30 bg-black/40 lg:hidden" onClick={() => setOpen(false)} aria-hidden />}

      <div className="flex min-w-0 flex-1 flex-col">
        {info.data?.demo_mode && (
          <div className="bg-unknown px-4 py-1 text-center text-xs font-semibold tracking-wide text-white" role="note">
            LAB / DEMO DATA — synthetic telemetry mode is enabled; records marked "lab" are generated, not real traffic.
          </div>
        )}
        <header className="flex h-14 items-center gap-3 border-b border-line bg-surface px-4">
          <button className="lg:hidden" onClick={() => setOpen(true)} aria-label="Open menu">
            <Menu className="size-5" />
          </button>
          <div className="ml-auto flex items-center gap-3">
            <span
              className={clsx(
                "flex items-center gap-1.5 text-xs",
                status === "live" ? "text-ok" : status === "connecting" ? "text-medium" : "text-muted",
              )}
              title="Real-time connection"
            >
              <span className={clsx("size-2 rounded-full", status === "live" ? "bg-ok" : status === "connecting" ? "bg-medium" : "bg-muted")} />
              {status === "live" ? "Live" : status === "connecting" ? "Connecting" : "Offline"}
            </span>
            <NavLink to="/notifications" className="relative rounded-md p-1.5 hover:bg-surface-2" aria-label="Notifications">
              <Bell className="size-4" />
              {(unread.data?.unread ?? 0) > 0 && (
                <span className="absolute -right-0.5 -top-0.5 rounded-full bg-critical px-1 text-[10px] font-bold text-white">
                  {unread.data?.unread}
                </span>
              )}
            </NavLink>
            <button onClick={toggleTheme} className="rounded-md p-1.5 hover:bg-surface-2" aria-label="Toggle colour theme">
              {dark ? <Sun className="size-4" /> : <Moon className="size-4" />}
            </button>
            <div className="hidden text-right text-xs sm:block">
              <div className="font-medium">{user?.name}</div>
              <div className="text-muted">{user?.role.name.replace(/_/g, " ")}</div>
            </div>
            <button onClick={() => void logout()} className="rounded-md p-1.5 hover:bg-surface-2" aria-label="Sign out">
              <LogOut className="size-4" />
            </button>
          </div>
        </header>
        <main className="min-w-0 flex-1 overflow-y-auto p-4 md:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
