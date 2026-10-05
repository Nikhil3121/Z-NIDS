import { lazy, Suspense, type ComponentType, type LazyExoticComponent } from "react";
import { createBrowserRouter, RouterProvider } from "react-router";

import { RequireAuth } from "@/auth/guards";
import { Spinner } from "@/components/ui";
import { AppLayout } from "@/layouts/AppLayout";
import LoginPage from "@/pages/auth/LoginPage";
import { ActivatePage, ForgotPasswordPage, ResetPasswordPage } from "@/pages/auth/TokenPages";

type Page = LazyExoticComponent<ComponentType>;
const page = (loader: () => Promise<{ default: ComponentType }>): Page => lazy(loader);

// Route-level code splitting: each page is its own chunk.
const pages: { path: string; perm?: string; component: Page }[] = [
  { path: "/", perm: "events:view", component: page(() => import("@/pages/DashboardPage")) },
  { path: "/live", perm: "events:view", component: page(() => import("@/pages/LivePage")) },
  { path: "/events", perm: "events:view", component: page(() => import("@/pages/EventsPage")) },
  { path: "/topology", perm: "events:view", component: page(() => import("@/pages/TopologyPage")) },
  { path: "/detections", perm: "detections:view", component: page(() => import("@/pages/DetectionsPage")) },
  { path: "/detections/:id", perm: "detections:view", component: page(() => import("@/pages/DetectionsPage").then((m) => ({ default: m.DetectionDetailPage }))) },
  { path: "/unknown", perm: "detections:view", component: page(() => import("@/pages/UnknownAttacksPage")) },
  { path: "/alerts", perm: "alerts:view", component: page(() => import("@/pages/AlertsPage")) },
  { path: "/alerts/:id", perm: "alerts:view", component: page(() => import("@/pages/AlertsPage").then((m) => ({ default: m.AlertDetailPage }))) },
  { path: "/mitre", perm: "detections:view", component: page(() => import("@/pages/MitrePage")) },
  { path: "/threat-intel", perm: "threat_intel:view", component: page(() => import("@/pages/ThreatIntelPage")) },
  { path: "/incidents", perm: "incidents:view", component: page(() => import("@/pages/IncidentsPage")) },
  { path: "/incidents/:id", perm: "incidents:view", component: page(() => import("@/pages/InvestigationPage")) },
  { path: "/assistant", perm: "assistant:use", component: page(() => import("@/pages/AssistantPage")) },
  { path: "/assets", perm: "assets:view", component: page(() => import("@/pages/AssetsPage")) },
  { path: "/assets/:id", perm: "assets:view", component: page(() => import("@/pages/AssetsPage").then((m) => ({ default: m.AssetDetailPage }))) },
  { path: "/reports", perm: "reports:view", component: page(() => import("@/pages/ReportsPage")) },
  { path: "/models", perm: "models:view", component: page(() => import("@/pages/ModelsPage")) },
  { path: "/models/evaluation", perm: "models:view", component: page(() => import("@/pages/EvaluationPage")) },
  { path: "/models/drift", perm: "models:view", component: page(() => import("@/pages/DriftPage")) },
  { path: "/notifications", component: page(() => import("@/pages/NotificationsPage")) },
  { path: "/audit", perm: "audit:view", component: page(() => import("@/pages/AuditPage")) },
  { path: "/users", perm: "users:manage", component: page(() => import("@/pages/UsersPage")) },
  { path: "/settings", component: page(() => import("@/pages/SettingsPage")) },
];

function guarded(component: Page, perm?: string) {
  const C = component;
  return (
    <RequireAuth permission={perm}>
      <Suspense fallback={<Spinner />}>
        <C />
      </Suspense>
    </RequireAuth>
  );
}

const router = createBrowserRouter([
  { path: "/login", element: <LoginPage /> },
  { path: "/activate", element: <ActivatePage /> },
  { path: "/reset-password", element: <ResetPasswordPage /> },
  { path: "/forgot-password", element: <ForgotPasswordPage /> },
  {
    element: (
      <RequireAuth>
        <AppLayout />
      </RequireAuth>
    ),
    children: [
      ...pages.map(({ path, perm, component }) => ({ path, element: guarded(component, perm) })),
      {
        path: "*",
        element: (
          <div className="mx-auto mt-20 max-w-md text-center">
            <h1 className="text-lg font-semibold">Page not found</h1>
            <p className="mt-2 text-sm text-muted">The address does not match any Z-NIDS page.</p>
          </div>
        ),
      },
    ],
  },
]);

export default function App() {
  return <RouterProvider router={router} />;
}
