import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router";

import { useAuth } from "@/auth/AuthProvider";
import { Spinner } from "@/components/ui";

/** UI-level route guard. The backend enforces every permission independently. */
export function RequireAuth({ children, permission }: { children: ReactNode; permission?: string }) {
  const { user, loading, can } = useAuth();
  const location = useLocation();
  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <Spinner label="Restoring session" />
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  if (permission && !can(permission)) {
    return (
      <div className="mx-auto mt-20 max-w-md rounded-lg border border-line bg-surface p-6 text-center">
        <h1 className="text-lg font-semibold">Access denied</h1>
        <p className="mt-2 text-sm text-muted">Your role does not include the permission required for this page.</p>
      </div>
    );
  }
  return <>{children}</>;
}

export function Can({ permission, children }: { permission: string; children: ReactNode }) {
  const { can } = useAuth();
  return can(permission) ? <>{children}</> : null;
}
