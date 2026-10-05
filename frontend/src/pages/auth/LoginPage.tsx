import { ShieldAlert } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router";

import { useAuth } from "@/auth/AuthProvider";
import { Button, Field, Input } from "@/components/ui";
import { ApiError, errorMessage } from "@/lib/api";

export function AuthShell({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="flex min-h-full items-center justify-center p-4">
      <div className="w-full max-w-sm rounded-xl border border-line bg-surface p-6 shadow-sm">
        <div className="mb-6 flex items-center gap-2">
          <ShieldAlert className="size-6 text-accent" aria-hidden />
          <div>
            <div className="font-bold tracking-wide">Z-NIDS</div>
            <div className="text-xs text-muted">Zero-Day Network Intrusion Detection &amp; Response</div>
          </div>
        </div>
        <h1 className="mb-4 text-lg font-semibold">{title}</h1>
        {children}
      </div>
    </div>
  );
}

export default function LoginPage() {
  const { user, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Return to the page that sent the user here (set by RequireAuth). Both the
  // post-login navigate and the already-signed-in redirect use it.
  const from = (location.state as { from?: string } | null)?.from;
  const destination = from && from !== "/login" ? from : "/";
  if (user) return <Navigate to={destination} replace />;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(email, password);
      navigate(destination, { replace: true });
    } catch (err) {
      setError(err instanceof ApiError && err.code === "RATE_LIMITED" ? "Too many attempts. Wait a minute and try again." : errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell title="Sign in">
      <form onSubmit={submit} className="space-y-4" noValidate>
        <Field label="Email">
          <Input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </Field>
        <Field label="Password">
          <Input type="password" autoComplete="current-password" required value={password}
                 onChange={(e) => setPassword(e.target.value)} />
        </Field>
        {error && <p role="alert" className="text-sm text-critical">{error}</p>}
        <Button type="submit" className="w-full" busy={busy} disabled={!email || !password}>Sign in</Button>
        <p className="text-center text-xs text-muted">
          <Link to="/forgot-password" className="text-accent hover:underline">Forgot password?</Link>
        </p>
      </form>
    </AuthShell>
  );
}
