import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router";

import { Button, Field, Input } from "@/components/ui";
import { errorMessage, post } from "@/lib/api";
import { Message } from "@/lib/schemas";
import { AuthShell } from "@/pages/auth/LoginPage";

function PasswordForm({ title, endpoint, field, done }: { title: string; endpoint: string; field: string; done: string }) {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (pw !== pw2) {
      setResult({ ok: false, text: "Passwords do not match." });
      return;
    }
    setBusy(true);
    try {
      await post(endpoint, Message, { token, [field]: pw });
      setResult({ ok: true, text: done });
    } catch (err) {
      setResult({ ok: false, text: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  }

  if (!token) return <AuthShell title={title}><p className="text-sm text-critical">This link is missing its token.</p></AuthShell>;
  return (
    <AuthShell title={title}>
      {result?.ok ? (
        <p className="text-sm">{result.text} <Link to="/login" className="text-accent hover:underline">Sign in</Link></p>
      ) : (
        <form onSubmit={submit} className="space-y-4">
          <Field label="New password" hint="At least 12 characters. A long passphrase is best.">
            <Input type="password" autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} />
          </Field>
          <Field label="Repeat password">
            <Input type="password" autoComplete="new-password" value={pw2} onChange={(e) => setPw2(e.target.value)} />
          </Field>
          {result && <p role="alert" className="text-sm text-critical">{result.text}</p>}
          <Button type="submit" className="w-full" busy={busy} disabled={!pw}>Save password</Button>
        </form>
      )}
    </AuthShell>
  );
}

export function ActivatePage() {
  return <PasswordForm title="Activate your account" endpoint="/auth/activate" field="password" done="Account activated." />;
}

export function ResetPasswordPage() {
  return <PasswordForm title="Choose a new password" endpoint="/auth/password-reset/confirm" field="new_password" done="Password updated." />;
}

export function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const r = await post("/auth/password-reset/request", Message, { email });
      setSent(r.message);
    } catch (err) {
      setSent(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <AuthShell title="Reset password">
      {sent ? <p className="text-sm">{sent}</p> : (
        <form onSubmit={submit} className="space-y-4">
          <Field label="Email"><Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} /></Field>
          <Button type="submit" className="w-full" busy={busy} disabled={!email}>Send reset link</Button>
        </form>
      )}
      <p className="mt-4 text-center text-xs"><Link to="/login" className="text-accent hover:underline">Back to sign in</Link></p>
    </AuthShell>
  );
}
