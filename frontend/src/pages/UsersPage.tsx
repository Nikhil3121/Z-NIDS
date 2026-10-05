import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { z } from "zod";

import { useAuth } from "@/auth/AuthProvider";
import { Button, Card, ErrorState, Field, Input, PageHeader, Pager, Select, Spinner, StatusPill, Table } from "@/components/ui";
import { errorMessage, get, patch, post } from "@/lib/api";
import { fmtAgo } from "@/lib/format";
import { Message, page, User } from "@/lib/schemas";

const UserPage = page(User);
const ROLES = ["ADMIN", "SECURITY_MANAGER", "SECURITY_ANALYST", "VIEWER"];

export default function UsersPage() {
  const qc = useQueryClient();
  const { user: me } = useAuth();
  const [pageNo, setPageNo] = useState(1);
  const [error, setError] = useState<string | null>(null);
  const q = useQuery({ queryKey: ["users", pageNo], queryFn: () => get("/users", UserPage, { page: pageNo, page_size: 50 }), placeholderData: keepPreviousData });
  const update = useMutation({
    mutationFn: ({ id, body }: { id: number; body: Record<string, unknown> }) => patch(`/users/${id}`, User, body),
    onSuccess: () => { setError(null); void qc.invalidateQueries({ queryKey: ["users"] }); },
    onError: (e) => setError(errorMessage(e)),
  });
  const resend = useMutation({ mutationFn: (id: number) => post(`/users/${id}/resend-activation`, Message), onError: (e) => setError(errorMessage(e)) });

  return (
    <>
      <PageHeader title="User Management" subtitle="New users receive an activation link by email and set their own password. Role changes and deactivation end the user's sessions immediately." />
      <InviteUser />
      {error && <p className="my-2 text-sm text-critical">{error}</p>}
      <Card dense className="mt-4">
        {q.isPending && <Spinner />}
        {q.isError && <div className="p-3"><ErrorState error={q.error} /></div>}
        {q.data && (
          <>
            <Table head={["Name", "Email", "Role", "Status", "Last login", ""]}>
              {q.data.items.map((u) => (
                <tr key={u.id}>
                  <td className="px-3 py-2">{u.name}</td>
                  <td className="px-3 py-2 text-sm">{u.email}</td>
                  <td className="px-3 py-2">
                    <Select value={u.role.name} aria-label={`Role of ${u.email}`} disabled={u.id === me?.id}
                            onChange={(e) => { if (window.confirm(`Change ${u.email} to ${e.target.value}?`)) update.mutate({ id: u.id, body: { role: e.target.value } }); }}>
                      {ROLES.map((r) => <option key={r} value={r}>{r.replace(/_/g, " ")}</option>)}
                    </Select>
                  </td>
                  <td className="px-3 py-2"><StatusPill value={u.is_active ? "ACTIVE" : "INACTIVE"} /></td>
                  <td className="px-3 py-2 text-xs text-muted">{fmtAgo(u.last_login)}</td>
                  <td className="whitespace-nowrap px-3 py-2">
                    {u.id !== me?.id && (u.is_active
                      ? <Button size="sm" variant="ghost" onClick={() => update.mutate({ id: u.id, body: { is_active: false } })}>Deactivate</Button>
                      : u.last_login
                        ? <Button size="sm" variant="ghost" onClick={() => update.mutate({ id: u.id, body: { is_active: true } })}>Reactivate</Button>
                        : <Button size="sm" variant="ghost" busy={resend.isPending && resend.variables === u.id} onClick={() => resend.mutate(u.id)}>Resend activation</Button>)}
                  </td>
                </tr>
              ))}
            </Table>
            <Pager page={q.data.page} pages={q.data.pages} total={q.data.total} onPage={setPageNo} />
          </>
        )}
      </Card>
    </>
  );
}

function InviteUser() {
  const qc = useQueryClient();
  const [form, setForm] = useState({ email: "", name: "", role: "SECURITY_ANALYST" });
  const [result, setResult] = useState<string | null>(null);
  const mut = useMutation({
    mutationFn: () => post("/users", User.extend({ activation_email_sent: z.boolean() }), form),
    onSuccess: (u) => {
      setResult(u.activation_email_sent ? `Activation link sent to ${u.email}.` : `User created, but the activation email could not be sent — use "Resend activation" once email is configured.`);
      setForm({ email: "", name: "", role: "SECURITY_ANALYST" });
      void qc.invalidateQueries({ queryKey: ["users"] });
    },
    onError: (e) => setResult(errorMessage(e)),
  });
  const submit = (e: FormEvent) => { e.preventDefault(); mut.mutate(); };
  return (
    <Card title="Invite user">
      <form onSubmit={submit} className="grid items-end gap-3 md:grid-cols-4">
        <Field label="Name"><Input required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
        <Field label="Email"><Input type="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></Field>
        <Field label="Role"><Select className="w-full" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
          {ROLES.map((r) => <option key={r} value={r}>{r.replace(/_/g, " ")}</option>)}</Select></Field>
        <Button type="submit" busy={mut.isPending}>Send invitation</Button>
      </form>
      {result && <p className="mt-2 text-sm">{result}</p>}
    </Card>
  );
}
