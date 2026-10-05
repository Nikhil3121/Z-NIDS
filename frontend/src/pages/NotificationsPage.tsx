import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { useState } from "react";
import { Link } from "react-router";
import { z } from "zod";

import { Button, Card, ErrorState, PageHeader, Pager, Spinner, Table } from "@/components/ui";
import { get, post, put } from "@/lib/api";
import { fmtAgo, titleCase } from "@/lib/format";
import { Message, NotificationItem, page, Preference } from "@/lib/schemas";

const NotificationPage = page(NotificationItem);
const LINK: Record<string, string> = { incident: "/incidents/", alert: "/alerts/", ml_model: "/models/drift?model=" };

export default function NotificationsPage() {
  const qc = useQueryClient();
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [pageNo, setPageNo] = useState(1);
  const q = useQuery({
    queryKey: ["notifications", "inbox", unreadOnly, pageNo],
    queryFn: () => get("/notifications", NotificationPage, { unread_only: unreadOnly || undefined, page: pageNo, page_size: 25 }),
    placeholderData: keepPreviousData,
  });
  const markAll = useMutation({ mutationFn: () => post("/notifications/read", Message), onSuccess: () => void qc.invalidateQueries({ queryKey: ["notifications"] }) });

  return (
    <>
      <PageHeader title="Notifications" subtitle="In-app notifications for your account, and how you want to be notified."
                  actions={<Button variant="outline" busy={markAll.isPending} onClick={() => markAll.mutate()}>Mark all read</Button>} />
      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Inbox" className="xl:col-span-2" dense
              actions={<label className="flex items-center gap-1 text-xs"><input type="checkbox" checked={unreadOnly} onChange={(e) => { setUnreadOnly(e.target.checked); setPageNo(1); }} /> Unread only</label>}>
          {q.isPending && <Spinner />}
          {q.isError && <div className="p-3"><ErrorState error={q.error} /></div>}
          {q.data && (
            <>
              <ul className="divide-y divide-line">
                {q.data.items.length === 0 && <li className="p-4 text-sm text-muted">No notifications.</li>}
                {q.data.items.map((n) => (
                  <li key={n.id} className={clsx("px-3 py-2 text-sm", !n.read_at && "bg-accent-soft/40")}>
                    <div className="flex items-center gap-2">
                      {!n.read_at && <span className="size-2 rounded-full bg-accent" aria-label="unread" />}
                      {n.resource_type && n.resource_id && LINK[n.resource_type]
                        ? <Link to={`${LINK[n.resource_type]}${n.resource_id}`} className="font-medium hover:underline">{n.title}</Link>
                        : <span className="font-medium">{n.title}</span>}
                      <span className="ml-auto text-xs text-muted">{fmtAgo(n.created_at)}</span>
                    </div>
                    <p className="mt-0.5 whitespace-pre-wrap text-xs text-muted">{n.body}</p>
                  </li>
                ))}
              </ul>
              <Pager page={q.data.page} pages={q.data.pages} total={q.data.total} onPage={setPageNo} />
            </>
          )}
        </Card>
        <Preferences />
      </div>
    </>
  );
}

function Preferences() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["notifications", "prefs"], queryFn: () => get("/users/me/notification-preferences", z.array(Preference)) });
  const save = useMutation({
    mutationFn: (prefs: z.infer<typeof Preference>[]) => put("/users/me/notification-preferences", z.array(Preference), prefs),
    onSuccess: (data) => qc.setQueryData(["notifications", "prefs"], data),
  });
  if (!q.data) return <Card title="Preferences">{q.isError ? <ErrorState error={q.error} /> : <Spinner />}</Card>;
  const toggle = (event: string, field: "in_app" | "email") =>
    save.mutate(q.data.map((p) => (p.event_type === event ? { ...p, [field]: !p[field] } : p)));
  return (
    <Card title="Preferences" dense>
      <Table head={["Event", "In-app", "Email"]}>
        {q.data.map((p) => (
          <tr key={p.event_type}>
            <td className="px-3 py-1.5 text-sm">{titleCase(p.event_type)}</td>
            <td className="px-3 py-1.5"><input type="checkbox" checked={p.in_app} onChange={() => toggle(p.event_type, "in_app")} aria-label={`${p.event_type} in-app`} /></td>
            <td className="px-3 py-1.5"><input type="checkbox" checked={p.email} onChange={() => toggle(p.event_type, "email")} aria-label={`${p.event_type} email`} /></td>
          </tr>
        ))}
      </Table>
    </Card>
  );
}
