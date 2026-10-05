import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, Paperclip } from "lucide-react";
import { useRef, useState, type FormEvent } from "react";
import { Link, useParams } from "react-router";
import { z } from "zod";

import { useAuth } from "@/auth/AuthProvider";
import { Can } from "@/auth/guards";
import { FactorList, MitreList, RiskBreakdown } from "@/components/Explanation";
import { Button, Card, ClassificationBadge, DemoTag, Empty, ErrorState, Field, Input, KeyValue, Mono, PageHeader, RiskBar, Select, SeverityBadge, Spinner, StatusPill, Table } from "@/components/ui";
import { API_BASE, api, errorMessage, get, getAccessToken, patch, post } from "@/lib/api";
import { fmtBytes, fmtTime, titleCase } from "@/lib/format";
import { EvidenceItem, Incident, Investigation, ResponseAction, type IncidentStatus } from "@/lib/schemas";

const NEXT: Record<IncidentStatus, IncidentStatus[]> = {
  NEW: ["ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"],
  ACKNOWLEDGED: ["INVESTIGATING", "RESOLVED"],
  INVESTIGATING: ["CONFIRMED", "RESOLVED"],
  CONFIRMED: ["CONTAINED", "RESOLVED"],
  CONTAINED: ["RESOLVED"],
  RESOLVED: ["INVESTIGATING"],
};
const Directory = z.array(z.object({ id: z.number(), name: z.string(), role: z.string() }));

export default function InvestigationPage() {
  const { id } = useParams();
  const q = useQuery({ queryKey: ["incident", id], queryFn: () => get(`/incidents/${id}/investigation`, Investigation) });
  if (q.isPending) return <Spinner label="Loading investigation" />;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  return <InvestigationView inv={q.data} />;
}

function InvestigationView({ inv }: { inv: Investigation }) {
  const i = inv.incident;
  const primary = inv.detections.reduce<(typeof inv.detections)[number] | null>(
    (best, d) => (!best || d.risk_score > best.risk_score ? d : best), null);
  return (
    <>
      <PageHeader
        title={`${i.reference}: ${i.title}`}
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={i.severity} /> <StatusPill value={i.status} /> <ClassificationBadge value={i.classification} />
            <DemoTag show={i.is_demo} />
            <span>opened {fmtTime(i.created_at)} · rule {i.correlation_rule ?? "manual"}</span>
          </span>
        }
      />
      {i.classification === "POTENTIAL_UNKNOWN" && (
        <p className="mb-4 rounded-md border border-unknown/40 bg-unknown/10 p-3 text-sm">
          This incident contains <strong>previously unseen behaviour</strong>: no signature or known attack family matched.
          Treat it as a hypothesis to investigate. It is not proof of a zero-day vulnerability.
        </p>
      )}
      <div className="grid gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          <Card title="Summary">
            <p className="mb-3 text-sm">{inv.description}</p>
            <KeyValue items={[
              ["Risk", <RiskBar key="r" value={i.risk_score} />],
              ["Sources", <Mono key="s">{inv.summary.sources.join(", ") || "—"}</Mono>],
              ["Destinations", <Mono key="d">{inv.summary.destinations.slice(0, 12).join(", ") || "—"}</Mono>],
              ["Alerts / detections", `${inv.summary.alert_count} / ${inv.summary.detection_count}`],
              ["First / last seen", `${fmtTime(i.first_seen)} → ${fmtTime(i.last_seen)}`],
              ["Assignee", i.assigned_to?.name ?? "unassigned"],
              ["Resolution", i.resolution ? `${i.resolution} — ${inv.resolution_notes ?? ""}` : "—"],
            ]} />
            {inv.attack_chain.length > 0 && (
              <div className="mt-4">
                <div className="mb-1 text-xs font-medium uppercase tracking-wide text-muted">Attack chain</div>
                <ol className="flex flex-wrap items-center gap-1 text-xs">
                  {inv.attack_chain.map((c, n) => (
                    <li key={`${c.alert_id}-${n}`} className="flex items-center gap-1">
                      {n > 0 && <span className="text-muted">→</span>}
                      <Link to={`/alerts/${c.alert_id}`} className="rounded border border-line px-1.5 py-0.5 hover:bg-surface-2">
                        {titleCase(c.stage)} · {c.category.replace(/_/g, " ")}
                      </Link>
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </Card>
          <div className="grid gap-4 lg:grid-cols-2">
            <Card title="Why it was flagged (highest-risk detection)">
              <FactorList factors={inv.summary.primary_explanation} />
              {primary && <p className="mt-2 text-xs text-muted">From <Link to={`/detections/${primary.id}`} className="hover:underline">DET-{primary.id}</Link></p>}
            </Card>
            <Card title="Risk breakdown"><RiskBreakdown components={inv.summary.risk_components} /></Card>
          </div>
          <Card title="Timeline" dense>
            <ol className="max-h-96 divide-y divide-line overflow-y-auto text-sm">
              {inv.timeline.map((t, n) => (
                <li key={`${t.kind}-${t.id}-${n}`} className="grid grid-cols-[140px_80px_1fr] gap-2 px-3 py-2">
                  <span className="tabular text-xs text-muted">{fmtTime(t.ts)}</span>
                  <span className="text-xs uppercase text-muted">{t.kind}</span>
                  <span className="min-w-0 break-words">
                    {t.kind === "detection" ? <Link to={`/detections/${t.id}`} className="hover:underline">{t.title}</Link>
                      : t.kind === "alert" ? <Link to={`/alerts/${t.id}`} className="hover:underline">{t.title}</Link> : t.title}
                  </span>
                </li>
              ))}
            </ol>
          </Card>
          <Card title="MITRE ATT&CK hypotheses"><MitreList items={inv.mitre} /></Card>
          <Card title={`Related events (±10 min around the source, max 200)`} dense>
            {!inv.related_events_visible ? <p className="p-3 text-sm text-muted">Your role cannot view raw events.</p> : (
              <Table head={["Time", "Flow", "Proto", "Sent / received", "Verdict"]} empty={inv.related_events.length === 0}>
                {inv.related_events.slice(0, 50).map((e) => (
                  <tr key={e.id}>
                    <td className="whitespace-nowrap px-3 py-1.5 text-xs">{fmtTime(e.ts)}</td>
                    <td className="px-3 py-1.5"><Mono>{e.src_ip} → {e.dst_ip}:{e.dst_port ?? "-"}</Mono></td>
                    <td className="px-3 py-1.5 uppercase">{e.protocol}</td>
                    <td className="px-3 py-1.5 text-xs">{fmtBytes(e.bytes_out)} / {fmtBytes(e.bytes_in)}</td>
                    <td className="px-3 py-1.5"><ClassificationBadge value={e.classification} /></td>
                  </tr>
                ))}
              </Table>
            )}
          </Card>
        </div>

        <div className="space-y-4">
          <Can permission="incidents:manage"><WorkflowPanel inv={inv} /></Can>
          <Card title="Affected assets">
            {inv.affected_assets.length === 0 ? <p className="text-sm text-muted">No inventoried assets involved.</p> : (
              <ul className="space-y-2 text-sm">
                {inv.affected_assets.map((a) => (
                  <li key={a.id} className="flex items-center justify-between gap-2">
                    <Link to={`/assets/${a.id}`} className="hover:underline">{a.hostname ?? a.ip_address}</Link>
                    <span className="text-xs text-muted">{a.role} · {a.criticality}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card title="Threat intelligence">
            {inv.threat_intelligence.length === 0 ? (
              <p className="text-sm text-muted">No threat-intelligence records exist for the involved addresses.</p>
            ) : (
              <ul className="space-y-1.5 text-sm">
                {inv.threat_intelligence.map((t) => (
                  <li key={t.id}><Mono>{t.ioc_value}</Mono> — {t.reputation} by {t.provider} ({t.confidence.toFixed(0)})</li>
                ))}
              </ul>
            )}
          </Card>
          <NotesPanel inv={inv} />
          <EvidencePanel inv={inv} />
          <ResponsePanel inv={inv} />
          <Card title="Related incidents">
            {inv.related_incidents.length === 0 ? <p className="text-sm text-muted">None.</p> : (
              <ul className="space-y-1 text-sm">
                {inv.related_incidents.map((r) => (
                  <li key={r.id}><Link to={`/incidents/${r.id}`} className="text-accent hover:underline">{r.reference}</Link> {r.title}</li>
                ))}
              </ul>
            )}
          </Card>
          <Card title="Audit history">
            {!inv.audit_visible ? <p className="text-sm text-muted">Requires the audit permission.</p> : (
              <ul className="max-h-64 space-y-1 overflow-y-auto text-xs">
                {inv.audit_history.map((a, n) => (
                  <li key={n}><span className="text-muted">{fmtTime(String(a.ts))}</span> {String(a.actor)} — {String(a.action)} ({String(a.result)})</li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      </div>
    </>
  );
}

function useRefresh(id: number) {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: ["incident", String(id)] });
    void qc.invalidateQueries({ queryKey: ["incidents"] });
  };
}

function WorkflowPanel({ inv }: { inv: Investigation }) {
  const i = inv.incident;
  const refresh = useRefresh(i.id);
  const { can } = useAuth();
  const users = useQuery({ queryKey: ["directory"], queryFn: () => get("/users/directory", Directory), enabled: can("incidents:manage") });
  const [target, setTarget] = useState<string>(NEXT[i.status][0]);
  const [resolution, setResolution] = useState("TRUE_POSITIVE");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState<string | null>(null);
  const mut = useMutation({
    mutationFn: (body: Record<string, unknown>) => patch(`/incidents/${i.id}`, Incident, body),
    onSuccess: () => { setError(null); setNotes(""); refresh(); },
    onError: (e) => setError(errorMessage(e)),
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    mut.mutate(target === "RESOLVED" ? { status: target, resolution, resolution_notes: notes } : { status: target });
  };
  return (
    <Card title="Workflow">
      <form onSubmit={submit} className="space-y-3">
        <Field label="Move to">
          <Select className="w-full" value={target} onChange={(e) => setTarget(e.target.value)}>
            {NEXT[i.status].map((s) => <option key={s} value={s}>{s}</option>)}
          </Select>
        </Field>
        {target === "RESOLVED" && (
          <>
            <Field label="Resolution">
              <Select className="w-full" value={resolution} onChange={(e) => setResolution(e.target.value)}>
                {["TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN", "DUPLICATE"].map((r) => <option key={r} value={r}>{titleCase(r)}</option>)}
              </Select>
            </Field>
            <Field label="Resolution notes"><textarea className="w-full rounded-md border border-line bg-surface p-2 text-sm" rows={3}
                                                       value={notes} onChange={(e) => setNotes(e.target.value)} required /></Field>
          </>
        )}
        <Button type="submit" size="sm" busy={mut.isPending}>Update status</Button>
      </form>
      <div className="mt-4 border-t border-line pt-3">
        <Field label="Assignee">
          <Select className="w-full" value={i.assigned_to?.id ?? ""} aria-label="Assignee"
                  onChange={(e) => mut.mutate(e.target.value ? { assigned_to_id: Number(e.target.value) } : { unassign: true })}>
            <option value="">Unassigned</option>
            {users.data?.map((u) => <option key={u.id} value={u.id}>{u.name} ({u.role.replace(/_/g, " ").toLowerCase()})</option>)}
          </Select>
        </Field>
      </div>
      <SeverityChanger id={i.id} current={i.severity} onDone={refresh} />
      {error && <p role="alert" className="mt-2 text-sm text-critical">{error}</p>}
    </Card>
  );
}

function SeverityChanger({ id, current, onDone }: { id: number; current: string; onDone: () => void }) {
  const [severity, setSeverity] = useState(current);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const mut = useMutation({
    mutationFn: () => patch(`/incidents/${id}`, Incident, { severity, severity_reason: reason }),
    onSuccess: () => { setReason(""); setError(null); onDone(); },
    onError: (e) => setError(errorMessage(e)),
  });
  return (
    <div className="mt-4 space-y-2 border-t border-line pt-3">
      <div className="flex gap-2">
        <Select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
          {["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>{s}</option>)}
        </Select>
        <Input placeholder="Reason for change" value={reason} onChange={(e) => setReason(e.target.value)} aria-label="Reason" />
      </div>
      <Button size="sm" variant="outline" disabled={severity === current || !reason.trim()} busy={mut.isPending} onClick={() => mut.mutate()}>
        Change severity
      </Button>
      {error && <p className="text-sm text-critical">{error}</p>}
    </div>
  );
}

function NotesPanel({ inv }: { inv: Investigation }) {
  const refresh = useRefresh(inv.incident.id);
  const [text, setText] = useState("");
  const mut = useMutation({
    mutationFn: () => post(`/incidents/${inv.incident.id}/notes`, EvidenceItem, { text }),
    onSuccess: () => { setText(""); refresh(); },
  });
  return (
    <Card title="Analyst notes">
      <ul className="mb-3 max-h-64 space-y-2 overflow-y-auto text-sm">
        {inv.notes.length === 0 && <li className="text-muted">No notes yet.</li>}
        {inv.notes.map((n) => (
          <li key={n.id} className="rounded-md bg-surface-2 p-2">
            <div className="whitespace-pre-wrap">{n.content}</div>
            <div className="mt-1 text-xs text-muted">{n.created_by?.name ?? "system"} · {fmtTime(n.created_at)}</div>
          </li>
        ))}
      </ul>
      <Can permission="incidents:manage">
        <textarea className="w-full rounded-md border border-line bg-surface p-2 text-sm" rows={3} placeholder="Add a note"
                  value={text} onChange={(e) => setText(e.target.value)} aria-label="New note" />
        <Button size="sm" className="mt-2" disabled={!text.trim()} busy={mut.isPending} onClick={() => mut.mutate()}>Add note</Button>
        {mut.isError && <p className="mt-1 text-sm text-critical">{errorMessage(mut.error)}</p>}
      </Can>
    </Card>
  );
}

function EvidencePanel({ inv }: { inv: Investigation }) {
  const refresh = useRefresh(inv.incident.id);
  const fileRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);
  const upload = useMutation({
    mutationFn: (file: File) => {
      const fd = new FormData();
      fd.append("file", file);
      return api(`/incidents/${inv.incident.id}/attachments`, EvidenceItem, { method: "POST", body: fd });
    },
    onSuccess: () => { setError(null); refresh(); },
    onError: (e) => setError(errorMessage(e)),
  });
  async function download(evidenceId: number, name: string) {
    const res = await fetch(`${API_BASE}/api/v1/incidents/${inv.incident.id}/attachments/${evidenceId}`, {
      headers: { Authorization: `Bearer ${getAccessToken() ?? ""}` }, credentials: "include",
    });
    if (!res.ok) { setError("Download failed"); return; }
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  }
  return (
    <Card title="Evidence" actions={
      <Can permission="incidents:manage">
        <input ref={fileRef} type="file" className="hidden" accept=".txt,.log,.csv,.json,.pdf,.png,.jpg,.jpeg,.pcap"
               onChange={(e) => { const f = e.target.files?.[0]; if (f) upload.mutate(f); e.target.value = ""; }} />
        <Button size="sm" variant="outline" busy={upload.isPending} onClick={() => fileRef.current?.click()}>
          <Paperclip className="size-3.5" /> Attach
        </Button>
      </Can>
    }>
      {inv.evidence.length === 0 ? <p className="text-sm text-muted">No evidence attached.</p> : (
        <ul className="space-y-1.5 text-sm">
          {inv.evidence.map((e) => (
            <li key={e.id} className="flex items-start gap-2">
              <span className="rounded bg-surface-2 px-1 text-[10px] uppercase">{e.evidence_type}</span>
              <span className="min-w-0 flex-1 break-words">
                {e.detection_id ? <Link to={`/detections/${e.detection_id}`} className="hover:underline">{e.content ?? `DET-${e.detection_id}`}</Link> : e.content}
                {e.attachment && <span className="block text-xs text-muted">{String(e.attachment.size)} bytes · sha256 {String(e.attachment.sha256).slice(0, 12)}…</span>}
              </span>
              {e.attachment && (
                <button className="text-accent" aria-label="Download attachment"
                        onClick={() => void download(e.id, String(e.attachment?.filename ?? "evidence"))}>
                  <Download className="size-4" />
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      {error && <p className="mt-2 text-sm text-critical">{error}</p>}
      <p className="mt-2 text-xs text-muted">Allowed: txt, log, csv, json, pdf, png, jpg, pcap · max 4 MB. Files are checked and stored outside the web root.</p>
    </Card>
  );
}

const ResponseStatus = z.object({ mode: z.string(), adapter: z.string(), adapter_is_sandbox: z.boolean(), explanation: z.string() });

function ResponsePanel({ inv }: { inv: Investigation }) {
  const refresh = useRefresh(inv.incident.id);
  const { can, user } = useAuth();
  const status = useQuery({ queryKey: ["response", "status"], queryFn: () => get("/response/status", ResponseStatus) });
  const [action, setAction] = useState("BLOCK_IP");
  const [target, setTarget] = useState(inv.incident.primary_src_ip ?? "");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const request = useMutation({
    mutationFn: () => post("/response/actions", ResponseAction, { action_type: action, target, reason, incident_id: inv.incident.id }),
    onSuccess: () => { setReason(""); setError(null); refresh(); },
    onError: (e) => setError(errorMessage(e)),
  });
  const decide = useMutation({
    mutationFn: ({ id, approve }: { id: number; approve: boolean }) => post(`/response/actions/${id}/decision`, ResponseAction, { approve }),
    onSuccess: refresh,
    onError: (e) => setError(errorMessage(e)),
  });
  const disabled = status.data?.mode === "DETECTION_ONLY";
  return (
    <Card title="Response actions">
      {status.data && (
        <p className="mb-3 text-xs text-muted">
          Mode <strong>{status.data.mode}</strong> · adapter <strong>{status.data.adapter}</strong>
          {status.data.adapter_is_sandbox && " (lab sandbox — no real device is changed)"}. {status.data.explanation}
        </p>
      )}
      {inv.response_actions.length === 0 ? <Empty title="No response actions" /> : (
        <ul className="mb-3 space-y-2 text-sm">
          {inv.response_actions.map((r) => (
            <li key={r.id} className="rounded-md border border-line p-2">
              <div className="flex items-center gap-2"><span className="font-medium">{r.action_type.replace(/_/g, " ")}</span>
                <Mono>{r.target}</Mono><span className="ml-auto"><StatusPill value={r.status} /></span></div>
              <div className="text-xs text-muted">{r.reason}</div>
              {r.status === "PROPOSED" && can("response:approve") && r.requested_by_id !== user?.id && (
                <div className="mt-2 flex gap-2">
                  <Button size="sm" onClick={() => decide.mutate({ id: r.id, approve: true })}>Approve &amp; execute</Button>
                  <Button size="sm" variant="ghost" onClick={() => decide.mutate({ id: r.id, approve: false })}>Reject</Button>
                </div>
              )}
              {r.status === "PROPOSED" && r.requested_by_id === user?.id && (
                <div className="mt-1 text-xs text-muted">Waiting for a second approver (four-eyes rule).</div>
              )}
            </li>
          ))}
        </ul>
      )}
      <Can permission="response:request">
        {disabled ? <p className="text-xs text-muted">Requests are disabled while the engine is in DETECTION_ONLY mode.</p> : (
          <div className="space-y-2 border-t border-line pt-3">
            <Select className="w-full" value={action} onChange={(e) => setAction(e.target.value)} aria-label="Action">
              <option value="BLOCK_IP">Block external IP</option>
              <option value="QUARANTINE_ASSET">Quarantine lab asset</option>
              <option value="DISABLE_LAB_ASSET">Disable lab asset</option>
            </Select>
            <Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="Target IP" aria-label="Target IP" />
            <Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Justification" aria-label="Justification" />
            <Button size="sm" disabled={!target || reason.trim().length < 5} busy={request.isPending} onClick={() => request.mutate()}>
              Request action
            </Button>
          </div>
        )}
      </Can>
      {error && <p className="mt-2 text-sm text-critical">{error}</p>}
    </Card>
  );
}
