import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { z } from "zod";

import { useAuth } from "@/auth/AuthProvider";
import { Can } from "@/auth/guards";
import { Button, Card, ErrorState, Field, Input, KeyValue, Mono, PageHeader, Select, Spinner, StatusPill, Table } from "@/components/ui";
import { errorMessage, get, post } from "@/lib/api";
import { fmtAgo } from "@/lib/format";
import { Channel, Message, Sensor } from "@/lib/schemas";

export default function SettingsPage() {
  const { can } = useAuth();
  return (
    <>
      <PageHeader title="Settings" subtitle="Security-sensitive configuration (secrets, response mode, retention) is set through environment variables on the server; this page shows it read-only and manages sensors, channels and lab data." />
      <div className="grid gap-4 xl:grid-cols-2">
        <ChangePassword />
        {can("settings:manage") && <SystemStatus />}
        {can("sensors:manage") && <Sensors />}
        {can("settings:manage") && <Channels />}
        {can("settings:manage") && <Lab />}
      </div>
    </>
  );
}

function ChangePassword() {
  const { logout } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const mut = useMutation({ mutationFn: () => post("/auth/change-password", Message, { current_password: current, new_password: next }),
                            onSuccess: () => void logout() });
  const submit = (e: FormEvent) => { e.preventDefault(); mut.mutate(); };
  return (
    <Card title="Change password">
      <form onSubmit={submit} className="space-y-3">
        <Field label="Current password"><Input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} /></Field>
        <Field label="New password" hint="At least 12 characters. Changing it signs you out everywhere.">
          <Input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} /></Field>
        <Button type="submit" size="sm" busy={mut.isPending} disabled={!current || !next}>Change password</Button>
        {mut.isError && <p className="text-sm text-critical">{errorMessage(mut.error)}</p>}
      </form>
    </Card>
  );
}

const Status = z.object({
  environment: z.string(), demo_mode: z.boolean(), pipeline_mode: z.string(),
  response: z.object({ mode: z.string(), adapter: z.string() }),
  detectors: z.object({
    signature: z.record(z.string(), z.unknown()), anomaly: z.object({ available: z.boolean(), model: z.string().nullable() }),
    behavioral: z.record(z.string(), z.unknown()), threat_intel: z.array(z.record(z.string(), z.unknown())),
  }),
  alerting: z.record(z.string(), z.unknown()), assistant: z.object({ llm_configured: z.boolean(), model: z.string() }),
  retention_days: z.record(z.string(), z.number()), processing_backlog: z.record(z.string(), z.number()), home_networks: z.array(z.string()),
});

function SystemStatus() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["system", "status"], queryFn: () => get("/system/status", Status) });
  const reload = useMutation({ mutationFn: () => post("/system/reload-rules", z.record(z.string(), z.unknown())),
                               onSuccess: () => void qc.invalidateQueries({ queryKey: ["system"] }) });
  if (q.isPending) return <Card title="System"><Spinner /></Card>;
  if (q.isError) return <Card title="System"><ErrorState error={q.error} /></Card>;
  const s = q.data;
  return (
    <Card title="System" actions={<Button size="sm" variant="outline" busy={reload.isPending} onClick={() => reload.mutate()}>Reload rules</Button>}>
      <KeyValue items={[
        ["Environment", s.environment], ["Demo mode", s.demo_mode ? "on (lab endpoints enabled)" : "off"], ["Pipeline", s.pipeline_mode],
        ["Response", `${s.response.mode} via ${s.response.adapter} adapter`],
        ["Signatures", `${String(s.detectors.signature.enabled_rules)} rules, ruleset ${String(s.detectors.signature.ruleset_version)}`],
        ["Anomaly model", s.detectors.anomaly.model ?? "none active"],
        ["Threat intel", s.detectors.threat_intel.map((p) => `${String(p.provider)}: ${String(p.status)}`).join(", ")],
        ["Email", s.alerting.email_configured ? `configured (${String(s.alerting.email_backend)})` : "not configured"],
        ["AI assistant", s.assistant.llm_configured ? `LLM (${s.assistant.model})` : "evidence-only (no API key)"],
        ["Retention (days)", Object.entries(s.retention_days).map(([k, v]) => `${k} ${v}`).join(" · ")],
        ["Unprocessed events", Object.entries(s.processing_backlog).map(([k, v]) => `${k} ${v}`).join(" · ") || "none"],
        ["Home networks", s.home_networks.join(", ")],
      ]} />
      {reload.isError && <p className="mt-2 text-sm text-critical">{errorMessage(reload.error)}</p>}
    </Card>
  );
}

function Sensors() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["sensors"], queryFn: () => get("/sensors", z.array(Sensor)) });
  const [name, setName] = useState("");
  const [type, setType] = useState("zeek");
  const [demo, setDemo] = useState(false);
  const [newKey, setNewKey] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: () => post("/sensors", Sensor.extend({ api_key: z.string() }), { name, sensor_type: type, is_demo: demo }),
    onSuccess: (s) => { setNewKey(s.api_key); setName(""); void qc.invalidateQueries({ queryKey: ["sensors"] }); },
  });
  return (
    <Card title="Sensors">
      {newKey && (
        <div className="mb-3 rounded-md border border-medium/50 bg-medium/10 p-2 text-sm">
          New API key — copy it now, it will not be shown again:<div className="mt-1 break-all"><Mono>{newKey}</Mono></div>
          <Button size="sm" variant="ghost" onClick={() => setNewKey(null)}>Done</Button>
        </div>
      )}
      {q.data && (
        <Table head={["Name", "Type", "Key", "Events", "Last seen", "State"]}>
          {q.data.map((s) => (
            <tr key={s.id}><td className="px-3 py-1.5">{s.name}{s.is_demo && <span className="ml-1 text-xs text-unknown">lab</span>}</td>
              <td className="px-3 py-1.5 text-xs">{s.sensor_type}</td><td className="px-3 py-1.5"><Mono>{s.key_prefix}…</Mono></td>
              <td className="px-3 py-1.5 tabular">{s.events_received.toLocaleString()}</td><td className="px-3 py-1.5 text-xs">{fmtAgo(s.last_seen)}</td>
              <td className="px-3 py-1.5"><StatusPill value={s.is_active ? "ACTIVE" : "INACTIVE"} /></td></tr>
          ))}
        </Table>
      )}
      <form onSubmit={(e) => { e.preventDefault(); create.mutate(); }} className="mt-3 flex flex-wrap items-center gap-2">
        <Input className="w-44" placeholder="Sensor name" value={name} onChange={(e) => setName(e.target.value)} aria-label="Sensor name" />
        <Select value={type} onChange={(e) => setType(e.target.value)} aria-label="Sensor type">
          {["zeek", "suricata", "netflow", "api", "synthetic"].map((t) => <option key={t}>{t}</option>)}
        </Select>
        <label className="flex items-center gap-1 text-sm"><input type="checkbox" checked={demo} onChange={(e) => setDemo(e.target.checked)} /> lab</label>
        <Button type="submit" size="sm" disabled={name.length < 2} busy={create.isPending}>Register</Button>
      </form>
      {create.isError && <p className="mt-2 text-sm text-critical">{errorMessage(create.error)}</p>}
    </Card>
  );
}

const EVENTS = ["critical_alert", "unknown_anomaly", "incident_escalated", "model_drift", "response_approval"];

function Channels() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["channels"], queryFn: () => get("/notifications/channels", z.array(Channel)) });
  const [form, setForm] = useState({ name: "", channel_type: "webhook", target: "", min_severity: "high" });
  const [events, setEvents] = useState<string[]>(["critical_alert"]);
  const [testResult, setTestResult] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: () => post("/notifications/channels", Channel, { ...form, events }),
    onSuccess: () => { setForm({ ...form, name: "", target: "" }); void qc.invalidateQueries({ queryKey: ["channels"] }); },
  });
  const test = useMutation({
    mutationFn: (id: number) => post(`/notifications/channels/${id}/test`, z.object({ status: z.string(), error: z.string().nullable() })),
    onSuccess: (r) => setTestResult(r.status === "SENT" ? "Test delivered." : `Test failed: ${r.error}`),
  });
  return (
    <Card title="Notification channels">
      <p className="mb-2 text-xs text-muted">Webhook bodies are signed (X-ZNIDS-Signature, HMAC-SHA256). Targets on private, loopback or metadata addresses are refused.</p>
      {q.data && (
        <ul className="mb-3 space-y-1 text-sm">
          {q.data.map((c) => (
            <li key={c.id} className="flex items-center gap-2">
              <span className="font-medium">{c.name}</span><span className="text-xs text-muted">{c.channel_type} · {c.target} · ≥{c.min_severity}</span>
              <StatusPill value={c.is_active ? "ACTIVE" : "INACTIVE"} />
              <Button size="sm" variant="ghost" onClick={() => test.mutate(c.id)}>Send test</Button>
            </li>
          ))}
          {q.data.length === 0 && <li className="text-muted">No channels configured.</li>}
        </ul>
      )}
      {testResult && <p className="mb-2 text-sm">{testResult}</p>}
      <form onSubmit={(e) => { e.preventDefault(); create.mutate(); }} className="space-y-2">
        <div className="flex gap-2">
          <Input placeholder="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} aria-label="Channel name" />
          <Select value={form.channel_type} onChange={(e) => setForm({ ...form, channel_type: e.target.value })} aria-label="Channel type">
            <option value="webhook">Webhook</option><option value="slack">Slack-compatible</option><option value="email">Email</option>
          </Select>
        </div>
        <Input placeholder={form.channel_type === "email" ? "soc@example.com" : "https://…"} value={form.target}
               onChange={(e) => setForm({ ...form, target: e.target.value })} aria-label="Target" />
        <div className="flex flex-wrap gap-2 text-sm">
          {EVENTS.map((ev) => (
            <label key={ev} className="flex items-center gap-1"><input type="checkbox" checked={events.includes(ev)}
              onChange={() => setEvents(events.includes(ev) ? events.filter((x) => x !== ev) : [...events, ev])} />{ev.replace(/_/g, " ")}</label>
          ))}
        </div>
        <Button type="submit" size="sm" disabled={!form.name || !form.target || events.length === 0} busy={create.isPending}>Add channel</Button>
        {create.isError && <p className="text-sm text-critical">{errorMessage(create.error)}</p>}
      </form>
    </Card>
  );
}

const LabStatus = z.object({ demo_mode: z.boolean(), scenarios: z.array(z.string()), aliases: z.record(z.string(), z.string()), banner: z.string().nullable() });
const LabResult = z.object({ scenario: z.string(), flows_generated: z.number(), accepted: z.number(), rejected: z.number(),
                             ground_truth_labels: z.record(z.string(), z.number()), note: z.string() }).loose();

function Lab() {
  const qc = useQueryClient();
  const status = useQuery({ queryKey: ["lab"], queryFn: () => get("/lab/status", LabStatus) });
  const [scenario, setScenario] = useState("port_scan");
  const [minutes, setMinutes] = useState(10);
  const run = useMutation({
    mutationFn: () => post("/lab/scenarios", LabResult, { scenario, minutes }),
    onSuccess: () => void qc.invalidateQueries(),
  });
  return (
    <Can permission="settings:manage">
      <Card title="LAB / DEMO scenarios">
        {!status.data?.demo_mode ? <p className="text-sm text-muted">Disabled. Set DEMO_MODE=true (never in production) to generate synthetic lab telemetry.</p> : (
          <>
            <p className="mb-3 text-xs text-muted">Generates synthetic flow metadata for the fictional lab network and sends it through the real ingestion and detection
              pipeline. No packets are sent and no real host is contacted. Everything is marked lab/demo.</p>
            <div className="flex flex-wrap items-center gap-2">
              <Select value={scenario} onChange={(e) => setScenario(e.target.value)} aria-label="Scenario">
                {[...status.data.scenarios, ...Object.keys(status.data.aliases)].map((s) => <option key={s} value={s}>{s.replace(/_/g, " ")}</option>)}
              </Select>
              <Input className="w-24" type="number" min={1} max={120} value={minutes} onChange={(e) => setMinutes(Number(e.target.value))} aria-label="Minutes" />
              <span className="text-sm text-muted">minutes</span>
              <Button size="sm" busy={run.isPending} onClick={() => run.mutate()}>Run scenario</Button>
            </div>
            {run.data && <p className="mt-2 text-sm">{run.data.accepted.toLocaleString()} flows ingested — ground truth: {Object.entries(run.data.ground_truth_labels).map(([k, v]) => `${k} ${v}`).join(", ")}</p>}
            {run.isError && <p className="mt-2 text-sm text-critical">{errorMessage(run.error)}</p>}
          </>
        )}
      </Card>
    </Can>
  );
}
