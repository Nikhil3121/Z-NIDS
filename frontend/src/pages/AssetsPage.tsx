import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Link, useParams } from "react-router";
import { z } from "zod";

import { useAuth } from "@/auth/AuthProvider";
import { Can } from "@/auth/guards";
import { Button, Card, DemoTag, ErrorState, Field, Input, KeyValue, Mono, PageHeader, Pager, RiskBar, Select, SeverityBadge, Spinner, StatusPill, Table } from "@/components/ui";
import { useDebounced } from "@/hooks/useDebounced";
import { errorMessage, get, patch, post } from "@/lib/api";
import { fmtAgo, fmtTime } from "@/lib/format";
import { Alert, Asset, page } from "@/lib/schemas";

const AssetPage = page(Asset);
const TYPES = ["server", "endpoint", "database", "firewall", "sensor", "network_device", "unknown"];
const CRIT = ["low", "medium", "high", "critical"];

export default function AssetsPage() {
  const [search, setSearch] = useState("");
  const [type, setType] = useState("");
  const [crit, setCrit] = useState("");
  const [pageNo, setPageNo] = useState(1);
  const [adding, setAdding] = useState(false);
  const q = useDebounced(search.trim());
  const query = { q: q || undefined, asset_type: type || undefined, criticality: crit || undefined, page: pageNo, page_size: 50, sort: "-risk_score" };
  const res = useQuery({ queryKey: ["assets", query], queryFn: ({ signal }) => get("/assets", AssetPage, query, signal),
                         placeholderData: keepPreviousData });
  return (
    <>
      <PageHeader title="Assets" subtitle="Inventory of internal hosts. Hosts seen in traffic are discovered automatically; analysts classify them and set criticality, which feeds the risk score."
                  actions={<Can permission="assets:manage"><Button onClick={() => setAdding((a) => !a)}>{adding ? "Cancel" : "Add asset"}</Button></Can>} />
      {adding && <AddAsset onDone={() => setAdding(false)} />}
      <Card dense>
        <div className="flex flex-wrap gap-2 border-b border-line p-3">
          <Input className="w-56" placeholder="Hostname, owner or IP" value={search} aria-label="Search assets" onChange={(e) => { setSearch(e.target.value); setPageNo(1); }} />
          <Select value={type} aria-label="Type" onChange={(e) => { setType(e.target.value); setPageNo(1); }}>
            <option value="">All types</option>{TYPES.map((t) => <option key={t} value={t}>{t.replace("_", " ")}</option>)}
          </Select>
          <Select value={crit} aria-label="Criticality" onChange={(e) => { setCrit(e.target.value); setPageNo(1); }}>
            <option value="">Any criticality</option>{CRIT.map((c) => <option key={c} value={c}>{c}</option>)}
          </Select>
        </div>
        {res.isPending && <Spinner />}
        {res.isError && <div className="p-3"><ErrorState error={res.error} onRetry={() => void res.refetch()} /></div>}
        {res.data && (
          <>
            <Table head={["Host", "IP", "Type", "Criticality", "Status", "Risk (24h)", "Last seen"]} empty={res.data.items.length === 0}>
              {res.data.items.map((a) => (
                <tr key={a.id} className="hover:bg-surface-2">
                  <td className="px-3 py-2"><Link to={`/assets/${a.id}`} className="hover:underline">{a.hostname ?? "(unnamed)"}</Link>
                    <span className="ml-1"><DemoTag show={a.is_demo} /></span>
                    {a.auto_discovered && <span className="ml-1 text-[10px] text-muted">discovered</span>}</td>
                  <td className="px-3 py-2"><Mono>{a.ip_address}</Mono></td>
                  <td className="px-3 py-2">{a.asset_type.replace("_", " ")}</td>
                  <td className="px-3 py-2">{a.criticality}</td>
                  <td className="px-3 py-2"><StatusPill value={a.status.toUpperCase()} /></td>
                  <td className="px-3 py-2"><RiskBar value={a.risk_score} /></td>
                  <td className="px-3 py-2 text-xs text-muted">{fmtAgo(a.last_seen)}</td>
                </tr>
              ))}
            </Table>
            <Pager page={res.data.page} pages={res.data.pages} total={res.data.total} onPage={setPageNo} />
          </>
        )}
      </Card>
    </>
  );
}

function AddAsset({ onDone }: { onDone: () => void }) {
  const qc = useQueryClient();
  const [form, setForm] = useState({ ip_address: "", hostname: "", asset_type: "server", criticality: "medium", owner: "", environment: "" });
  const mut = useMutation({
    mutationFn: () => post("/assets", Asset, Object.fromEntries(Object.entries(form).filter(([, v]) => v !== ""))),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ["assets"] }); onDone(); },
  });
  const submit = (e: FormEvent) => { e.preventDefault(); mut.mutate(); };
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm((f) => ({ ...f, [k]: e.target.value }));
  return (
    <Card title="New asset" className="mb-4">
      <form onSubmit={submit} className="grid gap-3 md:grid-cols-3">
        <Field label="IP address"><Input required value={form.ip_address} onChange={set("ip_address")} /></Field>
        <Field label="Hostname"><Input value={form.hostname} onChange={set("hostname")} /></Field>
        <Field label="Owner"><Input value={form.owner} onChange={set("owner")} /></Field>
        <Field label="Type"><Select className="w-full" value={form.asset_type} onChange={set("asset_type")}>{TYPES.map((t) => <option key={t}>{t}</option>)}</Select></Field>
        <Field label="Criticality"><Select className="w-full" value={form.criticality} onChange={set("criticality")}>{CRIT.map((c) => <option key={c}>{c}</option>)}</Select></Field>
        <Field label="Environment"><Input value={form.environment} onChange={set("environment")} placeholder="prod, lab, office…" /></Field>
        <div className="md:col-span-3"><Button type="submit" busy={mut.isPending}>Create</Button>
          {mut.isError && <span className="ml-3 text-sm text-critical">{errorMessage(mut.error)}</span>}</div>
      </form>
    </Card>
  );
}

const AssetDetail = z.object({ asset: Asset, recent_alerts: z.array(Alert) });

export function AssetDetailPage() {
  const { id } = useParams();
  const { can } = useAuth();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["assets", "one", id], queryFn: () => get(`/assets/${id}`, AssetDetail) });
  const mut = useMutation({
    mutationFn: (body: Record<string, unknown>) => patch(`/assets/${id}`, Asset, body),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["assets"] }),
  });
  if (q.isPending) return <Spinner />;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const a = q.data.asset;
  return (
    <>
      <PageHeader title={a.hostname ?? a.ip_address} subtitle={<Link to="/assets" className="text-accent hover:underline">← Assets</Link>} />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Details">
          <KeyValue items={[
            ["IP", <Mono key="ip">{a.ip_address}</Mono>], ["MAC", a.mac_address ?? "—"], ["Type", a.asset_type], ["OS", a.operating_system ?? "—"],
            ["Environment", a.environment ?? "—"], ["Owner", a.owner ?? "—"], ["Status", a.status], ["Lab asset", a.is_lab ? "yes" : "no"],
            ["Risk (24h)", <RiskBar key="r" value={a.risk_score} />], ["First seen", fmtTime(a.first_seen)], ["Last seen", fmtTime(a.last_seen)],
          ]} />
          {can("assets:manage") && (
            <div className="mt-4 flex flex-wrap gap-2 border-t border-line pt-3">
              <Select value={a.criticality} aria-label="Criticality" onChange={(e) => mut.mutate({ criticality: e.target.value })}>
                {CRIT.map((c) => <option key={c} value={c}>{c} criticality</option>)}
              </Select>
              <Select value={a.asset_type} aria-label="Type" onChange={(e) => mut.mutate({ asset_type: e.target.value })}>
                {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
              </Select>
              {mut.isError && <span className="text-sm text-critical">{errorMessage(mut.error)}</span>}
            </div>
          )}
        </Card>
        <Card title="Recent alerts involving this asset" dense>
          <Table head={["Alert", "Severity", "Last seen"]} empty={q.data.recent_alerts.length === 0}>
            {q.data.recent_alerts.map((al) => (
              <tr key={al.id}><td className="px-3 py-2"><Link to={`/alerts/${al.id}`} className="hover:underline">{al.title}</Link></td>
                <td className="px-3 py-2"><SeverityBadge severity={al.severity} /></td>
                <td className="px-3 py-2 text-xs text-muted">{fmtAgo(al.last_seen)}</td></tr>
            ))}
          </Table>
        </Card>
      </div>
    </>
  );
}
