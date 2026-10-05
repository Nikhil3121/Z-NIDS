import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { z } from "zod";

import { Can } from "@/auth/guards";
import { Button, Card, ErrorState, Field, Input, Mono, PageHeader, Pager, Select, Spinner, StatusPill, Table } from "@/components/ui";
import { errorMessage, get, post } from "@/lib/api";
import { fmtAgo } from "@/lib/format";
import { Indicator, page, ProviderStatus } from "@/lib/schemas";

const IndicatorPage = page(Indicator);
const LookupResult = z.object({
  ioc_type: z.string(), ioc_value: z.string(), indicators: z.array(Indicator),
  providers: z.array(z.record(z.string(), z.unknown())), note: z.string().nullable(),
});

export default function ThreatIntelPage() {
  const providers = useQuery({ queryKey: ["ti", "providers"], queryFn: () => get("/threat-intelligence/providers", z.array(ProviderStatus)) });
  const [pageNo, setPageNo] = useState(1);
  const list = useQuery({ queryKey: ["ti", "list", pageNo], placeholderData: keepPreviousData,
                          queryFn: () => get("/threat-intelligence/indicators", IndicatorPage, { page: pageNo, page_size: 25 }) });
  return (
    <>
      <PageHeader title="Threat Intelligence"
                  subtitle="Indicators come only from configured providers or analysts. When a provider has no credentials it is shown as unavailable — no reputation is ever invented." />
      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Providers">
          {providers.isPending ? <Spinner /> : providers.isError ? <ErrorState error={providers.error} /> : (
            <ul className="space-y-2 text-sm">
              {providers.data.map((p) => (
                <li key={p.provider} className="flex items-center justify-between gap-2">
                  <span className="font-medium">{p.provider}</span>
                  <span className="text-right"><StatusPill value={p.status.toUpperCase()} />
                    {p.reason && <span className="block text-xs text-muted">{p.reason}</span>}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Can permission="threat_intel:manage"><Lookup /></Can>
        <Can permission="threat_intel:manage"><AddIoc /></Can>
      </div>
      <Card title="Known indicators" className="mt-4" dense>
        {list.isPending && <Spinner />}
        {list.isError && <div className="p-3"><ErrorState error={list.error} /></div>}
        {list.data && (
          <>
            <Table head={["Indicator", "Type", "Provider", "Reputation", "Confidence", "Source", "Updated"]} empty={list.data.items.length === 0}>
              {list.data.items.map((i) => (
                <tr key={i.id}><td className="px-3 py-2"><Mono>{i.ioc_value}</Mono></td><td className="px-3 py-2">{i.ioc_type}</td>
                  <td className="px-3 py-2">{i.provider}</td><td className="px-3 py-2">{i.reputation}</td>
                  <td className="px-3 py-2 tabular">{i.confidence.toFixed(0)}</td><td className="px-3 py-2 text-xs text-muted">{i.source}</td>
                  <td className="px-3 py-2 text-xs text-muted">{fmtAgo(i.fetched_at)}</td></tr>
              ))}
            </Table>
            <Pager page={list.data.page} pages={list.data.pages} total={list.data.total} onPage={setPageNo} />
          </>
        )}
      </Card>
    </>
  );
}

function Lookup() {
  const [type, setType] = useState("ip");
  const [value, setValue] = useState("");
  const mut = useMutation({ mutationFn: () => post("/threat-intelligence/lookup", LookupResult, { ioc_type: type, value }) });
  return (
    <Card title="Lookup">
      <form onSubmit={(e) => { e.preventDefault(); mut.mutate(); }} className="flex gap-2">
        <Select value={type} onChange={(e) => setType(e.target.value)} aria-label="IOC type">
          {["ip", "domain", "url", "hash"].map((t) => <option key={t}>{t}</option>)}
        </Select>
        <Input value={value} onChange={(e) => setValue(e.target.value)} placeholder="Indicator" aria-label="Indicator" />
        <Button type="submit" disabled={!value} busy={mut.isPending}>Look up</Button>
      </form>
      {mut.isError && <p className="mt-2 text-sm text-critical">{errorMessage(mut.error)}</p>}
      {mut.data && (
        <div className="mt-3 space-y-2 text-sm">
          {mut.data.note && <p className="text-muted">{mut.data.note}</p>}
          {mut.data.indicators.map((i) => <p key={i.id}>{i.provider}: <strong>{i.reputation}</strong> (confidence {i.confidence.toFixed(0)})</p>)}
          <p className="text-xs text-muted">Providers: {mut.data.providers.map((p) => `${String(p.provider)}=${String(p.status)}`).join(", ")}</p>
        </div>
      )}
    </Card>
  );
}

function AddIoc() {
  const qc = useQueryClient();
  const [form, setForm] = useState({ ioc_type: "ip", value: "", reputation: "malicious", confidence: "80", source: "" });
  const mut = useMutation({
    mutationFn: () => post("/threat-intelligence/indicators", Indicator, { ...form, confidence: Number(form.confidence), source: form.source || null }),
    onSuccess: () => { setForm((f) => ({ ...f, value: "" })); void qc.invalidateQueries({ queryKey: ["ti"] }); },
  });
  const submit = (e: FormEvent) => { e.preventDefault(); mut.mutate(); };
  return (
    <Card title="Add analyst indicator">
      <form onSubmit={submit} className="space-y-2">
        <div className="flex gap-2">
          <Select value={form.ioc_type} onChange={(e) => setForm({ ...form, ioc_type: e.target.value })} aria-label="Type">
            {["ip", "domain", "url", "hash"].map((t) => <option key={t}>{t}</option>)}
          </Select>
          <Input value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} placeholder="Value" aria-label="Value" />
        </div>
        <div className="flex gap-2">
          <Select value={form.reputation} onChange={(e) => setForm({ ...form, reputation: e.target.value })} aria-label="Reputation">
            {["malicious", "suspicious", "benign"].map((t) => <option key={t}>{t}</option>)}
          </Select>
          <Field label="Confidence"><Input type="number" min={0} max={100} value={form.confidence}
                                           onChange={(e) => setForm({ ...form, confidence: e.target.value })} /></Field>
        </div>
        <Input value={form.source} onChange={(e) => setForm({ ...form, source: e.target.value })} placeholder="Source / reference" aria-label="Source" />
        <Button type="submit" size="sm" disabled={!form.value} busy={mut.isPending}>Save indicator</Button>
        {mut.isError && <p className="text-sm text-critical">{errorMessage(mut.error)}</p>}
      </form>
    </Card>
  );
}
