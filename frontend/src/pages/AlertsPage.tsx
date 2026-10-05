import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router";
import { z } from "zod";

import { Can } from "@/auth/guards";
import { DetectionSummary, FactorList, MitreList, RiskBreakdown } from "@/components/Explanation";
import { Button, Card, ClassificationBadge, DemoTag, ErrorState, Input, Mono, PageHeader, Pager, RiskBar, Select, SeverityBadge, Spinner, StatusPill, Table } from "@/components/ui";
import { useDebounced } from "@/hooks/useDebounced";
import { errorMessage, get, patch } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { Alert, Detection, page } from "@/lib/schemas";

const AlertPage = page(Alert);

export default function AlertsPage() {
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("");
  const [search, setSearch] = useState("");
  const [pageNo, setPageNo] = useState(1);
  const q = useDebounced(search.trim());
  const query = {
    open_only: status === "open" || undefined,
    status: status !== "open" && status ? status : undefined,
    severity: severity || undefined,
    q: q || undefined,
    page: pageNo,
    page_size: 50,
    sort: "-last_seen",
  };
  const res = useQuery({ queryKey: ["alerts", query], queryFn: ({ signal }) => get("/alerts", AlertPage, query, signal),
                         placeholderData: keepPreviousData });
  return (
    <>
      <PageHeader title="Alerts" subtitle="Deduplicated detections. Repeats of the same behaviour increase the occurrence count instead of creating new alerts." />
      <Card dense>
        <div className="flex flex-wrap gap-2 border-b border-line p-3">
          <Select value={status} aria-label="Status" onChange={(e) => { setStatus(e.target.value); setPageNo(1); }}>
            <option value="open">Open + acknowledged</option>
            <option value="">All</option>
            {["OPEN", "ACKNOWLEDGED", "RESOLVED", "SUPPRESSED"].map((s) => <option key={s} value={s}>{s}</option>)}
          </Select>
          <Select value={severity} aria-label="Severity" onChange={(e) => { setSeverity(e.target.value); setPageNo(1); }}>
            <option value="">All severities</option>
            {["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>{s}</option>)}
          </Select>
          <Input className="w-64" placeholder="Search titles" value={search} onChange={(e) => { setSearch(e.target.value); setPageNo(1); }} aria-label="Search" />
        </div>
        {res.isPending && <Spinner />}
        {res.isError && <div className="p-3"><ErrorState error={res.error} onRetry={() => void res.refetch()} /></div>}
        {res.data && (
          <>
            <Table head={["Alert", "Severity", "Verdict", "Source → Destination", "Occurrences", "Last seen", "Risk", "Status"]} empty={res.data.items.length === 0}>
              {res.data.items.map((a) => (
                <tr key={a.id} className="hover:bg-surface-2">
                  <td className="px-3 py-2"><Link to={`/alerts/${a.id}`} className="hover:underline">{a.title}</Link>
                    <span className="ml-1"><DemoTag show={a.is_demo} /></span>
                    {a.incident_id && <Link to={`/incidents/${a.incident_id}`} className="ml-2 text-xs text-accent hover:underline">INC-{a.incident_id}</Link>}</td>
                  <td className="px-3 py-2"><SeverityBadge severity={a.severity} /></td>
                  <td className="px-3 py-2"><ClassificationBadge value={a.classification} /></td>
                  <td className="whitespace-nowrap px-3 py-2"><Mono>{a.src_ip ?? "—"} → {a.dst_ip ?? "—"}</Mono></td>
                  <td className="px-3 py-2 tabular">{a.occurrence_count.toLocaleString()}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-xs">{fmtTime(a.last_seen)}</td>
                  <td className="px-3 py-2"><RiskBar value={a.risk_score} /></td>
                  <td className="px-3 py-2"><StatusPill value={a.status} /></td>
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

const AlertDetail = z.object({ alert: Alert, detections: z.array(Detection) });

export function AlertDetailPage() {
  const { id } = useParams();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["alerts", "one", id], queryFn: () => get(`/alerts/${id}`, AlertDetail) });
  const [error, setError] = useState<string | null>(null);
  const update = useMutation({
    mutationFn: (status: string) => patch(`/alerts/${id}`, Alert, { status }),
    onSuccess: () => { setError(null); void qc.invalidateQueries({ queryKey: ["alerts"] }); },
    onError: (e) => setError(errorMessage(e)),
  });
  if (q.isPending) return <Spinner />;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const { alert: a, detections } = q.data;
  const primary = detections.find((d) => d.id === a.primary_detection_id) ?? detections[0];
  return (
    <>
      <PageHeader
        title={`ALT-${a.id}: ${a.title}`}
        subtitle={<span className="flex flex-wrap items-center gap-2"><SeverityBadge severity={a.severity} /><StatusPill value={a.status} />
          <span>{a.occurrence_count} occurrences · first {fmtTime(a.first_seen)} · last {fmtTime(a.last_seen)}</span>
          {a.incident_id && <Link to={`/incidents/${a.incident_id}`} className="text-accent hover:underline">Open INC-{a.incident_id}</Link>}</span>}
        actions={
          <Can permission="alerts:manage">
            {a.status === "OPEN" && <Button size="sm" onClick={() => update.mutate("ACKNOWLEDGED")} busy={update.isPending}>Acknowledge</Button>}
            {(a.status === "OPEN" || a.status === "ACKNOWLEDGED") && (
              <>
                <Button size="sm" variant="outline" onClick={() => update.mutate("RESOLVED")}>Resolve</Button>
                <Button size="sm" variant="ghost" onClick={() => update.mutate("SUPPRESSED")}>Suppress</Button>
              </>
            )}
            {(a.status === "RESOLVED" || a.status === "SUPPRESSED") && <Button size="sm" variant="outline" onClick={() => update.mutate("OPEN")}>Reopen</Button>}
          </Can>
        }
      />
      {error && <div className="mb-3"><ErrorState error={new Error(error)} /></div>}
      <p className="mb-4 text-sm">{a.description}</p>
      {primary && (
        <div className="grid gap-4 xl:grid-cols-2">
          <Card title="Primary detection"><DetectionSummary d={primary} /></Card>
          <Card title="Risk breakdown"><RiskBreakdown components={primary.risk_components} /></Card>
          <Card title="Why it was flagged"><FactorList factors={primary.explanation} /></Card>
          <Card title="MITRE ATT&CK hypotheses"><MitreList items={primary.mitre} /></Card>
        </div>
      )}
      <Card title={`Linked detections (latest ${detections.length})`} className="mt-4" dense>
        <Table head={["Time", "Verdict", "Flow", "Risk"]}>
          {detections.map((d) => (
            <tr key={d.id}>
              <td className="px-3 py-2 text-xs"><Link to={`/detections/${d.id}`} className="hover:underline">{fmtTime(d.ts)}</Link></td>
              <td className="px-3 py-2"><ClassificationBadge value={d.classification} /></td>
              <td className="px-3 py-2"><Mono>{d.src_ip} → {d.dst_ip}:{d.dst_port ?? "-"}</Mono></td>
              <td className="px-3 py-2"><RiskBar value={d.risk_score} /></td>
            </tr>
          ))}
        </Table>
      </Card>
    </>
  );
}
