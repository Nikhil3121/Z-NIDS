import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router";

import { DetectionSummary, FactorList, MitreList, RiskBreakdown } from "@/components/Explanation";
import { Card, ClassificationBadge, DemoTag, ErrorState, Mono, PageHeader, Pager, RiskBar, Select, SeverityBadge, Spinner, Table } from "@/components/ui";
import { get } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { Detection, page } from "@/lib/schemas";

const DetectionPage = page(Detection);

export default function DetectionCenterPage() {
  const [classification, setClassification] = useState("");
  const [detector, setDetector] = useState("");
  const [severity, setSeverity] = useState("");
  const [pageNo, setPageNo] = useState(1);
  const query = { classification: classification || undefined, detector: detector || undefined,
                  severity: severity || undefined, page: pageNo, page_size: 50, sort: "-ts" };
  const q = useQuery({ queryKey: ["detections", query], queryFn: ({ signal }) => get("/detections", DetectionPage, query, signal),
                       placeholderData: keepPreviousData });

  return (
    <>
      <PageHeader title="Detection Center" subtitle="Every non-normal verdict with the detectors that fired, its risk and its explanation." />
      <Card dense>
        <div className="flex flex-wrap gap-2 border-b border-line p-3">
          <Select value={classification} aria-label="Verdict" onChange={(e) => { setClassification(e.target.value); setPageNo(1); }}>
            <option value="">All verdicts</option>
            <option value="KNOWN_ATTACK">Known attack</option>
            <option value="ANOMALOUS">Anomalous</option>
            <option value="POTENTIAL_UNKNOWN">Potential unknown</option>
          </Select>
          <Select value={detector} aria-label="Detector" onChange={(e) => { setDetector(e.target.value); setPageNo(1); }}>
            <option value="">All detectors</option>
            <option value="signature">Signature</option>
            <option value="anomaly">ML anomaly</option>
            <option value="behavioral">Behavioural</option>
            <option value="threat_intel">Threat intel</option>
          </Select>
          <Select value={severity} aria-label="Severity" onChange={(e) => { setSeverity(e.target.value); setPageNo(1); }}>
            <option value="">All severities</option>
            {["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>{s}</option>)}
          </Select>
        </div>
        {q.isPending && <Spinner />}
        {q.isError && <div className="p-3"><ErrorState error={q.error} onRetry={() => void q.refetch()} /></div>}
        {q.data && (
          <>
            <Table head={["Time", "Verdict", "Category", "Source → Destination", "Detectors", "Severity", "Risk"]} empty={q.data.items.length === 0}>
              {q.data.items.map((d) => (
                <tr key={d.id} className="hover:bg-surface-2">
                  <td className="whitespace-nowrap px-3 py-2 text-xs"><Link to={`/detections/${d.id}`} className="hover:underline">{fmtTime(d.ts)}</Link></td>
                  <td className="px-3 py-2"><span className="flex items-center gap-1"><ClassificationBadge value={d.classification} /><DemoTag show={d.is_demo} /></span></td>
                  <td className="px-3 py-2">{d.category.replace(/_/g, " ")}</td>
                  <td className="whitespace-nowrap px-3 py-2"><Mono>{d.src_ip} → {d.dst_ip}:{d.dst_port ?? "-"}</Mono></td>
                  <td className="px-3 py-2 text-xs text-muted">{d.detectors_fired.join(", ")}</td>
                  <td className="px-3 py-2"><SeverityBadge severity={d.severity} /></td>
                  <td className="px-3 py-2"><RiskBar value={d.risk_score} /></td>
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

export function DetectionDetailPage() {
  const { id } = useParams();
  const q = useQuery({ queryKey: ["detections", "one", id], queryFn: () => get(`/detections/${id}`, Detection) });
  if (q.isPending) return <Spinner />;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const d = q.data;
  return (
    <>
      <PageHeader title={`Detection DET-${d.id}`} subtitle={<Link to="/detections" className="text-accent hover:underline">← Detection Center</Link>} />
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Summary"><DetectionSummary d={d} /></Card>
        <Card title="Risk breakdown"><RiskBreakdown components={d.risk_components} /></Card>
        <Card title="Why it was flagged"><FactorList factors={d.explanation} /></Card>
        <Card title="MITRE ATT&CK hypotheses"><MitreList items={d.mitre} /></Card>
      </div>
    </>
  );
}
