import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate } from "react-router";

import { Card, DemoTag, ErrorState, Mono, PageHeader, Pager, RiskBar, Select, SeverityBadge, Spinner, StatusPill, Table } from "@/components/ui";
import { get } from "@/lib/api";
import { fmtPct, fmtTime } from "@/lib/format";
import { page, UnknownRow } from "@/lib/schemas";

const UnknownPage = page(UnknownRow);

export default function UnknownAttackCenterPage() {
  const navigate = useNavigate();
  const [minRisk, setMinRisk] = useState("");
  const [sort, setSort] = useState("-last_seen");
  const [pageNo, setPageNo] = useState(1);
  const query = { min_risk: minRisk || undefined, sort, page: pageNo, page_size: 25 };
  const q = useQuery({ queryKey: ["unknown", query], queryFn: ({ signal }) => get("/detections/unknown", UnknownPage, query, signal),
                       placeholderData: keepPreviousData });

  return (
    <>
      <PageHeader
        title="Unknown Attack Center"
        subtitle="Potential unknown attacks: behaviour that matches no signature and no known attack family, but deviates strongly from learned normal traffic. These are hypotheses for investigation, not confirmed zero-day exploits."
      />
      <Card dense>
        <div className="flex flex-wrap gap-2 border-b border-line p-3">
          <Select value={minRisk} aria-label="Minimum risk" onChange={(e) => { setMinRisk(e.target.value); setPageNo(1); }}>
            <option value="">Any risk</option>
            <option value="40">Risk ≥ 40</option>
            <option value="65">Risk ≥ 65</option>
            <option value="85">Risk ≥ 85</option>
          </Select>
          <Select value={sort} aria-label="Sort" onChange={(e) => setSort(e.target.value)}>
            <option value="-last_seen">Most recent</option>
            <option value="-risk_score">Highest risk</option>
          </Select>
        </div>
        {q.isPending && <Spinner />}
        {q.isError && <div className="p-3"><ErrorState error={q.error} onRetry={() => void q.refetch()} /></div>}
        {q.data && (
          <>
            <Table head={["Incident", "Source", "Destination", "Last seen", "Anomaly score", "Confidence", "Risk", "Asset criticality", "Status", "Why"]}
                   empty={q.data.items.length === 0}>
              {q.data.items.map((r) => (
                <tr key={r.alert_id} className="cursor-pointer hover:bg-surface-2"
                    onClick={() => navigate(r.incident_id ? `/incidents/${r.incident_id}` : `/alerts/${r.alert_id}`)}>
                  <td className="whitespace-nowrap px-3 py-2">
                    {r.incident_reference ? (
                      <Link to={`/incidents/${r.incident_id}`} className="font-medium text-accent hover:underline" onClick={(e) => e.stopPropagation()}>{r.incident_reference}</Link>
                    ) : <span className="text-xs text-muted">ALT-{r.alert_id} (no incident)</span>}
                    <span className="ml-1"><DemoTag show={r.is_demo} /></span>
                  </td>
                  <td className="px-3 py-2"><Mono>{r.src_ip ?? "—"}</Mono></td>
                  <td className="px-3 py-2"><Mono>{r.dst_ip ?? "—"}</Mono></td>
                  <td className="whitespace-nowrap px-3 py-2 text-xs">{fmtTime(r.last_seen)}<div className="text-muted">{r.occurrences} occurrences</div></td>
                  <td className="px-3 py-2 tabular">{r.anomaly_score !== null ? fmtPct(r.anomaly_score, 2) : "—"}</td>
                  <td className="px-3 py-2 tabular">{r.confidence !== null ? fmtPct(r.confidence, 0) : "—"}</td>
                  <td className="px-3 py-2"><RiskBar value={r.risk_score} /></td>
                  <td className="px-3 py-2">{r.asset_criticality ?? "unknown"}{r.asset_hostname && <div className="text-xs text-muted">{r.asset_hostname}</div>}</td>
                  <td className="px-3 py-2"><div className="flex flex-col gap-1"><SeverityBadge severity={r.severity} />
                    <StatusPill value={r.incident_status ?? r.alert_status} /></div></td>
                  <td className="max-w-xs px-3 py-2 text-xs text-muted">{r.top_factors.filter(Boolean).slice(0, 2).join("; ")}</td>
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
