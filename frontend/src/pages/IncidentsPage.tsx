import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";

import { Card, ClassificationBadge, DemoTag, ErrorState, Input, Mono, PageHeader, Pager, RiskBar, Select, SeverityBadge, Spinner, StatusPill, Table } from "@/components/ui";
import { useDebounced } from "@/hooks/useDebounced";
import { get } from "@/lib/api";
import { fmtAgo } from "@/lib/format";
import { Incident, page } from "@/lib/schemas";

const IncidentPage = page(Incident);

export default function IncidentsPage() {
  const [status, setStatus] = useState("active");
  const [severity, setSeverity] = useState("");
  const [mine, setMine] = useState(false);
  const [search, setSearch] = useState("");
  const [pageNo, setPageNo] = useState(1);
  const q = useDebounced(search.trim());
  const query = {
    active_only: status === "active" || undefined,
    status: status !== "active" && status ? status : undefined,
    severity: severity || undefined,
    assigned_to_me: mine || undefined,
    q: q || undefined,
    page: pageNo,
    page_size: 25,
    sort: "-last_seen",
  };
  const res = useQuery({ queryKey: ["incidents", query], queryFn: ({ signal }) => get("/incidents", IncidentPage, query, signal),
                         placeholderData: keepPreviousData });

  return (
    <>
      <PageHeader title="Incidents" subtitle="Correlated alerts that need an analyst. Workflow: New → Acknowledged → Investigating → Confirmed → Contained → Resolved." />
      <Card dense>
        <div className="flex flex-wrap items-center gap-2 border-b border-line p-3">
          <Select value={status} aria-label="Status" onChange={(e) => { setStatus(e.target.value); setPageNo(1); }}>
            <option value="active">Active</option>
            <option value="">All</option>
            {["NEW", "ACKNOWLEDGED", "INVESTIGATING", "CONFIRMED", "CONTAINED", "RESOLVED"].map((s) => <option key={s} value={s}>{s}</option>)}
          </Select>
          <Select value={severity} aria-label="Severity" onChange={(e) => { setSeverity(e.target.value); setPageNo(1); }}>
            <option value="">All severities</option>
            {["critical", "high", "medium", "low"].map((s) => <option key={s} value={s}>{s}</option>)}
          </Select>
          <Input className="w-56" placeholder="INC-1004 or title" value={search} aria-label="Search incidents"
                 onChange={(e) => { setSearch(e.target.value); setPageNo(1); }} />
          <label className="flex items-center gap-1.5 text-sm">
            <input type="checkbox" checked={mine} onChange={(e) => { setMine(e.target.checked); setPageNo(1); }} /> Assigned to me
          </label>
        </div>
        {res.isPending && <Spinner />}
        {res.isError && <div className="p-3"><ErrorState error={res.error} onRetry={() => void res.refetch()} /></div>}
        {res.data && (
          <>
            <Table head={["Reference", "Title", "Severity", "Verdict", "Source", "Risk", "Status", "Assignee", "Last activity"]}
                   empty={res.data.items.length === 0}>
              {res.data.items.map((i) => (
                <tr key={i.id} className="hover:bg-surface-2">
                  <td className="whitespace-nowrap px-3 py-2"><Link to={`/incidents/${i.id}`} className="font-medium text-accent hover:underline">{i.reference}</Link>
                    <span className="ml-1"><DemoTag show={i.is_demo} /></span></td>
                  <td className="px-3 py-2">{i.title}</td>
                  <td className="px-3 py-2"><SeverityBadge severity={i.severity} /></td>
                  <td className="px-3 py-2"><ClassificationBadge value={i.classification} /></td>
                  <td className="px-3 py-2"><Mono>{i.primary_src_ip ?? "—"}</Mono></td>
                  <td className="px-3 py-2"><RiskBar value={i.risk_score} /></td>
                  <td className="px-3 py-2"><StatusPill value={i.status} /></td>
                  <td className="px-3 py-2 text-sm">{i.assigned_to?.name ?? <span className="text-muted">unassigned</span>}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-xs text-muted">{fmtAgo(i.last_seen)}</td>
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
