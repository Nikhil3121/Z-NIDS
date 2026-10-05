import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Download } from "lucide-react";
import { useState } from "react";
import { z } from "zod";

import { Button, Card, ErrorState, Input, Mono, PageHeader, Pager, Select, Spinner, StatusPill, Table } from "@/components/ui";
import { useDebounced } from "@/hooks/useDebounced";
import { api, errorMessage, get } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { AuditEntry, page } from "@/lib/schemas";

const AuditPage = page(AuditEntry);

export default function AuditLogPage() {
  const [action, setAction] = useState("");
  const [result, setResult] = useState("");
  const [actor, setActor] = useState("");
  const [pageNo, setPageNo] = useState(1);
  const [error, setError] = useState<string | null>(null);
  const debActor = useDebounced(actor.trim());
  const actions = useQuery({ queryKey: ["audit", "actions"], queryFn: () => get("/audit/actions", z.array(z.string())) });
  const query = { action: action || undefined, result: result || undefined, actor: debActor || undefined, page: pageNo, page_size: 50 };
  const q = useQuery({ queryKey: ["audit", query], queryFn: ({ signal }) => get("/audit", AuditPage, query, signal), placeholderData: keepPreviousData });

  async function exportCsv() {
    try {
      const csv = await api<string>("/audit/export", null, { query: { action: action || undefined }, raw: true });
      const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = "znids-audit.csv";
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  return (
    <>
      <PageHeader title="Audit Logs" subtitle="Append-only record of logins, configuration changes, incident updates, model activations and response actions."
                  actions={<Button variant="outline" onClick={() => void exportCsv()}><Download className="size-4" /> Export CSV</Button>} />
      {error && <p className="mb-2 text-sm text-critical">{error}</p>}
      <Card dense>
        <div className="flex flex-wrap gap-2 border-b border-line p-3">
          <Select value={action} aria-label="Action" onChange={(e) => { setAction(e.target.value); setPageNo(1); }}>
            <option value="">All actions</option>{actions.data?.map((a) => <option key={a}>{a}</option>)}
          </Select>
          <Select value={result} aria-label="Result" onChange={(e) => { setResult(e.target.value); setPageNo(1); }}>
            <option value="">Any result</option>{["SUCCESS", "FAILURE", "DENIED"].map((r) => <option key={r}>{r}</option>)}
          </Select>
          <Input className="w-56" placeholder="Actor" value={actor} aria-label="Actor" onChange={(e) => { setActor(e.target.value); setPageNo(1); }} />
        </div>
        {q.isPending && <Spinner />}
        {q.isError && <div className="p-3"><ErrorState error={q.error} /></div>}
        {q.data && (
          <>
            <Table head={["Time", "Actor", "Action", "Resource", "Result", "IP", "Details"]} empty={q.data.items.length === 0}>
              {q.data.items.map((a) => (
                <tr key={a.id}>
                  <td className="whitespace-nowrap px-3 py-1.5 text-xs">{fmtTime(a.ts)}</td>
                  <td className="px-3 py-1.5 text-sm">{a.actor_label}</td>
                  <td className="px-3 py-1.5 text-xs font-medium">{a.action}</td>
                  <td className="px-3 py-1.5 text-xs">{a.resource_type ? `${a.resource_type}:${a.resource_id ?? ""}` : "—"}</td>
                  <td className="px-3 py-1.5"><StatusPill value={a.result} /></td>
                  <td className="px-3 py-1.5"><Mono>{a.ip_address ?? "—"}</Mono></td>
                  <td className="max-w-md truncate px-3 py-1.5 text-xs text-muted" title={JSON.stringify(a.details)}>{JSON.stringify(a.details)}</td>
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
