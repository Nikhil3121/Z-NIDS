import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { ExternalLink } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";
import { z } from "zod";

import { Card, ErrorState, Mono, PageHeader, Select, Spinner, Table } from "@/components/ui";
import { get } from "@/lib/api";
import { fmtPct, fmtTime } from "@/lib/format";
import { MitreTechnique } from "@/lib/schemas";

const TechniqueDetections = z.array(z.object({
  detection_id: z.number(), ts: z.string(), src_ip: z.string(), dst_ip: z.string(), classification: z.string(),
  confidence: z.number(), evidence: z.string(), risk_score: z.number(),
}));

export default function MitrePage() {
  const [days, setDays] = useState(7);
  const [selected, setSelected] = useState<string | null>(null);
  const q = useQuery({ queryKey: ["mitre", days], queryFn: () => get("/mitre/techniques", z.array(MitreTechnique), { days }) });
  const tactics = q.data ? [...new Set(q.data.map((t) => t.tactic))] : [];
  return (
    <>
      <PageHeader title="MITRE ATT&CK" subtitle="Techniques hypothesised from detections. A mapping is made only when the flow evidence supports it; confidence is never presented as certainty."
                  actions={<Select value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Window">
                    <option value={1}>Last 24 hours</option><option value={7}>Last 7 days</option><option value={30}>Last 30 days</option></Select>} />
      {q.isPending && <Spinner />}
      {q.isError && <ErrorState error={q.error} />}
      {q.data && (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {tactics.map((tactic) => (
            <Card key={tactic} title={tactic}>
              <ul className="space-y-1.5">
                {q.data.filter((t) => t.tactic === tactic).map((t) => (
                  <li key={t.technique_id}>
                    <button onClick={() => setSelected(t.technique_id)}
                            className={clsx("w-full rounded-md border px-2 py-1.5 text-left text-sm",
                              t.observed ? "border-critical/50 bg-critical/10" : "border-line opacity-70",
                              selected === t.technique_id && "ring-2 ring-accent")}>
                      <div className="flex items-center justify-between gap-2"><span className="font-mono text-xs">{t.technique_id}</span>
                        {t.observed > 0 && <span className="tabular text-xs">{t.observed}× · max {fmtPct(t.max_confidence, 0)}</span>}</div>
                      <div>{t.name}</div>
                    </button>
                  </li>
                ))}
              </ul>
            </Card>
          ))}
        </div>
      )}
      {selected && <TechniqueDetail id={selected} url={q.data?.find((t) => t.technique_id === selected)?.url} />}
    </>
  );
}

function TechniqueDetail({ id, url }: { id: string; url?: string }) {
  const q = useQuery({ queryKey: ["mitre", "detections", id], queryFn: () => get(`/mitre/techniques/${id}/detections`, TechniqueDetections) });
  return (
    <Card className="mt-4" dense title={<span className="flex items-center gap-2">{id} detections
      {url && <a href={url} target="_blank" rel="noreferrer noopener" className="text-accent"><ExternalLink className="size-3.5" /></a>}</span>}>
      {q.isPending ? <Spinner /> : q.isError ? <ErrorState error={q.error} /> : (
        <Table head={["Time", "Flow", "Confidence", "Evidence"]} empty={q.data.length === 0}>
          {q.data.map((d) => (
            <tr key={d.detection_id}><td className="whitespace-nowrap px-3 py-2 text-xs"><Link to={`/detections/${d.detection_id}`} className="hover:underline">{fmtTime(d.ts)}</Link></td>
              <td className="px-3 py-2"><Mono>{d.src_ip} → {d.dst_ip}</Mono></td><td className="px-3 py-2 tabular">{fmtPct(d.confidence, 0)}</td>
              <td className="px-3 py-2 text-xs text-muted">{d.evidence}</td></tr>
          ))}
        </Table>
      )}
    </Card>
  );
}
