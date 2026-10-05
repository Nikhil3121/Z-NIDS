import { useQuery } from "@tanstack/react-query";
import { Download } from "lucide-react";
import { useState } from "react";
import { z } from "zod";

import { Button, Card, ErrorState, Field, Input, PageHeader, Spinner, Stat, Table } from "@/components/ui";
import { api, errorMessage, get } from "@/lib/api";
import { fmtNum, fmtPct } from "@/lib/format";

const Report = z.object({
  period: z.object({ start: z.string(), end: z.string() }),
  includes_demo_data: z.boolean(),
  events: z.object({ total: z.number(), normal: z.number(), anomalous: z.number(), known_attack: z.number(), potential_unknown: z.number() }),
  alerts: z.object({ by_severity: z.record(z.string(), z.number()), by_category: z.array(z.object({ category: z.string(), count: z.number() })) }),
  incidents: z.object({ total: z.number(), resolved: z.number(), potential_unknown: z.number(),
    items: z.array(z.object({ reference: z.string(), title: z.string(), severity: z.string(), status: z.string(), risk_score: z.number() }).loose()) }),
  top_sources: z.array(z.object({ ip: z.string(), detections: z.number(), max_risk: z.number() })),
  mitre_techniques: z.array(z.object({ technique_id: z.string(), name: z.string(), detections: z.number(), max_confidence: z.number() })),
  response_actions: z.array(z.object({ action: z.string(), status: z.string(), count: z.number() })),
  model: z.object({ tag: z.string(), dataset: z.string(), headline_metrics: z.record(z.string(), z.unknown()),
                    latest_evaluation_synthetic: z.boolean().nullable() }).loose().nullable(),
});

function isoLocal(d: Date) {
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

export default function ReportsPage() {
  const [start, setStart] = useState(() => isoLocal(new Date(Date.now() - 86_400_000)));
  const [end, setEnd] = useState(() => isoLocal(new Date()));
  const [demo, setDemo] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const range = { start: new Date(start).toISOString(), end: new Date(end).toISOString(), include_demo: demo };
  const q = useQuery({ queryKey: ["report", range], queryFn: () => get("/reports/summary", Report, range) });

  async function downloadMarkdown() {
    try {
      const text = await api<string>("/reports/summary", null, { query: { ...range, fmt: "markdown" }, raw: true });
      const url = URL.createObjectURL(new Blob([text], { type: "text/markdown" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = "znids-report.md";
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  return (
    <>
      <PageHeader title="Reports" subtitle="Period summaries generated from stored data. Every generation is recorded in the audit log."
                  actions={<Button variant="outline" onClick={() => void downloadMarkdown()}><Download className="size-4" /> Markdown</Button>} />
      <Card className="mb-4">
        <div className="flex flex-wrap items-end gap-3">
          <Field label="From"><Input type="datetime-local" value={start} onChange={(e) => setStart(e.target.value)} /></Field>
          <Field label="To"><Input type="datetime-local" value={end} onChange={(e) => setEnd(e.target.value)} /></Field>
          <label className="flex items-center gap-1.5 pb-2 text-sm"><input type="checkbox" checked={demo} onChange={(e) => setDemo(e.target.checked)} /> Include lab / demo data</label>
        </div>
        {error && <p className="mt-2 text-sm text-critical">{error}</p>}
      </Card>
      {q.isPending && <Spinner />}
      {q.isError && <ErrorState error={q.error} />}
      {q.data && (
        <div className="space-y-4">
          {q.data.includes_demo_data && <p className="text-sm text-unknown">Includes LAB / DEMO data (synthetic telemetry).</p>}
          <div className="grid gap-3 md:grid-cols-5">
            <Stat label="Flows analysed" value={fmtNum(q.data.events.total)} />
            <Stat label="Known attack" value={fmtNum(q.data.events.known_attack)} tone="text-critical" />
            <Stat label="Anomalous" value={fmtNum(q.data.events.anomalous)} tone="text-medium" />
            <Stat label="Potential unknown" value={fmtNum(q.data.events.potential_unknown)} tone="text-unknown" />
            <Stat label="Incidents" value={q.data.incidents.total} hint={`${q.data.incidents.resolved} resolved · ${q.data.incidents.potential_unknown} unknown`} />
          </div>
          <div className="grid gap-4 xl:grid-cols-2">
            <Card title="Incidents" dense>
              <Table head={["Ref", "Title", "Severity", "Status", "Risk"]} empty={q.data.incidents.items.length === 0}>
                {q.data.incidents.items.map((i) => (
                  <tr key={i.reference}><td className="px-3 py-1.5">{i.reference}</td><td className="px-3 py-1.5">{i.title}</td>
                    <td className="px-3 py-1.5">{i.severity}</td><td className="px-3 py-1.5">{i.status}</td><td className="px-3 py-1.5 tabular">{i.risk_score.toFixed(0)}</td></tr>
                ))}
              </Table>
            </Card>
            <Card title="MITRE ATT&CK techniques" dense>
              <Table head={["Technique", "Name", "Detections", "Max confidence"]} empty={q.data.mitre_techniques.length === 0}>
                {q.data.mitre_techniques.map((t) => (
                  <tr key={t.technique_id}><td className="px-3 py-1.5 font-mono text-xs">{t.technique_id}</td><td className="px-3 py-1.5">{t.name}</td>
                    <td className="px-3 py-1.5 tabular">{t.detections}</td><td className="px-3 py-1.5 tabular">{fmtPct(t.max_confidence, 0)}</td></tr>
                ))}
              </Table>
            </Card>
            <Card title="Alerts by category" dense>
              <Table head={["Category", "Alerts"]} empty={q.data.alerts.by_category.length === 0}>
                {q.data.alerts.by_category.map((c) => <tr key={c.category}><td className="px-3 py-1.5">{c.category.replace(/_/g, " ")}</td><td className="px-3 py-1.5 tabular">{c.count}</td></tr>)}
              </Table>
            </Card>
            <Card title="Detection model">
              {q.data.model ? (
                <p className="text-sm">Active model <strong>{q.data.model.tag}</strong> trained on {q.data.model.dataset}
                  {q.data.model.latest_evaluation_synthetic && " (synthetic lab data)"}. Unknown-attack detection (macro):{" "}
                  {fmtPct(q.data.model.headline_metrics.unknown_macro_detection_rate as number | null)}, false-positive rate{" "}
                  {fmtPct(q.data.model.headline_metrics.false_positive_rate as number | null, 2)}.</p>
              ) : <p className="text-sm text-muted">No active anomaly model.</p>}
            </Card>
          </div>
        </div>
      )}
    </>
  );
}
