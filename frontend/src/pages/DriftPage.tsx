import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { z } from "zod";

import { Can } from "@/auth/guards";
import { Button, Card, Empty, ErrorState, PageHeader, Spinner, StatusPill, Table } from "@/components/ui";
import { errorMessage, get, post } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { DriftReport } from "@/lib/schemas";

const CheckResult = z.object({ outcome: z.string(), report: DriftReport.nullable(), alert_id: z.number().nullable() });

export default function DriftPage() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["drift"], queryFn: () => get("/models/drift", z.array(DriftReport)) });
  const check = useMutation({
    mutationFn: () => post("/models/drift/check", CheckResult),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["drift"] }),
  });
  const latest = q.data?.[0];
  const top = latest ? Object.entries(latest.feature_psi).sort((a, b) => b[1] - a[1]).slice(0, 15).map(([name, psi]) => ({ name, psi })) : [];
  return (
    <>
      <PageHeader
        title="Model Drift"
        subtitle="Population Stability Index (PSI) between the active model's training distribution and recent traffic that was classified normal. Drift raises a MODEL_DRIFT alert; it never retrains or replaces the model automatically."
        actions={<Can permission="models:manage"><Button busy={check.isPending} onClick={() => check.mutate()}>Run drift check</Button></Can>}
      />
      {check.data && <p className="mb-3 text-sm">Result: <strong>{check.data.outcome}</strong>{check.data.alert_id && ` — alert ALT-${check.data.alert_id} raised`}</p>}
      {check.isError && <p className="mb-3 text-sm text-critical">{errorMessage(check.error)}</p>}
      {q.isPending && <Spinner />}
      {q.isError && <ErrorState error={q.error} />}
      {q.data && q.data.length === 0 && <Card><Empty title="No drift reports yet" hint="Checks run hourly once enough normal traffic (DRIFT_MIN_SAMPLES) has been processed, or on demand." /></Card>}
      {latest && (
        <div className="grid gap-4 xl:grid-cols-2">
          <Card title={`Latest check — max PSI ${latest.max_psi.toFixed(3)} (threshold ${latest.threshold})`}>
            <div className="h-80">
              <ResponsiveContainer>
                <BarChart data={top} layout="vertical" margin={{ left: 120 }}>
                  <XAxis type="number" tick={{ fontSize: 11, fill: "var(--muted)" }} />
                  <YAxis type="category" dataKey="name" tick={{ fontSize: 10, fill: "var(--muted)" }} width={150} />
                  <Tooltip contentStyle={{ background: "var(--surface)", border: "1px solid var(--border)", fontSize: 12 }} />
                  <Bar dataKey="psi" name="PSI" fill={latest.drifted ? "var(--critical)" : "var(--accent)"} />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <p className="text-xs text-muted">Reading: PSI &lt; 0.1 stable · 0.1–0.25 moderate · &gt; 0.25 significant shift.</p>
          </Card>
          <Card title="History" dense>
            <Table head={["Checked", "Window", "Samples", "Max PSI", "Result"]}>
              {(q.data ?? []).map((r) => (
                <tr key={r.id}>
                  <td className="whitespace-nowrap px-3 py-1.5 text-xs">{fmtTime(r.created_at)}</td>
                  <td className="px-3 py-1.5 text-xs text-muted">{fmtTime(r.window_start)} →</td>
                  <td className="px-3 py-1.5 tabular">{r.sample_size.toLocaleString()}</td>
                  <td className="px-3 py-1.5 tabular">{r.max_psi.toFixed(3)}</td>
                  <td className="px-3 py-1.5"><StatusPill value={r.drifted ? "DRIFTED" : "STABLE"} /></td>
                </tr>
              ))}
            </Table>
          </Card>
        </div>
      )}
    </>
  );
}
