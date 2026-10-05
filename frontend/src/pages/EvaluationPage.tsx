import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { z } from "zod";

import { Card, Empty, ErrorState, PageHeader, Select, Spinner, Stat, Table } from "@/components/ui";
import { get } from "@/lib/api";
import { fmtPct, fmtTime } from "@/lib/format";
import { Evaluation, MLModel } from "@/lib/schemas";

const ModelDetail = z.object({ model: MLModel, evaluations: z.array(Evaluation) });
type Block = Record<string, number | null | undefined>;

export default function EvaluationPage() {
  const [params, setParams] = useSearchParams();
  const models = useQuery({ queryKey: ["models"], queryFn: () => get("/models", z.array(MLModel)) });
  const modelId = params.get("model") ?? (models.data?.find((m) => m.status === "ACTIVE") ?? models.data?.[0])?.id?.toString() ?? "";
  const detail = useQuery({ queryKey: ["models", "detail", modelId], enabled: Boolean(modelId),
                            queryFn: () => get(`/models/${modelId}`, ModelDetail) });
  const ev = detail.data?.evaluations[0];

  return (
    <>
      <PageHeader
        title="Model Evaluation"
        subtitle="Held-out attack families: whole families are removed from training and appear only in the test period, so they are previously unseen behaviour for the model. This is a laboratory evaluation of unseen attack behaviour — not proof of discovering real zero-day vulnerabilities."
        actions={
          <Select value={modelId} onChange={(e) => setParams({ model: e.target.value })} aria-label="Model">
            {models.data?.map((m) => <option key={m.id} value={m.id}>{m.tag} ({m.status})</option>)}
          </Select>
        }
      />
      {(models.isPending || detail.isPending) && modelId && <Spinner />}
      {detail.isError && <ErrorState error={detail.error} />}
      {models.data?.length === 0 && <Card><Empty title="No models registered yet" hint="Train one from the ML Models page or with scripts/train_model.py." /></Card>}
      {ev && <EvaluationView ev={ev} />}
    </>
  );
}

function EvaluationView({ ev }: { ev: Evaluation }) {
  const s = ev.summary as Record<string, unknown>;
  const overall = (s.overall ?? {}) as Block;
  const unknown = (s.unknown_attacks ?? {}) as Block;
  const baseline = (s.supervised_baseline ?? {}) as Block;
  const latency = (s.detection_latency ?? {}) as Block;
  const families = Object.entries(ev.per_family).map(([name, v]) => ({
    name: name.replace(/_/g, " "),
    group: String(v.group),
    zNids: Number(v.detection_rate) * 100,
    baseline: v.supervised_baseline_recall !== undefined ? Number(v.supervised_baseline_recall) * 100 : null,
    rows: Number(v.rows),
    asKnown: Number(v.as_known_attack),
    asAnomalous: Number(v.as_anomalous),
    asUnknown: Number(v.as_potential_unknown),
  }));
  const classes = ["NORMAL", "KNOWN_ATTACK", "ANOMALOUS", "POTENTIAL_UNKNOWN"];

  return (
    <div className="space-y-4">
      {ev.is_synthetic && (
        <p className="rounded-md border border-unknown/40 bg-unknown/10 p-3 text-sm">
          <strong>Synthetic laboratory data.</strong> These results demonstrate the methodology on generated flows ({ev.dataset}); they are not
          a measurement of performance on real network traffic.
        </p>
      )}
      <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Unknown detection (per family)" value={fmtPct(unknown.macro_detection_rate)} tone="text-unknown" hint="Macro average over held-out families" />
        <Stat label="Unknown detection (flows)" value={fmtPct(unknown.unknown_attack_detection_rate)} hint="Row-weighted; dominated by large families" />
        <Stat label="Supervised baseline on unknown" value={fmtPct(baseline.unknown_recall)} tone="text-high" hint="Same classifier, no anomaly model" />
        <Stat label="False-positive rate" value={fmtPct(s.false_positive_rate as number, 2)} hint="Normal test flows flagged" />
        <Stat label="Precision / recall" value={`${fmtPct(overall.precision)} / ${fmtPct(overall.recall)}`} hint={`F1 ${fmtPct(overall.f1)}`} />
        <Stat label="ROC-AUC / PR-AUC" value={`${overall.roc_auc?.toFixed(3) ?? "n/a"} / ${overall.pr_auc?.toFixed(3) ?? "n/a"}`} />
      </div>

      <Card title="Detection rate per attack family — Z-NIDS vs supervised baseline">
        <div className="h-72">
          <ResponsiveContainer>
            <BarChart data={families}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="name" tick={{ fontSize: 11, fill: "var(--muted)" }} />
              <YAxis unit="%" domain={[0, 100]} tick={{ fontSize: 11, fill: "var(--muted)" }} width={44} />
              <Tooltip contentStyle={{ background: "var(--surface)", border: "1px solid var(--border)", fontSize: 12 }}
                       formatter={(v) => `${Number(v).toFixed(1)}%`} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Bar dataKey="zNids" name="Z-NIDS" fill="var(--unknown)" />
              <Bar dataKey="baseline" name="Supervised baseline" fill="var(--high)" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </Card>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Per family" dense>
          <Table head={["Family", "Group", "Test flows", "Detected", "As known", "As anomalous", "As potential unknown"]}>
            {families.map((f) => (
              <tr key={f.name}>
                <td className="px-3 py-1.5">{f.name}</td>
                <td className="px-3 py-1.5 text-xs">{f.group === "unknown" ? <span className="text-unknown">held out</span> : "trained"}</td>
                <td className="px-3 py-1.5 tabular">{f.rows.toLocaleString()}</td>
                <td className="px-3 py-1.5 tabular font-medium">{f.zNids.toFixed(1)}%</td>
                <td className="px-3 py-1.5 tabular">{fmtPct(f.asKnown)}</td>
                <td className="px-3 py-1.5 tabular">{fmtPct(f.asAnomalous)}</td>
                <td className="px-3 py-1.5 tabular">{fmtPct(f.asUnknown)}</td>
              </tr>
            ))}
          </Table>
        </Card>
        <Card title="Confusion matrix (rows = ground truth, columns = verdict)" dense>
          <Table head={["Label", ...classes.map((c) => c.replace(/_/g, " ").toLowerCase())]}>
            {Object.entries(ev.confusion_matrix).map(([label, cols]) => (
              <tr key={label}>
                <td className="px-3 py-1.5">{label.replace(/_/g, " ")}{ev.heldout_families.includes(label) && <span className="ml-1 text-xs text-unknown">(unseen)</span>}</td>
                {classes.map((c) => <td key={c} className="px-3 py-1.5 tabular">{(cols[c] ?? 0).toLocaleString()}</td>)}
              </tr>
            ))}
          </Table>
        </Card>
      </div>

      <Card title="Experiment metadata">
        <div className="grid gap-2 text-sm md:grid-cols-2">
          <div>Dataset: <strong>{ev.dataset}</strong> (sha256 {ev.dataset_sha256.slice(0, 16)}…)</div>
          <div>Evaluated: {fmtTime(ev.created_at)}</div>
          <div>Held-out families: {ev.heldout_families.join(", ") || "none"}</div>
          <div>Median seconds to first detection: known {latency.median_seconds_known ?? "n/a"} · unknown {latency.median_seconds_unknown ?? "n/a"}</div>
          <div>Inference: {latency.inference_ms_per_1000_flows ?? "n/a"} ms per 1,000 flows</div>
          <div>Unknown flows misattributed to a known family: {fmtPct(unknown.misattributed_to_known_family_rate)}</div>
        </div>
      </Card>
    </div>
  );
}
