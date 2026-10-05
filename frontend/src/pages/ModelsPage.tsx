import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { z } from "zod";

import { Can } from "@/auth/guards";
import { Button, Card, ErrorState, Mono, PageHeader, Select, Spinner, StatusPill, Table } from "@/components/ui";
import { errorMessage, get, post } from "@/lib/api";
import { fmtPct, fmtTime } from "@/lib/format";
import { MLModel } from "@/lib/schemas";

const Status = z.object({ active_model: z.string().nullable(), anomaly_detection_available: z.boolean(), reason: z.string().nullable() });
const Features = z.object({ feature_version: z.string(), members: z.array(z.string()), attack_families: z.array(z.string()),
  features: z.array(z.object({ name: z.string(), label: z.string(), description: z.string(), unit: z.string(), group: z.string() })) });
const Datasets = z.array(z.object({ file: z.string(), sha256: z.string(), rows: z.number(), labels: z.record(z.string(), z.number()),
  params: z.record(z.string(), z.unknown()) }).loose());

export default function ModelsPage() {
  const qc = useQueryClient();
  const models = useQuery({ queryKey: ["models"], queryFn: () => get("/models", z.array(MLModel)) });
  const status = useQuery({ queryKey: ["models", "status"], queryFn: () => get("/models/status", Status) });
  const [error, setError] = useState<string | null>(null);
  const activate = useMutation({
    mutationFn: (id: number) => post(`/models/${id}/activate`, MLModel),
    onSuccess: () => { setError(null); void qc.invalidateQueries({ queryKey: ["models"] }); },
    onError: (e) => setError(errorMessage(e)),
  });
  return (
    <>
      <PageHeader title="ML Models" subtitle="Versioned, checksummed model bundles. Training registers a new version; only an explicit, audited activation changes the production model." />
      <Card className="mb-4">
        {status.data && (status.data.active_model
          ? <p className="text-sm">Active model: <strong>{status.data.active_model}</strong> — anomaly detection is running.</p>
          : <p className="text-sm text-high">{status.data.reason}</p>)}
      </Card>
      {error && <div className="mb-3"><ErrorState error={new Error(error)} /></div>}
      <Card title="Registry" dense>
        {models.isPending ? <Spinner /> : models.isError ? <div className="p-3"><ErrorState error={models.error} /></div> : (
          <Table head={["Version", "Status", "Members", "Dataset", "Held-out families", "Unknown (macro)", "FPR", "Trained", "Checksum", ""]}
                 empty={models.data.length === 0}>
            {models.data.map((m) => {
              const cfg = m.training_config as { heldout_families?: string[] };
              return (
                <tr key={m.id}>
                  <td className="px-3 py-2 font-medium">{m.tag}</td>
                  <td className="px-3 py-2"><StatusPill value={m.status} /></td>
                  <td className="px-3 py-2 text-xs">{m.model_type.replace("ensemble:", "").replace(/\+/g, " + ")}</td>
                  <td className="px-3 py-2 text-xs">{m.training_dataset}{m.metrics.synthetic_dataset === true && <span className="ml-1 text-unknown">(synthetic)</span>}</td>
                  <td className="px-3 py-2 text-xs">{cfg.heldout_families?.join(", ") || "—"}</td>
                  <td className="px-3 py-2 tabular">{fmtPct(m.metrics.unknown_macro_detection_rate as number | null)}</td>
                  <td className="px-3 py-2 tabular">{fmtPct(m.metrics.false_positive_rate as number | null, 2)}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-xs">{fmtTime(m.trained_at)}</td>
                  <td className="px-3 py-2"><Mono>{m.checksum_sha256.slice(0, 12)}…</Mono></td>
                  <td className="whitespace-nowrap px-3 py-2">
                    <Link to={`/models/evaluation?model=${m.id}`} className="mr-2 text-xs text-accent hover:underline">Evaluation</Link>
                    <Can permission="models:manage">
                      {m.status !== "ACTIVE" && m.status !== "REJECTED" && (
                        <Button size="sm" variant="outline" busy={activate.isPending && activate.variables === m.id}
                                onClick={() => { if (window.confirm(`Activate ${m.tag} as the production model?`)) activate.mutate(m.id); }}>
                          Activate
                        </Button>
                      )}
                    </Can>
                  </td>
                </tr>
              );
            })}
          </Table>
        )}
      </Card>
      <Can permission="models:manage"><TrainPanel /></Can>
      <FeatureCatalogue />
    </>
  );
}

function TrainPanel() {
  const qc = useQueryClient();
  const datasets = useQuery({ queryKey: ["models", "datasets"], queryFn: () => get("/models/datasets", Datasets) });
  const feats = useQuery({ queryKey: ["models", "features"], queryFn: () => get("/models/features", Features) });
  const [dataset, setDataset] = useState("");
  const [heldout, setHeldout] = useState<string[]>([]);
  const [members, setMembers] = useState(["isolation_forest", "autoencoder"]);
  const [message, setMessage] = useState<string | null>(null);
  const train = useMutation({
    mutationFn: () => post("/models/train", z.object({ task_id: z.string(), status: z.string() }), { dataset, heldout_families: heldout, members }),
    onSuccess: (r) => setMessage(`Training queued (task ${r.task_id}). The new version appears here when it finishes.`),
    onError: (e) => setMessage(errorMessage(e)),
  });
  const gen = useMutation({
    mutationFn: () => post("/models/datasets/synthetic", z.object({ dataset: z.string() }), {}),
    onSuccess: (r) => { setDataset(r.dataset); void qc.invalidateQueries({ queryKey: ["models", "datasets"] }); },
  });
  const toggle = (list: string[], v: string) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);
  return (
    <Card title="Train a new version" className="mt-4">
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-2">
          <div className="text-sm font-medium">Dataset</div>
          <Select className="w-full" value={dataset} onChange={(e) => setDataset(e.target.value)} aria-label="Dataset">
            <option value="">Select…</option>
            {datasets.data?.map((d) => <option key={d.file} value={d.file}>{d.file} ({d.rows.toLocaleString()} flows)</option>)}
          </Select>
          <Button size="sm" variant="outline" busy={gen.isPending} onClick={() => gen.mutate()}>Generate synthetic lab dataset</Button>
        </div>
        <div>
          <div className="mb-1 text-sm font-medium">Withhold from training (unseen at test time)</div>
          <div className="flex flex-wrap gap-2">
            {feats.data?.attack_families.map((f) => (
              <label key={f} className="flex items-center gap-1 text-sm">
                <input type="checkbox" checked={heldout.includes(f)} onChange={() => setHeldout(toggle(heldout, f))} />{f.replace(/_/g, " ")}
              </label>
            ))}
          </div>
        </div>
        <div>
          <div className="mb-1 text-sm font-medium">Anomaly members</div>
          {feats.data?.members.map((m) => (
            <label key={m} className="flex items-center gap-1 text-sm">
              <input type="checkbox" checked={members.includes(m)} onChange={() => setMembers(toggle(members, m))} />{m.replace(/_/g, " ")}
            </label>
          ))}
        </div>
      </div>
      <div className="mt-3 flex items-center gap-3">
        <Button disabled={!dataset || members.length === 0} busy={train.isPending} onClick={() => train.mutate()}>Start training</Button>
        {message && <span className="text-sm text-muted">{message}</span>}
      </div>
    </Card>
  );
}

function FeatureCatalogue() {
  const q = useQuery({ queryKey: ["models", "features"], queryFn: () => get("/models/features", Features) });
  if (!q.data) return null;
  return (
    <Card title={`Feature catalogue (${q.data.feature_version}, ${q.data.features.length} features)`} className="mt-4" dense>
      <div className="max-h-96 overflow-y-auto">
        <Table head={["Feature", "Group", "Description"]}>
          {q.data.features.map((f) => (
            <tr key={f.name}><td className="px-3 py-1.5"><Mono>{f.name}</Mono></td><td className="px-3 py-1.5 text-xs">{f.group}</td>
              <td className="px-3 py-1.5 text-xs text-muted">{f.description}</td></tr>
          ))}
        </Table>
      </div>
    </Card>
  );
}
