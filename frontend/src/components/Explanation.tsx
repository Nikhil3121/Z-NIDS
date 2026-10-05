import { ExternalLink } from "lucide-react";

import { ClassificationBadge, KeyValue, Mono, SeverityBadge } from "@/components/ui";
import { fmtPct, fmtTime } from "@/lib/format";
import type { Detection, Factor, Mitre } from "@/lib/schemas";

const COMPONENTS = ["signature", "anomaly", "behavioral", "threat_intel", "asset_criticality", "correlation"] as const;
const COMPONENT_LABEL: Record<(typeof COMPONENTS)[number], string> = {
  signature: "Signature",
  anomaly: "Anomaly (ML)",
  behavioral: "Behaviour vs baseline",
  threat_intel: "Threat intelligence",
  asset_criticality: "Asset criticality",
  correlation: "Recent related activity",
};

export function RiskBreakdown({ components }: { components: Record<string, unknown> | null | undefined }) {
  if (!components) return <p className="text-sm text-muted">No risk breakdown recorded.</p>;
  const reason = typeof components.reason === "string" ? components.reason : null;
  return (
    <div className="space-y-2">
      {COMPONENTS.map((k) => {
        const v = Number(components[k] ?? 0);
        return (
          <div key={k} className="grid grid-cols-[150px_1fr_40px] items-center gap-2 text-sm">
            <span className="text-muted">{COMPONENT_LABEL[k]}</span>
            <div className="h-2 overflow-hidden rounded bg-surface-2">
              <div className="h-full bg-accent" style={{ width: `${Math.min(100, v)}%` }} />
            </div>
            <span className="tabular text-right text-xs">{v.toFixed(0)}</span>
          </div>
        );
      })}
      {reason && <p className="pt-1 text-sm">{reason}</p>}
      {typeof components.formula === "string" && (
        <p className="text-xs text-muted">Formula: <Mono>{components.formula}</Mono></p>
      )}
    </div>
  );
}

export function FactorList({ factors }: { factors: Factor[] }) {
  if (!factors.length) return <p className="text-sm text-muted">The detectors recorded no contributing factors.</p>;
  return (
    <ul className="space-y-1.5 text-sm">
      {factors.map((f, i) => (
        <li key={i} className="flex gap-2">
          <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-accent" aria-hidden />
          <span>
            {f.detail ?? f.label ?? f.feature}
            {f.source && <span className="ml-1 text-xs text-muted">({f.source.replace(/_/g, " ")})</span>}
          </span>
        </li>
      ))}
    </ul>
  );
}

export function MitreList({ items }: { items: Mitre[] }) {
  if (!items.length) {
    return <p className="text-sm text-muted">No ATT&amp;CK technique is supported by the evidence for this detection.</p>;
  }
  return (
    <ul className="space-y-2 text-sm">
      {items.map((m) => (
        <li key={m.technique_id} className="rounded-md border border-line p-2">
          <div className="flex flex-wrap items-center gap-2">
            <a href={m.url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 font-medium text-accent hover:underline">
              {m.technique_id} <ExternalLink className="size-3" aria-hidden />
            </a>
            <span>{m.name}</span>
            <span className="text-xs text-muted">{m.tactic}</span>
            <span className="ml-auto text-xs" title="Hypothesis confidence, not certainty">confidence {fmtPct(m.confidence, 0)}</span>
          </div>
          <p className="mt-1 text-xs text-muted">Evidence: {m.evidence}</p>
        </li>
      ))}
    </ul>
  );
}

export function DetectionSummary({ d }: { d: Detection }) {
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <ClassificationBadge value={d.classification} />
        <SeverityBadge severity={d.severity} />
        <span className="text-sm text-muted">{d.category.replace(/_/g, " ")}</span>
      </div>
      <p className="text-sm">{d.summary}</p>
      <KeyValue
        items={[
          ["Time", fmtTime(d.ts)],
          ["Flow", <Mono key="f">{d.src_ip}{d.src_port ? `:${d.src_port}` : ""} → {d.dst_ip}{d.dst_port !== null ? `:${d.dst_port}` : ""} ({d.protocol})</Mono>],
          ["Detectors", d.detectors_fired.join(", ")],
          ["Anomaly score", d.anomaly_score !== null ? `${fmtPct(d.anomaly_score, 2)} percentile of normal validation traffic` : "model not applied"],
          ["Confidence", fmtPct(d.confidence, 0)],
          ["Risk", `${d.risk_score.toFixed(0)} / 100`],
          ["Rule", d.rule_id ?? "—"],
          ["Model", d.model_version ?? "—"],
        ]}
      />
    </div>
  );
}
