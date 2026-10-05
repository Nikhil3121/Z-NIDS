import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";

import { Card, Empty, ErrorState, Input, PageHeader, Select, Spinner } from "@/components/ui";
import { get } from "@/lib/api";
import { fmtAgo, fmtBytes, fmtNum } from "@/lib/format";
import { Topology } from "@/lib/schemas";

/** Column per role, left to right: internet, perimeter, servers & databases, endpoints. */
const COLUMN: Record<string, number> = {
  internet: 0, external: 0,
  firewall: 1, network_device: 1, sensor: 1,
  server: 2, database: 2,
  endpoint: 3, unknown: 3,
};
const COLUMN_LABEL = ["Internet", "Perimeter / network", "Servers & databases", "Endpoints & other"];
const KIND_COLOR: Record<string, string> = {
  internet: "var(--muted)", external: "var(--muted)", firewall: "var(--high)", network_device: "var(--medium)",
  sensor: "var(--accent)", server: "var(--accent)", database: "var(--unknown)", endpoint: "var(--low)", unknown: "var(--info)",
};

export default function TopologyPage() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const [minutes, setMinutes] = useState(60);
  const incident = params.get("incident") ?? "";
  const [incidentInput, setIncidentInput] = useState(incident);
  const q = useQuery({
    queryKey: ["topology", minutes, incident],
    queryFn: () => get("/assets/topology", Topology, { minutes, incident_id: incident || undefined, max_edges: 200 }),
  });

  const layout = useMemo(() => {
    if (!q.data) return null;
    const cols: string[][] = [[], [], [], []];
    const byId = new Map(q.data.nodes.map((n) => [n.id, n]));
    const degree = new Map<string, number>();
    q.data.edges.forEach((e) => {
      degree.set(e.source, (degree.get(e.source) ?? 0) + e.flows);
      degree.set(e.target, (degree.get(e.target) ?? 0) + e.flows);
    });
    q.data.nodes.forEach((n) => cols[COLUMN[n.kind] ?? 3].push(n.id));
    cols.forEach((c) => c.sort((a, b) => (degree.get(b) ?? 0) - (degree.get(a) ?? 0)));
    const width = 1000;
    const rowH = 30;
    const height = Math.max(240, Math.max(...cols.map((c) => c.length)) * rowH + 60);
    const pos = new Map<string, { x: number; y: number }>();
    cols.forEach((c, ci) => {
      const x = 90 + ci * ((width - 180) / 3);
      const offset = (height - c.length * rowH) / 2;
      c.forEach((id, ri) => pos.set(id, { x, y: offset + ri * rowH + rowH / 2 }));
    });
    const maxFlows = Math.max(1, ...q.data.edges.map((e) => e.flows));
    return { byId, pos, width, height, maxFlows };
  }, [q.data]);

  return (
    <>
      <PageHeader
        title="Network Topology"
        subtitle="Built only from flows observed in the selected window. Red edges carried non-normal traffic; bold edges belong to the selected incident."
        actions={
          <>
            <Select value={minutes} onChange={(e) => setMinutes(Number(e.target.value))} aria-label="Window">
              <option value={15}>Last 15 min</option><option value={60}>Last hour</option><option value={360}>Last 6 hours</option>
              <option value={1440}>Last 24 hours</option>
            </Select>
            <form onSubmit={(e) => { e.preventDefault(); setParams(incidentInput ? { incident: incidentInput.replace(/\D/g, "") } : {}); }}>
              <Input className="w-40" placeholder="Incident id, e.g. 1004" value={incidentInput}
                     onChange={(e) => setIncidentInput(e.target.value)} aria-label="Highlight incident" />
            </form>
          </>
        }
      />
      {q.isPending && <Spinner />}
      {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}
      {q.data && layout && (
        q.data.nodes.length === 0 ? <Card><Empty title="No traffic observed in this window" /></Card> : (
          <Card dense>
            <div className="overflow-x-auto">
              <svg viewBox={`0 0 ${layout.width} ${layout.height}`} className="min-w-[800px]" role="img"
                   aria-label={`Topology with ${q.data.nodes.length} nodes and ${q.data.edges.length} observed connections`}>
                {COLUMN_LABEL.map((l, i) => (
                  <text key={l} x={90 + i * ((layout.width - 180) / 3)} y={18} textAnchor="middle" fontSize={11} fill="var(--muted)">{l}</text>
                ))}
                {q.data.edges.map((e, i) => {
                  const a = layout.pos.get(e.source);
                  const b = layout.pos.get(e.target);
                  if (!a || !b) return null;
                  const mx = (a.x + b.x) / 2;
                  const color = e.highlight ? "var(--unknown)" : e.suspicious > 0 ? "var(--critical)" : "var(--border)";
                  return (
                    <path key={i} d={`M${a.x},${a.y} C${mx},${a.y} ${mx},${b.y} ${b.x},${b.y}`} fill="none" stroke={color}
                          strokeOpacity={e.highlight || e.suspicious ? 0.9 : 0.6}
                          strokeWidth={e.highlight ? 3 : 0.6 + 2.4 * Math.sqrt(e.flows / layout.maxFlows)}>
                      <title>{`${e.source} → ${e.target}: ${fmtNum(e.flows)} flows, ${fmtBytes(e.bytes)}, ${e.suspicious} suspicious`}</title>
                    </path>
                  );
                })}
                {q.data.nodes.map((n) => {
                  const p = layout.pos.get(n.id);
                  if (!p) return null;
                  const col = COLUMN[n.kind] ?? 3;
                  const labelLeft = col === 3;
                  return (
                    <g key={n.id} className={n.asset_id ? "cursor-pointer" : undefined}
                       onClick={() => n.asset_id && navigate(`/assets/${n.asset_id}`)}>
                      <circle cx={p.x} cy={p.y} r={n.kind === "internet" ? 10 : 6} fill={KIND_COLOR[n.kind] ?? "var(--info)"}
                              stroke={n.risk >= 65 ? "var(--critical)" : "var(--surface)"} strokeWidth={n.risk >= 65 ? 3 : 1.5} />
                      <text x={labelLeft ? p.x + 10 : p.x - 10} y={p.y + 4} fontSize={10.5} textAnchor={labelLeft ? "start" : "end"}
                            fill="var(--text)">
                        {n.kind === "internet" ? `Internet (${n.external_hosts ?? 0} hosts)` : n.label}
                      </text>
                      <title>{`${n.label} (${n.kind}) — risk ${n.risk.toFixed(0)}${n.criticality ? `, ${n.criticality} criticality` : ""}`}</title>
                    </g>
                  );
                })}
              </svg>
            </div>
            <div className="flex flex-wrap items-center gap-4 border-t border-line px-3 py-2 text-xs text-muted">
              <span>{q.data.nodes.length} nodes · {q.data.edges.length} edges{q.data.truncated && " (busiest edges only)"}</span>
              <span>Sensors: {q.data.sensors.map((s) => `${s.name} (${fmtAgo(s.last_seen)})`).join(", ") || "none registered"}</span>
            </div>
          </Card>
        )
      )}
    </>
  );
}
