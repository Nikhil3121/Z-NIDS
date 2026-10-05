import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { Card, ErrorState, Mono, PageHeader, RiskBar, Select, Spinner, Stat } from "@/components/ui";
import { get } from "@/lib/api";
import { fmtBytes, fmtNum, fmtShortTime, titleCase } from "@/lib/format";
import { Dashboard } from "@/lib/schemas";

export const CLASS_COLORS = {
  normal: "var(--ok)",
  anomalous: "var(--medium)",
  known_attack: "var(--critical)",
  potential_unknown: "var(--unknown)",
};
const SEV_COLORS: Record<string, string> = {
  critical: "var(--critical)", high: "var(--high)", medium: "var(--medium)", low: "var(--low)", info: "var(--info)",
};
const tooltipStyle = { background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 6, fontSize: 12 };

export default function DashboardPage() {
  const [hours, setHours] = useState(24);
  const q = useQuery({ queryKey: ["dashboard", hours], queryFn: () => get("/dashboard/overview", Dashboard, { hours }) });

  return (
    <>
      <PageHeader
        title="Security Overview"
        subtitle="Every figure is computed from stored events, detections and incidents. Updates arrive over the live connection."
        actions={
          <Select value={hours} onChange={(e) => setHours(Number(e.target.value))} aria-label="Time window">
            <option value={1}>Last hour</option>
            <option value={24}>Last 24 hours</option>
            <option value={168}>Last 7 days</option>
          </Select>
        }
      />
      {q.isPending && <Spinner />}
      {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}
      {q.data && <DashboardBody d={q.data} />}
    </>
  );
}

function DashboardBody({ d }: { d: Dashboard }) {
  const o = d.overview;
  const dist = Object.entries(d.detection_distribution).map(([k, v]) => ({ name: titleCase(k), key: k, value: v }));
  const sev = Object.entries(d.severity).map(([k, v]) => ({ name: k, value: v }));
  const timeline = d.timeline.points.map((p) => ({ ...p, t: fmtShortTime(p.ts) }));
  const trendCats = [...new Set(d.attack_trends.map((t) => t.category))];
  const trendRows = Object.values(
    d.attack_trends.reduce<Record<string, Record<string, string | number>>>((acc, t) => {
      const h = fmtShortTime(t.hour);
      acc[h] ??= { hour: h };
      acc[h][t.category] = t.count;
      return acc;
    }, {}),
  );
  const palette = ["var(--critical)", "var(--unknown)", "var(--high)", "var(--medium)", "var(--accent)", "var(--low)"];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Total events" value={fmtNum(o.total_events)} hint={fmtBytes(o.traffic_bytes)} />
        <Stat label="Active incidents" value={o.active_incidents} tone={o.active_incidents ? "text-high" : undefined} />
        <Stat label="Critical alerts" value={o.critical_alerts} tone={o.critical_alerts ? "text-critical" : undefined}
              hint={`${o.open_alerts} open alerts`} />
        <Stat label="Unknown anomalies" value={fmtNum(o.unknown_anomalies)} tone="text-unknown"
              hint="Potential unknown attack flows" />
        <Stat label="Blocked IPs (lab)" value={o.blocked_ips_lab}
              hint={`${o.response_actions_executed} executed · ${o.response_actions_pending} awaiting approval`} />
        <Stat label="Assets monitored" value={o.assets_monitored} />
      </div>

      <div className="grid gap-3 md:grid-cols-3">
        <Stat label="Events / sec" value={d.live.events_per_sec.toFixed(2)} hint="Arrivals in the last 60 s" />
        <Stat label="Connections / sec" value={d.live.connections_per_sec.toFixed(2)} hint="One flow = one connection" />
        <Stat label="Traffic volume" value={`${fmtBytes(d.live.bytes_per_sec)}/s`} hint="Last 60 s" />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Event timeline" className="xl:col-span-2">
          {timeline.length === 0 ? <p className="text-sm text-muted">No events in this window.</p> : (
            <div className="h-64">
              <ResponsiveContainer>
                <AreaChart data={timeline}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                  <XAxis dataKey="t" tick={{ fontSize: 11, fill: "var(--muted)" }} minTickGap={24} />
                  <YAxis tick={{ fontSize: 11, fill: "var(--muted)" }} width={48} />
                  <Tooltip contentStyle={tooltipStyle} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  {(["normal", "anomalous", "known_attack", "potential_unknown"] as const).map((k) => (
                    <Area key={k} type="monotone" dataKey={k} name={titleCase(k)} stackId="1"
                          stroke={CLASS_COLORS[k]} fill={CLASS_COLORS[k]} fillOpacity={0.35} />
                  ))}
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>
        <Card title="Detection distribution">
          <div className="h-64">
            <ResponsiveContainer>
              <PieChart>
                <Pie data={dist} dataKey="value" nameKey="name" innerRadius={50} outerRadius={85} paddingAngle={2}>
                  {dist.map((e) => <Cell key={e.key} fill={CLASS_COLORS[e.key as keyof typeof CLASS_COLORS]} />)}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Open alerts by severity">
          <div className="h-56">
            <ResponsiveContainer>
              <BarChart data={sev}>
                <XAxis dataKey="name" tick={{ fontSize: 11, fill: "var(--muted)" }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: "var(--muted)" }} width={32} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--surface-2)" }} />
                <Bar dataKey="value" name="Alerts">{sev.map((s) => <Cell key={s.name} fill={SEV_COLORS[s.name]} />)}</Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title="Attack trends (detections per hour)" className="xl:col-span-2">
          {trendRows.length === 0 ? <p className="text-sm text-muted">No detections in this window.</p> : (
            <div className="h-56">
              <ResponsiveContainer>
                <BarChart data={trendRows}>
                  <XAxis dataKey="hour" tick={{ fontSize: 11, fill: "var(--muted)" }} />
                  <YAxis tick={{ fontSize: 11, fill: "var(--muted)" }} width={40} />
                  <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--surface-2)" }} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  {trendCats.map((c, i) => <Bar key={c} dataKey={c} name={titleCase(c)} stackId="a" fill={palette[i % palette.length]} />)}
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-4">
        <TalkerCard title="Top source IPs" rows={d.top_sources} />
        <TalkerCard title="Top destination IPs" rows={d.top_destinations} />
        <Card title="Protocol distribution">
          <ul className="space-y-1.5 text-sm">
            {d.protocols.map((p) => (
              <li key={p.protocol} className="flex justify-between"><span className="uppercase">{p.protocol}</span>
                <span className="tabular text-muted">{fmtNum(p.flows)}</span></li>
            ))}
            {d.protocols.length === 0 && <li className="text-muted">No traffic.</li>}
          </ul>
        </Card>
        <Card title="Asset risk">
          <ul className="space-y-2 text-sm">
            {d.asset_risk.map((a) => (
              <li key={a.id} className="flex items-center justify-between gap-2">
                <Link to={`/assets/${a.id}`} className="min-w-0 truncate hover:underline">{a.hostname ?? a.ip}</Link>
                <RiskBar value={a.risk_score} />
              </li>
            ))}
            {d.asset_risk.length === 0 && <li className="text-muted">No asset has recent risky activity.</li>}
          </ul>
        </Card>
      </div>
    </div>
  );
}

function TalkerCard({ title, rows }: { title: string; rows: { ip: string; flows: number; suspicious: number }[] }) {
  return (
    <Card title={title}>
      <ul className="space-y-1.5 text-sm">
        {rows.map((r) => (
          <li key={r.ip} className="flex items-center justify-between gap-2">
            <Link to={`/events?ip=${encodeURIComponent(r.ip)}`} className="hover:underline"><Mono>{r.ip}</Mono></Link>
            <span className="tabular text-xs text-muted">
              {fmtNum(r.flows)}{r.suspicious > 0 && <span className="ml-1 text-high">· {fmtNum(r.suspicious)} suspicious</span>}
            </span>
          </li>
        ))}
        {rows.length === 0 && <li className="text-muted">No traffic.</li>}
      </ul>
    </Card>
  );
}
