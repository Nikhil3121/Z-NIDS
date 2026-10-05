import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link } from "react-router";
import { Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { Card, ClassificationBadge, Empty, PageHeader, SeverityBadge, Stat } from "@/components/ui";
import { get } from "@/lib/api";
import { fmtBytes, fmtShortTime } from "@/lib/format";
import { Dashboard, type Classification, type Severity } from "@/lib/schemas";
import { useRealtime, type RealtimeMessage } from "@/realtime/RealtimeProvider";

type Sample = { t: string; eps: number; bps: number };

export default function LiveMonitoringPage() {
  const { status, last } = useRealtime();
  const q = useQuery({ queryKey: ["live"], queryFn: () => get("/dashboard/overview", Dashboard, { hours: 1 }) });
  const [series, setSeries] = useState<Sample[]>([]);

  // Rates are recomputed by the server whenever a processed-batch event arrives (no polling).
  useEffect(() => {
    if (!q.data) return;
    const d = q.data;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setSeries((s) => [...s.slice(-59), { t: fmtShortTime(d.generated_at), eps: d.live.events_per_sec, bps: d.live.bytes_per_sec }]);
  }, [q.data]);

  const alerts = last.filter((m) => m.type.startsWith("security."));
  const batches = last.filter((m) => m.type === "network.event.created");

  return (
    <>
      <PageHeader title="Live Monitoring" subtitle="Streaming activity pushed over the authenticated WebSocket." />
      <div className="mb-4 grid gap-3 md:grid-cols-4">
        <Stat label="Connection" value={status === "live" ? "Live" : status} tone={status === "live" ? "text-ok" : "text-medium"} />
        <Stat label="Events / sec" value={q.data?.live.events_per_sec.toFixed(2) ?? "—"} />
        <Stat label="Connections / sec" value={q.data?.live.connections_per_sec.toFixed(2) ?? "—"} />
        <Stat label="Traffic" value={q.data ? `${fmtBytes(q.data.live.bytes_per_sec)}/s` : "—"} />
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Event rate (updates as batches are processed)">
          {series.length < 2 ? <Empty title="Waiting for traffic" hint="The chart fills as sensors deliver events." /> : (
            <div className="h-60">
              <ResponsiveContainer>
                <LineChart data={series}>
                  <XAxis dataKey="t" tick={{ fontSize: 11, fill: "var(--muted)" }} minTickGap={30} />
                  <YAxis tick={{ fontSize: 11, fill: "var(--muted)" }} width={40} />
                  <Tooltip contentStyle={{ background: "var(--surface)", border: "1px solid var(--border)", fontSize: 12 }} />
                  <Line type="monotone" dataKey="eps" name="events/s" stroke="var(--accent)" dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>
        <Card title="Live security feed" dense>
          <ul className="max-h-72 divide-y divide-line overflow-y-auto">
            {alerts.length === 0 && <li><Empty title="No live alerts yet" hint="New and updated alerts and incidents appear here as they happen." /></li>}
            {alerts.map((m, i) => <FeedItem key={`${m.ts}-${i}`} m={m} />)}
          </ul>
        </Card>
      </div>
      <Card title="Processed batches" className="mt-4" dense>
        <ul className="max-h-64 divide-y divide-line overflow-y-auto text-sm">
          {batches.length === 0 && <li className="p-3 text-muted">No batches received on this page yet.</li>}
          {batches.map((m, i) => {
            const d = m.data as { count?: number; detections?: number; by_classification?: Record<string, number>; demo?: boolean };
            return (
              <li key={`${m.ts}-${i}`} className="flex flex-wrap items-center gap-3 px-3 py-2">
                <span className="tabular text-xs text-muted">{fmtShortTime(m.ts)}</span>
                <span>{d.count} flows</span>
                <span className="text-muted">{d.detections} detections</span>
                {Object.entries(d.by_classification ?? {}).map(([k, v]) => (
                  <span key={k} className="flex items-center gap-1"><ClassificationBadge value={k as Classification} /> {v}</span>
                ))}
                {d.demo && <span className="text-xs text-unknown">lab</span>}
              </li>
            );
          })}
        </ul>
      </Card>
    </>
  );
}

function FeedItem({ m }: { m: RealtimeMessage }) {
  const d = m.data as { id?: number; title?: string; severity?: Severity; reference?: string; classification?: Classification };
  const isIncident = m.type.includes("incident");
  return (
    <li className="flex items-center gap-2 px-3 py-2 text-sm">
      <span className="tabular text-xs text-muted">{fmtShortTime(m.ts)}</span>
      {d.severity && <SeverityBadge severity={d.severity} />}
      <Link to={isIncident ? `/incidents/${d.id}` : `/alerts/${d.id}`} className="min-w-0 flex-1 truncate hover:underline">
        {isIncident ? `${d.reference} ` : ""}{d.title}
      </Link>
      <span className="text-xs text-muted">{m.type.replace("security.", "")}</span>
    </li>
  );
}
