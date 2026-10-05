import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useRef, useState } from "react";
import { useSearchParams } from "react-router";

import { Card, ClassificationBadge, DemoTag, Empty, ErrorState, Input, Mono, PageHeader, Pager, Select, Spinner } from "@/components/ui";
import { useDebounced } from "@/hooks/useDebounced";
import { get } from "@/lib/api";
import { fmtBytes, fmtTime } from "@/lib/format";
import { Event, page, type NetEvent } from "@/lib/schemas";

const EventsPage = page(Event);
const ROW_HEIGHT = 38;
const COLS = "grid-cols-[170px_150px_150px_70px_70px_90px_90px_150px_60px]";

export default function EventsExplorerPage() {
  const [params, setParams] = useSearchParams();
  const [ip, setIp] = useState(params.get("ip") ?? "");
  const [classification, setClassification] = useState(params.get("classification") ?? "");
  const [protocol, setProtocol] = useState("");
  const [port, setPort] = useState("");
  const [pageNo, setPageNo] = useState(1);
  const debouncedIp = useDebounced(ip.trim());
  const debouncedPort = useDebounced(port.trim());

  const query = {
    ip: debouncedIp || undefined,
    classification: classification || undefined,
    protocol: protocol || undefined,
    dst_port: debouncedPort || undefined,
    page: pageNo,
    page_size: 200,
  };
  const q = useQuery({
    queryKey: ["events", query],
    queryFn: ({ signal }) => get("/events", EventsPage, query, signal),
    placeholderData: keepPreviousData,
  });

  const setFilter = (fn: () => void) => {
    fn();
    setPageNo(1);
  };

  return (
    <>
      <PageHeader title="Events Explorer" subtitle="Normalised flow records from all sensors. Server-side filtering and paging — the browser never loads the full history." />
      <Card dense>
        <div className="flex flex-wrap gap-2 border-b border-line p-3">
          <Input className="w-48" placeholder="IP address" value={ip} aria-label="Filter by IP"
                 onChange={(e) => setFilter(() => { setIp(e.target.value); setParams(e.target.value ? { ip: e.target.value } : {}); })} />
          <Select value={classification} aria-label="Classification" onChange={(e) => setFilter(() => setClassification(e.target.value))}>
            <option value="">All verdicts</option>
            <option value="NORMAL">Normal</option>
            <option value="KNOWN_ATTACK">Known attack</option>
            <option value="ANOMALOUS">Anomalous</option>
            <option value="POTENTIAL_UNKNOWN">Potential unknown</option>
          </Select>
          <Select value={protocol} aria-label="Protocol" onChange={(e) => setFilter(() => setProtocol(e.target.value))}>
            <option value="">All protocols</option>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
            <option value="icmp">ICMP</option>
          </Select>
          <Input className="w-28" placeholder="Dst port" inputMode="numeric" value={port} aria-label="Destination port"
                 onChange={(e) => setFilter(() => setPort(e.target.value.replace(/\D/g, "")))} />
        </div>
        {q.isPending && <Spinner />}
        {q.isError && <div className="p-3"><ErrorState error={q.error} onRetry={() => void q.refetch()} /></div>}
        {q.data && (q.data.items.length === 0 ? <Empty title="No events" hint="No flows match these filters." /> : (
          <VirtualRows rows={q.data.items} />
        ))}
        {q.data && <Pager page={q.data.page} pages={q.data.pages} total={q.data.total} onPage={setPageNo} />}
      </Card>
    </>
  );
}

function VirtualRows({ rows }: { rows: NetEvent[] }) {
  const parent = useRef<HTMLDivElement>(null);
  // eslint-disable-next-line react-hooks/incompatible-library
  const v = useVirtualizer({ count: rows.length, getScrollElement: () => parent.current, estimateSize: () => ROW_HEIGHT, overscan: 12 });
  return (
    <div className="overflow-x-auto">
      <div className="min-w-[1000px]">
        <div className={`grid ${COLS} gap-2 border-b border-line px-3 py-2 text-xs font-medium uppercase tracking-wide text-muted`}>
          <span>Time</span><span>Source</span><span>Destination</span><span>Proto</span><span>State</span>
          <span>Sent</span><span>Received</span><span>Verdict</span><span>Risk</span>
        </div>
        <div ref={parent} className="h-[60vh] overflow-y-auto" role="table" aria-rowcount={rows.length}>
          <div style={{ height: v.getTotalSize(), position: "relative" }}>
            {v.getVirtualItems().map((item) => {
              const e = rows[item.index];
              return (
                <div key={e.id} role="row"
                     className={`absolute left-0 right-0 grid ${COLS} items-center gap-2 border-b border-line px-3 text-sm`}
                     style={{ height: ROW_HEIGHT, transform: `translateY(${item.start}px)` }}>
                  <span className="tabular text-xs">{fmtTime(e.ts)}</span>
                  <Mono>{e.src_ip}{e.src_port ? `:${e.src_port}` : ""}</Mono>
                  <Mono>{e.dst_ip}{e.dst_port !== null ? `:${e.dst_port}` : ""}</Mono>
                  <span className="uppercase">{e.protocol}</span>
                  <span className="text-xs text-muted">{e.conn_state ?? "—"}</span>
                  <span className="tabular text-xs">{fmtBytes(e.bytes_out)}</span>
                  <span className="tabular text-xs">{fmtBytes(e.bytes_in)}</span>
                  <span className="flex items-center gap-1"><ClassificationBadge value={e.classification} /><DemoTag show={e.is_demo} /></span>
                  <span className="tabular text-xs">{e.risk_score !== null ? e.risk_score.toFixed(0) : "—"}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
