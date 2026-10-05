import clsx from "clsx";
import { AlertTriangle, ChevronLeft, ChevronRight, Inbox, Loader2 } from "lucide-react";
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from "react";

import { errorMessage } from "@/lib/api";
import type { Classification, Severity } from "@/lib/schemas";

export function Card({ title, actions, children, className, dense }: {
  title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; dense?: boolean;
}) {
  return (
    <section className={clsx("rounded-lg border border-line bg-surface", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-2.5">
          <h2 className="text-sm font-semibold">{title}</h2>
          <div className="flex items-center gap-2">{actions}</div>
        </header>
      )}
      <div className={dense ? "" : "p-4"}>{children}</div>
    </section>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-1 max-w-3xl text-sm text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "bg-critical/15 text-critical border-critical/40",
  high: "bg-high/15 text-high border-high/40",
  medium: "bg-medium/15 text-medium border-medium/40",
  low: "bg-low/15 text-low border-low/40",
  info: "bg-info/15 text-info border-info/40",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={clsx("inline-flex rounded border px-1.5 py-0.5 text-[11px] font-semibold uppercase", SEVERITY_STYLE[severity])}>
      {severity}
    </span>
  );
}

const CLASS_LABEL: Record<Classification, string> = {
  NORMAL: "Normal",
  KNOWN_ATTACK: "Known attack",
  ANOMALOUS: "Anomalous",
  POTENTIAL_UNKNOWN: "Potential unknown attack",
};
const CLASS_STYLE: Record<Classification, string> = {
  NORMAL: "text-ok border-ok/40",
  KNOWN_ATTACK: "text-critical border-critical/40",
  ANOMALOUS: "text-medium border-medium/40",
  POTENTIAL_UNKNOWN: "text-unknown border-unknown/50 bg-unknown/10",
};

export function ClassificationBadge({ value }: { value: Classification | null | undefined }) {
  if (!value) return <span className="text-xs text-muted">pending</span>;
  return (
    <span className={clsx("inline-flex whitespace-nowrap rounded border px-1.5 py-0.5 text-[11px] font-medium", CLASS_STYLE[value])}>
      {CLASS_LABEL[value]}
    </span>
  );
}

export function StatusPill({ value }: { value: string }) {
  const tone =
    value === "RESOLVED" || value === "EXECUTED" || value === "ACTIVE" || value === "SENT"
      ? "text-ok border-ok/40"
      : value === "NEW" || value === "OPEN" || value === "PROPOSED" || value === "FAILED"
        ? "text-high border-high/40"
        : "text-muted border-line";
  return <span className={clsx("rounded border px-1.5 py-0.5 text-[11px] font-medium", tone)}>{value.replace(/_/g, " ")}</span>;
}

export function DemoTag({ show }: { show: boolean }) {
  if (!show) return null;
  return (
    <span className="rounded border border-unknown/50 px-1 py-px text-[10px] font-semibold uppercase text-unknown"
          title="Synthetic lab data">
      lab
    </span>
  );
}

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: ReactNode; tone?: string }) {
  return (
    <div className="rounded-lg border border-line bg-surface p-4">
      <div className="text-xs font-medium uppercase tracking-wide text-muted">{label}</div>
      <div className={clsx("tabular mt-1 text-2xl font-semibold", tone)}>{value}</div>
      {hint && <div className="mt-1 text-xs text-muted">{hint}</div>}
    </div>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 p-4 text-sm text-muted" role="status">
      <Loader2 className="size-4 animate-spin" aria-hidden />
      {label ?? "Loading"}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex items-start gap-3 rounded-md border border-critical/40 bg-critical/10 p-3 text-sm">
      <AlertTriangle className="mt-0.5 size-4 shrink-0 text-critical" aria-hidden />
      <div className="flex-1">
        <div className="font-medium">Could not load data</div>
        <div className="text-muted">{errorMessage(error)}</div>
      </div>
      {onRetry && <Button size="sm" variant="ghost" onClick={onRetry}>Retry</Button>}
    </div>
  );
}

export function Empty({ title, hint }: { title: string; hint?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-1 p-8 text-center text-sm text-muted">
      <Inbox className="size-6" aria-hidden />
      <div className="font-medium text-ink">{title}</div>
      {hint && <div className="max-w-md">{hint}</div>}
    </div>
  );
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "ghost" | "danger" | "outline";
  size?: "sm" | "md";
  busy?: boolean;
};

export function Button({ variant = "primary", size = "md", busy, className, children, disabled, ...rest }: ButtonProps) {
  return (
    <button
      {...rest}
      disabled={disabled || busy}
      className={clsx(
        "inline-flex items-center justify-center gap-1.5 rounded-md font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        size === "sm" ? "px-2.5 py-1 text-xs" : "px-3.5 py-2 text-sm",
        variant === "primary" && "bg-accent text-white hover:brightness-110",
        variant === "danger" && "bg-critical text-white hover:brightness-110",
        variant === "outline" && "border border-line bg-surface hover:bg-surface-2",
        variant === "ghost" && "hover:bg-surface-2",
        className,
      )}
    >
      {busy && <Loader2 className="size-3.5 animate-spin" aria-hidden />}
      {children}
    </button>
  );
}

export function Input({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...rest}
      className={clsx("w-full rounded-md border border-line bg-surface px-3 py-2 text-sm placeholder:text-muted", className)}
    />
  );
}

export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select {...rest} className={clsx("rounded-md border border-line bg-surface px-2.5 py-2 text-sm", className)}>
      {children}
    </select>
  );
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: ReactNode }) {
  return (
    <label className="block text-sm">
      <span className="mb-1 block font-medium">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-muted">{hint}</span>}
    </label>
  );
}

export function Table({ head, children, empty }: { head: ReactNode[]; children: ReactNode; empty?: boolean }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-line text-xs uppercase tracking-wide text-muted">
          <tr>{head.map((h, i) => <th key={i} className="whitespace-nowrap px-3 py-2 font-medium">{h}</th>)}</tr>
        </thead>
        <tbody className="divide-y divide-line">{children}</tbody>
      </table>
      {empty && <Empty title="Nothing here yet" hint="No records match the current filters." />}
    </div>
  );
}

export function Pager({ page, pages, total, onPage }: { page: number; pages: number; total: number; onPage: (p: number) => void }) {
  return (
    <div className="flex items-center justify-between border-t border-line px-3 py-2 text-xs text-muted">
      <span className="tabular">{total.toLocaleString()} records</span>
      <div className="flex items-center gap-2">
        <Button size="sm" variant="ghost" disabled={page <= 1} onClick={() => onPage(page - 1)} aria-label="Previous page">
          <ChevronLeft className="size-4" />
        </Button>
        <span className="tabular">Page {page} of {Math.max(pages, 1)}</span>
        <Button size="sm" variant="ghost" disabled={page >= pages} onClick={() => onPage(page + 1)} aria-label="Next page">
          <ChevronRight className="size-4" />
        </Button>
      </div>
    </div>
  );
}

export function KeyValue({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5 text-sm">
      {items.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-muted">{k}</dt>
          <dd className="min-w-0 break-words">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function RiskBar({ value }: { value: number }) {
  const tone = value >= 85 ? "bg-critical" : value >= 65 ? "bg-high" : value >= 40 ? "bg-medium" : "bg-low";
  return (
    <div className="flex items-center gap-2" title={`Risk ${value.toFixed(0)} / 100`}>
      <div className="h-1.5 w-16 overflow-hidden rounded bg-surface-2">
        <div className={clsx("h-full", tone)} style={{ width: `${Math.min(100, Math.max(0, value))}%` }} />
      </div>
      <span className="tabular text-xs">{value.toFixed(0)}</span>
    </div>
  );
}

export function Mono({ children }: { children: ReactNode }) {
  return <span className="font-mono text-[13px]">{children}</span>;
}
