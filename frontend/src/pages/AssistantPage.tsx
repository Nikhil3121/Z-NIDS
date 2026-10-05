import { useMutation, useQuery } from "@tanstack/react-query";
import { Bot } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { z } from "zod";

import { Button, Card, Input, PageHeader } from "@/components/ui";
import { errorMessage, get, post } from "@/lib/api";
import { AssistantAnswer } from "@/lib/schemas";

const Status = z.object({ llm_available: z.boolean(), model: z.string().nullable(), mode: z.string(), can_execute_actions: z.boolean() });
const EXAMPLES = ["Show today's critical incidents", "Summarize incident INC-1003", "What happened to 10.20.1.87?", "Show open potential unknown incidents"];

function citeLink(c: string): string | null {
  const m = /^(INC|ALT|DET)-(\d+)$/.exec(c);
  if (!m) return null;
  return { INC: "/incidents/", ALT: "/alerts/", DET: "/detections/" }[m[1] as "INC" | "ALT" | "DET"] + m[2];
}

/** Renders "[INC-1003]" citations as links; everything else is plain text (no HTML injection). */
function Answer({ text }: { text: string }) {
  const parts = text.split(/(\[[A-Z]{2,4}-[^\]]+\])/g);
  return (
    <p className="whitespace-pre-wrap text-sm leading-6">
      {parts.map((p, i) => {
        const m = /^\[(.+)\]$/.exec(p);
        const href = m ? citeLink(m[1]) : null;
        return href ? <Link key={i} to={href} className="font-mono text-xs text-accent hover:underline">[{m![1]}]</Link> : <span key={i}>{p}</span>;
      })}
    </p>
  );
}

export default function AssistantPage() {
  const status = useQuery({ queryKey: ["assistant", "status"], queryFn: () => get("/assistant/status", Status) });
  const [question, setQuestion] = useState("");
  const [history, setHistory] = useState<{ q: string; a: z.infer<typeof AssistantAnswer> }[]>([]);
  const ask = useMutation({
    mutationFn: (q: string) => post("/assistant/ask", AssistantAnswer, { question: q }),
    onSuccess: (a, q) => { setHistory((h) => [{ q, a }, ...h]); setQuestion(""); },
  });
  const submit = (e: FormEvent) => { e.preventDefault(); if (question.trim()) ask.mutate(question.trim()); };
  return (
    <>
      <PageHeader title="AI Security Assistant"
                  subtitle="Answers only from Z-NIDS records and cites them (INC-, ALT-, DET- …). If the platform has no evidence, it says so. It cannot take actions." />
      <Card className="mb-4">
        {status.data && (
          <p className="mb-3 text-xs text-muted">
            Mode: <strong>{status.data.mode === "llm" ? `language model (${status.data.model}) over retrieved evidence` : "evidence-only (no language model configured)"}</strong>.
            Answers citing records outside the retrieved evidence are discarded automatically.
          </p>
        )}
        <form onSubmit={submit} className="flex gap-2">
          <Input value={question} onChange={(e) => setQuestion(e.target.value)} placeholder="Ask about an incident, alert, detection or IP address…" aria-label="Question" maxLength={1000} />
          <Button type="submit" busy={ask.isPending} disabled={!question.trim()}><Bot className="size-4" /> Ask</Button>
        </form>
        <div className="mt-2 flex flex-wrap gap-2">
          {EXAMPLES.map((e) => <button key={e} className="rounded-full border border-line px-2.5 py-0.5 text-xs hover:bg-surface-2" onClick={() => ask.mutate(e)}>{e}</button>)}
        </div>
        {ask.isError && <p className="mt-2 text-sm text-critical">{errorMessage(ask.error)}</p>}
      </Card>
      <div className="space-y-4">
        {history.map(({ q, a }, i) => (
          <Card key={i} title={q}>
            <Answer text={a.answer} />
            {a.notes.length > 0 && <ul className="mt-2 list-disc pl-5 text-xs text-muted">{a.notes.map((n, j) => <li key={j}>{n}</li>)}</ul>}
            <details className="mt-3 text-xs">
              <summary className="cursor-pointer text-muted">Evidence used ({a.evidence.length} records)</summary>
              <ul className="mt-2 space-y-1">
                {a.evidence.map((e) => (
                  <li key={e.citation}><span className="font-mono">{e.citation}</span> <span className="text-muted">{e.type}</span></li>
                ))}
              </ul>
            </details>
          </Card>
        ))}
      </div>
    </>
  );
}
