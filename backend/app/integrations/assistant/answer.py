"""Grounded answer generation.

Two modes:
* **LLM** (ANTHROPIC_API_KEY set): Claude writes the answer from the retrieved
  evidence only. The evidence is passed as data, the system prompt forbids
  outside facts, and the answer is then *checked*: any citation that does not
  exist in the evidence set causes the LLM answer to be discarded in favour of
  the deterministic one.
* **Evidence-only** (no key, or the LLM failed): a deterministic summary built
  directly from the records.

The assistant has no tools and cannot execute response actions.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

import anthropic

from app.core.config import get_settings
from app.integrations.assistant.retrieval import Retrieval

logger = logging.getLogger(__name__)

INSUFFICIENT = "The available platform evidence is insufficient to answer this question."

SYSTEM_PROMPT = """You are the Z-NIDS security assistant for SOC analysts.

Answer strictly from the evidence records supplied in the user turn. They are exported \
from the Z-NIDS database and are the only facts you may use.

Rules:
- Cite every factual statement with the record's citation ID in square brackets, e.g. [INC-1004], [ALT-12], [DET-55].
- Use only citation IDs that appear in the evidence. Never invent events, alerts, incidents, indicators, or IDs.
- Do not claim any response action (blocking, quarantine) happened unless a response_action record shows status EXECUTED.
- Threat-intelligence statements must come from threat_intel records; do not add reputation knowledge of your own.
- Anomaly detections describe previously unseen behaviour. Call them "potential unknown attacks" or "anomalies" - never confirmed zero-day exploits.
- If a record is marked demo: true, mention that it is lab/demo data.
- You cannot take actions. If asked to, explain that response actions must be requested and approved in the Response workflow.
- If the evidence does not answer the question, say exactly: "The available platform evidence is insufficient to answer this question." and state what is missing.

Be concise and analyst-oriented: lead with the answer, then the supporting points."""

_CITE = re.compile(r"\[([A-Z]{2,4}-[0-9A-Za-z.:/\-]+?)\]")


@dataclass
class Answer:
    answer: str
    citations: list[str]
    mode: str  # llm | evidence_only
    model: str | None = None
    notes: list[str] = field(default_factory=list)


def llm_configured() -> bool:
    return bool(get_settings().anthropic_api_key)


def _deterministic(r: Retrieval) -> Answer:
    if not r.items:
        notes = r.scope_notes or ["No matching incidents, alerts, detections or events were found."]
        return Answer(INSUFFICIENT + " " + " ".join(notes), [], "evidence_only", notes=notes)
    lines: list[str] = []
    for item in r.items:
        d = item.data
        if item.kind == "incident":
            lines.append(
                f"[{item.cite}] {d['title']} — {d['severity']}, {d['status']}, risk {d['risk_score']:.0f}"
                + (f", classification {d['classification']}" if d.get("classification") else "")
                + (" (lab/demo data)" if d.get("demo") else "")
            )
        elif item.kind == "alert":
            lines.append(
                f"[{item.cite}] {d['title']} — {d['severity']}, {d['status']}, "
                f"{d['occurrences']} occurrence(s), last seen {d['last_seen']}"
            )
        elif item.kind == "detection":
            why = "; ".join(x for x in d["explanation"][:3] if x)
            lines.append(
                f"[{item.cite}] {d['classification']} ({d['category']}) {d['src']} → {d['dst']}, "
                f"risk {d['risk_score']:.0f}. {d.get('risk_reason') or ''} {('Factors: ' + why) if why else ''}"
            )
        elif item.kind == "ip_activity":
            lines.append(
                f"[{item.cite}] {d['ip']}: {d['flows']} flows since {d['window_start']}, "
                f"{d['non_normal_flows']} not classified normal"
            )
        elif item.kind == "threat_intel":
            lines.append(
                f"[{item.cite}] {d['ip']} rated {d['reputation']} by {d['provider']} "
                f"(confidence {d['confidence']:.0f})"
            )
        elif item.kind == "response_action":
            lines.append(f"[{item.cite}] {d['action']} {d['target']}: {d['status']}")
        elif item.kind in ("incident_activity", "evidence"):
            lines.append(f"[{item.cite}] {d.get('message') or d.get('content')}")
        elif item.kind == "event":
            lines.append(f"[{item.cite}] {d['src']} → {d['dst']} {d['protocol']}, classification {d['classification']}")
    text = "Evidence found in Z-NIDS:\n" + "\n".join(f"- {line.strip()}" for line in lines)
    if r.scope_notes:
        text += "\n\nNotes: " + " ".join(r.scope_notes)
    return Answer(text, sorted(r.citations), "evidence_only", notes=r.scope_notes)


def _evidence_payload(r: Retrieval) -> str:
    return json.dumps(
        [{"citation": i.cite, "type": i.kind, "record": i.data} for i in r.items], default=str, sort_keys=True
    )


def answer(r: Retrieval) -> Answer:
    fallback = _deterministic(r)
    if not r.items or not llm_configured():
        return fallback
    settings = get_settings()
    client = anthropic.Anthropic(
        api_key=settings.anthropic_api_key, timeout=settings.assistant_timeout_seconds, max_retries=2
    )
    user_content = (
        "<evidence>\n"
        + _evidence_payload(r)
        + "\n</evidence>\n\n"
        + ("<scope_notes>" + " ".join(r.scope_notes) + "</scope_notes>\n\n" if r.scope_notes else "")
        + "<question>\n"
        + r.question
        + "\n</question>"
    )
    try:
        response = client.beta.messages.create(
            model=settings.assistant_model,
            max_tokens=settings.assistant_max_tokens,
            system=[{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user_content}],
            output_config={"effort": "medium"},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
    except anthropic.RateLimitError:
        logger.warning("assistant LLM rate limited; returning evidence-only answer")
        fallback.notes.append("The language model was rate limited; showing the evidence directly.")
        return fallback
    except (anthropic.APIStatusError, anthropic.APIConnectionError) as exc:
        logger.error("assistant LLM call failed", extra={"error_type": type(exc).__name__})
        fallback.notes.append("The language model was unavailable; showing the evidence directly.")
        return fallback

    if response.stop_reason == "refusal":
        fallback.notes.append("The language model declined this request; showing the evidence directly.")
        return fallback
    text = "".join(b.text for b in response.content if b.type == "text").strip()
    cited = set(_CITE.findall(text))
    unknown = cited - r.citations
    if not text or unknown:
        # Grounding check failed: never show an answer that cites records we did not supply.
        logger.warning("assistant answer failed grounding check", extra={"unknown_citations": sorted(unknown)})
        fallback.notes.append("The generated answer referenced records outside the evidence and was discarded.")
        return fallback
    notes = list(r.scope_notes)
    if response.stop_reason == "max_tokens":
        notes.append("Answer was truncated at the length limit.")
    return Answer(text, sorted(cited), "llm", model=response.model, notes=notes)


def evidence_view(r: Retrieval) -> list[dict[str, Any]]:
    return [{"citation": i.cite, "type": i.kind, "record": i.data} for i in r.items]
