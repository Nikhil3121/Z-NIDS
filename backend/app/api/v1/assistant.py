"""/api/v1/assistant — evidence-grounded security Q&A (read-only)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import Field
from starlette.concurrency import run_in_threadpool

from app.api.deps import DbSession, Meta, require
from app.core.config import get_settings
from app.core.rate_limit import rate_limiter
from app.integrations.assistant.answer import answer, evidence_view, llm_configured
from app.integrations.assistant.retrieval import retrieve
from app.models.enums import Permission
from app.models.user import User
from app.schemas.common import StrictInput
from app.services import audit_service

router = APIRouter(prefix="/assistant", tags=["assistant"])
Analyst = Annotated[User, Depends(require(Permission.USE_ASSISTANT))]


class Question(StrictInput):
    question: str = Field(min_length=3, max_length=1000)


@router.get("/status")
def status(_: Analyst) -> dict[str, Any]:
    s = get_settings()
    return {
        "llm_available": llm_configured(),
        "model": s.assistant_model if llm_configured() else None,
        "mode": "llm" if llm_configured() else "evidence_only",
        "can_execute_actions": False,
    }


@router.post("/ask")
async def ask(body: Question, db: DbSession, user: Analyst, meta: Meta) -> dict[str, Any]:
    rate_limiter.hit("assistant", f"user:{user.id}", get_settings().rate_limit_assistant_per_minute)

    def _run() -> dict[str, Any]:
        retrieval = retrieve(db, user, body.question)
        result = answer(retrieval)
        audit_service.record(
            db,
            "ASSISTANT_QUERY",
            actor=user,
            resource_type="assistant",
            meta=meta,
            details={
                "question": body.question[:300],
                "mode": result.mode,
                "citations": result.citations[:40],
                "evidence_items": len(retrieval.items),
            },
        )
        db.commit()
        return {
            "answer": result.answer,
            "mode": result.mode,
            "model": result.model,
            "citations": result.citations,
            "notes": result.notes,
            "evidence": evidence_view(retrieval),
        }

    return await run_in_threadpool(_run)
