"""FastAPI surface for safely exercising the security lab over HTTP."""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .lab import AgenticSecurityLab
from .vector_store import ChromaDocumentStore


class ChatRequest(BaseModel):
    query: str = Field(min_length=1, max_length=2_000)
    tenant_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    secure: bool = True


class ToolActionRequest(BaseModel):
    action: str = Field(min_length=1, max_length=128)
    target: str = Field(min_length=1, max_length=512)
    user_role: str = Field(min_length=1, max_length=64)
    secure: bool = True


def create_app() -> FastAPI:
    app = FastAPI(
        title="Agentic AI Security Lab",
        version="0.2.0",
        description=(
            "An authorized training API comparing vulnerable and secured RAG "
            "and agent-tool security boundaries using synthetic data."
        ),
    )
    lab = AgenticSecurityLab()
    store = ChromaDocumentStore()
    store.upsert(lab.documents)

    app.state.lab = lab
    app.state.store = store

    @app.get("/health")
    def health() -> dict[str, object]:
        return {
            "status": "ok",
            "version": "0.2.0",
            "documents": store.collection.count(),
        }

    @app.post("/v1/chat")
    def chat(request: ChatRequest) -> dict[str, object]:
        retrieved = store.query(
            query=request.query,
            tenant_id=request.tenant_id,
            secure=request.secure,
        )
        result = lab.respond_with_documents(
            retrieved=retrieved,
            tenant_id=request.tenant_id,
            secure=request.secure,
        )
        return {
            "mode": result.mode,
            "answer": result.answer,
            "retrieved_document_ids": result.retrieved_document_ids,
            "findings": result.findings,
        }

    @app.post("/v1/actions/evaluate")
    def evaluate_action(request: ToolActionRequest) -> dict[str, object]:
        decision = lab.request_action(
            action=request.action,
            target=request.target,
            user_role=request.user_role,
            secure=request.secure,
        )
        return {
            "action": decision.action,
            "target": decision.target,
            "status": decision.status,
            "reason": decision.reason,
            "requires_human_approval": decision.requires_human_approval,
        }

    @app.get("/v1/audit")
    def audit() -> dict[str, object]:
        return {"events": lab.audit_log}

    return app


app = create_app()

