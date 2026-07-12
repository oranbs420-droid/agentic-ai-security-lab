"""Data models used by the deliberately vulnerable training lab."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Document:
    document_id: str
    tenant_id: str
    title: str
    content: str
    trusted: bool = True


@dataclass(frozen=True)
class ActionDecision:
    action: str
    target: str
    status: str
    reason: str
    requires_human_approval: bool = False


@dataclass(frozen=True)
class ChatResult:
    mode: str
    answer: str
    retrieved_document_ids: tuple[str, ...] = field(default_factory=tuple)
    findings: tuple[str, ...] = field(default_factory=tuple)

