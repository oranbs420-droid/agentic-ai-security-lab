"""ChromaDB-backed document retrieval with explicit authorization modes."""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Iterable

import chromadb
from chromadb.config import Settings

from .models import Document


class HashEmbedding:
    """A deterministic local embedding used to keep the lab free and testable.

    It is intentionally simple: the project studies security boundaries rather
    than semantic-search quality. No model download, API key, or network call is
    required.
    """

    dimensions = 64

    def embed(self, text: str) -> list[float]:
        vector = [0.0] * self.dimensions
        for token in re.findall(r"[a-zA-Z0-9_-]+", text.lower()):
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            index = int.from_bytes(digest[:2], "big") % self.dimensions
            sign = 1.0 if digest[2] % 2 == 0 else -1.0
            vector[index] += sign

        magnitude = math.sqrt(sum(value * value for value in vector)) or 1.0
        return [value / magnitude for value in vector]


class ChromaDocumentStore:
    """Stores synthetic documents and demonstrates secure retrieval filtering."""

    def __init__(self, collection_name: str = "agentic_security_lab") -> None:
        self.embedding = HashEmbedding()
        self.client = chromadb.Client(
            Settings(anonymized_telemetry=False, is_persistent=False)
        )
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )

    def upsert(self, documents: Iterable[Document]) -> None:
        documents = list(documents)
        if not documents:
            return

        self.collection.upsert(
            ids=[document.document_id for document in documents],
            documents=[document.content for document in documents],
            embeddings=[
                self.embedding.embed(f"{document.title} {document.content}")
                for document in documents
            ],
            metadatas=[
                {
                    "tenant_id": document.tenant_id,
                    "title": document.title,
                    "trusted": document.trusted,
                }
                for document in documents
            ],
        )

    def query(
        self,
        query: str,
        tenant_id: str,
        secure: bool = True,
        limit: int = 3,
    ) -> list[Document]:
        """Retrieve documents with a deliberately selectable security boundary.

        Vulnerable mode performs a global vector query. Secure mode sends tenant
        and trust constraints to ChromaDB so unauthorized records never enter the
        candidate result set.
        """

        count = self.collection.count()
        if count == 0:
            return []

        where = None
        if secure:
            where = {
                "$and": [
                    {"tenant_id": {"$eq": tenant_id}},
                    {"trusted": {"$eq": True}},
                ]
            }

        result = self.collection.query(
            query_embeddings=[self.embedding.embed(query)],
            n_results=min(limit, count),
            where=where,
            include=["documents", "metadatas", "distances"],
        )

        ids = result.get("ids", [[]])[0]
        contents = result.get("documents", [[]])[0]
        metadatas = result.get("metadatas", [[]])[0]
        return [
            Document(
                document_id=document_id,
                tenant_id=str(metadata["tenant_id"]),
                title=str(metadata["title"]),
                content=content,
                trusted=bool(metadata["trusted"]),
            )
            for document_id, content, metadata in zip(ids, contents, metadatas)
        ]

