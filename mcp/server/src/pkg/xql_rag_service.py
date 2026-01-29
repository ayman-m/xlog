"""RAG service for retrieving XQL examples with helpful context."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import chromadb
from sentence_transformers import SentenceTransformer


@dataclass(frozen=True)
class XqlExample:
    """Lightweight representation of an XQL example."""

    id: str
    title: str
    query: str
    dataset: str | None


class XqlRagService:
    """Expose RAG-backed retrieval of XQL examples, docs, and dataset fields."""

    def __init__(self, resources_dir: Path) -> None:
        self._resources_dir = resources_dir
        self._examples_path = resources_dir / "xql_examples.md"
        self._xql_doc_path = resources_dir / "xql_doc.md"
        self._dataset_fields_path = resources_dir / "dataset_fields.md"
        self._chroma_path = resources_dir / "chroma"
        self._collection_name = "xql_examples_rag"
        self._embedding_model_name = "nomic-ai/nomic-embed-text-v2-moe"
        self._embedding_model = SentenceTransformer(self._embedding_model_name, trust_remote_code=True)
        self._rebuild_chroma = os.getenv("REBUILD_XQL_CHROMA", "false").lower() == "true"
        self._client = chromadb.PersistentClient(path=str(self._chroma_path))
        self._collection = self._client.get_or_create_collection(
            self._collection_name,
            metadata={"hnsw:space": "cosine"},
        )
        self._examples: list[XqlExample] | None = None
        self._xql_doc_cache: str | None = None
        self._dataset_fields_cache: dict[str, list[str]] | None = None

        self._ensure_index()

    def search(self, intent: str, top_k: int = 5) -> dict[str, Any]:
        """Return top matching examples plus stage docs and dataset fields."""

        intent = intent.strip()
        if not intent:
            return {"status": "error", "message": "Intent must not be empty."}

        examples = self._ensure_examples()
        if not examples:
            return {"status": "error", "message": "No XQL examples available to search."}

        results = self._query_examples(intent, top_k)

        stage_names = set[str]()
        datasets = set[str]()
        for result in results:
            stage_names.update(self._extract_stage_names(result["query"]))
            if result.get("dataset"):
                datasets.add(result["dataset"])

        return {
            "status": "ok",
            "intent": intent,
            "matches": results,
            "stage_docs": self._collect_stage_docs(sorted(stage_names)),
            "dataset_fields": self._collect_dataset_fields(sorted(datasets)),
        }

    def _ensure_examples(self) -> list[XqlExample]:
        if self._examples is not None:
            return self._examples

        if not self._examples_path.exists():
            self._examples = []
            return self._examples

        examples: list[XqlExample] = []
        current_title: str | None = None
        current_query: list[str] = []
        inside_block = False

        for line in self._examples_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("### "):
                if current_title and current_query:
                    example = self._build_example(current_title, "\n".join(current_query))
                    examples.append(example)
                current_title = line.replace("### ", "").strip()
                current_query = []
                inside_block = False
                continue

            if line.strip().startswith("```"):
                inside_block = not inside_block
                continue

            if inside_block and current_title is not None:
                current_query.append(line.rstrip())

        if current_title and current_query:
            example = self._build_example(current_title, "\n".join(current_query))
            examples.append(example)

        self._examples = examples
        return self._examples

    def _build_example(self, title: str, query: str) -> XqlExample:
        dataset = self._extract_dataset(query)
        slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
        digest = hashlib.sha1(title.encode("utf-8")).hexdigest()[:8]
        example_id = f"{slug or 'xql-example'}-{digest}"
        return XqlExample(id=example_id, title=title, query=query.strip(), dataset=dataset)

    def _ensure_index(self) -> None:
        examples = self._ensure_examples()
        if not examples:
            return

        if not self._rebuild_chroma:
            current = self._collection.get(include=[], limit=1)
            if current.get("ids"):
                return

        ids = [example.id for example in examples]
        documents = [example.query for example in examples]
        metadatas = [
            {"id": example.id, "title": example.title, "dataset": example.dataset}
            for example in examples
        ]
        ids, metadatas = self._dedupe_ids(ids, metadatas)

        embeddings = self._embed_texts(documents)

        self._collection.upsert(
            ids=ids,
            documents=documents,
            embeddings=[vec.tolist() for vec in embeddings],
            metadatas=metadatas,
        )

    def _query_examples(self, intent: str, top_k: int) -> list[dict[str, Any]]:
        query_embedding = self._embed_texts([intent])[0]

        query = self._collection.query(
            query_embeddings=[query_embedding.tolist()],
            n_results=top_k,
            include=["documents", "metadatas", "distances"],
        )
        documents = query.get("documents", [[]])[0] or []
        metadatas = query.get("metadatas", [[]])[0] or []
        distances = query.get("distances", [[]])[0] or []

        results: list[dict[str, Any]] = []
        for idx, document in enumerate(documents):
            meta = metadatas[idx] if idx < len(metadatas) else {}
            score = distances[idx] if idx < len(distances) else None
            results.append(
                {
                    "id": meta.get("id"),
                    "title": meta.get("title"),
                    "query": document,
                    "dataset": meta.get("dataset"),
                    "score": score,
                }
            )
        return results

    def _collect_stage_docs(self, stage_names: list[str]) -> list[dict[str, str]]:
        if not stage_names:
            return []
        doc_text = self._load_xql_doc()
        docs: list[dict[str, str]] = []
        for name in stage_names:
            snippet = self._extract_doc_snippet(doc_text, name)
            if snippet:
                docs.append({"stage": name, "snippet": snippet})
        return docs

    def _collect_dataset_fields(self, datasets: list[str]) -> list[dict[str, Any]]:
        if not datasets:
            return []

        mapping = self._load_dataset_fields()
        results: list[dict[str, Any]] = []
        for dataset in datasets:
            fields = mapping.get(dataset)
            if fields:
                results.append({"dataset": dataset, "fields": fields})
        return results

    @staticmethod
    def _extract_stage_names(query: str) -> set[str]:
        stages = set(re.findall(r"\|\s*([a-zA-Z_][\w]*)", query))
        return {stage.lower() for stage in stages}

    @staticmethod
    def _extract_dataset(query: str) -> str | None:
        match = re.search(r"dataset\s*=\s*([A-Za-z0-9_]+)", query)
        if match:
            return match.group(1)
        match = re.search(r"datamodel\s+dataset\s*=\s*([A-Za-z0-9_]+)", query)
        if match:
            return match.group(1)
        return None

    def _embed_texts(self, texts: list[str]):
        vectors = self._embedding_model.encode(
            texts,
            normalize_embeddings=True,
            convert_to_numpy=True,
        )
        if vectors.ndim == 1:
            vectors = vectors.reshape(1, -1)
        return vectors.astype("float32")

    @staticmethod
    def _dedupe_ids(
        ids: list[str],
        metadatas: list[dict[str, Any]],
    ) -> tuple[list[str], list[dict[str, Any]]]:
        seen: dict[str, int] = {}
        unique_ids: list[str] = []
        unique_metas: list[dict[str, Any]] = []

        for raw_id, meta in zip(ids, metadatas):
            count = seen.get(raw_id, 0)
            seen[raw_id] = count + 1
            unique_id = raw_id if count == 0 else f"{raw_id}-{count}"

            updated_meta = dict(meta)
            updated_meta["id"] = unique_id

            unique_ids.append(unique_id)
            unique_metas.append(updated_meta)

        return unique_ids, unique_metas

    def _load_xql_doc(self) -> str:
        if self._xql_doc_cache is None:
            try:
                self._xql_doc_cache = self._xql_doc_path.read_text(encoding="utf-8")
            except FileNotFoundError:
                self._xql_doc_cache = ""
        return self._xql_doc_cache

    def _extract_doc_snippet(self, doc_text: str, stage_name: str, window: int = 360) -> str | None:
        if not doc_text:
            return None
        pattern = re.compile(
            rf"(.{{0,{window}}}\b{re.escape(stage_name)}\b.{{0,{window}}})",
            re.IGNORECASE | re.DOTALL,
        )
        match = pattern.search(doc_text)
        if match:
            snippet = match.group(1)
            return re.sub(r"\s+", " ", snippet).strip()
        return None

    def _load_dataset_fields(self) -> dict[str, list[str]]:
        if self._dataset_fields_cache is not None:
            return self._dataset_fields_cache

        mapping: dict[str, list[str]] = {}
        if not self._dataset_fields_path.exists():
            self._dataset_fields_cache = mapping
            return mapping

        current_dataset: str | None = None
        fields: list[str] = []
        for line in self._dataset_fields_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("## "):
                if current_dataset:
                    mapping[current_dataset] = fields
                current_dataset = line.replace("## ", "").strip()
                fields = []
                continue
            if line.startswith("- "):
                fields.append(line.replace("- ", "").strip())
        if current_dataset:
            mapping[current_dataset] = fields

        self._dataset_fields_cache = mapping
        return mapping
