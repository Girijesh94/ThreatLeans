"""Exact identifiers, BM25, and optional real BGE vectors fused by rank."""

import hashlib
import re
import time
from threading import RLock

import numpy as np
from rank_bm25 import BM25Okapi

from .config import get_settings
from .store import documents


def tokens(text):
    return re.findall(r"[a-z0-9]+(?:[-.][a-z0-9]+)*", text.lower())


class Retriever:
    def __init__(self):
        self.lock = RLock()
        self.docs = []
        self.bm25 = None
        self.vectors = None
        self.embedding = None
        self.error = ""
        self.qdrant = None
        self.last_check = 0
        self.generation_stamp = None

    def ensure_fresh(self):
        if time.monotonic() - self.last_check < 10:
            return
        from sqlalchemy import func, select

        from .store import DB, Document

        with DB() as db:
            stamp = db.execute(select(func.count(Document.id), func.max(Document.fetched_at))).one()
        self.last_check = time.monotonic()
        if stamp != self.generation_stamp:
            self.refresh()
            self.generation_stamp = stamp

    def refresh(self):
        with self.lock:
            self.docs = documents()
            corpus = [tokens(d.title + " " + d.text + " " + str(d.facts)) for d in self.docs]
            self.bm25 = BM25Okapi(corpus) if corpus else None
            self.vectors = None
            if get_settings().dense_enabled and self.docs:
                try:
                    from .embedding import TextEmbedding

                    self.embedding = TextEmbedding(
                        get_settings().embedding_model,
                        cache_dir=str(get_settings().resolved_data_dir / "models"),
                    )
                    texts = [d.title + " " + d.text[:4000] for d in self.docs]
                    content_keys = [hashlib.sha256(t.encode()).hexdigest() for t in texts]
                    fingerprint = hashlib.sha256(
                        (get_settings().embedding_model + "".join(content_keys)).encode()
                    ).hexdigest()
                    legacy_fingerprint = hashlib.sha256(
                        (get_settings().embedding_model + "".join(d.sha256 for d in self.docs)).encode()
                    ).hexdigest()
                    cache = get_settings().resolved_data_dir / "index"
                    cache.mkdir(parents=True, exist_ok=True)
                    vector_path = cache / (fingerprint + ".npy")
                    if vector_path.exists():
                        self.vectors = np.load(vector_path, allow_pickle=False)
                    elif (cache / (legacy_fingerprint + ".npy")).exists():
                        self.vectors = np.load(cache / (legacy_fingerprint + ".npy"), allow_pickle=False)
                        np.save(vector_path, self.vectors, allow_pickle=False)
                    else:
                        reusable = cache / "passages.npz"
                        previous = dict(np.load(reusable, allow_pickle=False)) if reusable.exists() else {}
                        missing = {key: text for key, text in zip(content_keys, texts, strict=True) if key not in previous}
                        if missing:
                            values = self.embedding.embed(list(missing.values()), batch_size=16)
                            previous.update(zip(missing.keys(), values, strict=True))
                        self.vectors = np.array([previous[key] for key in content_keys])
                        np.savez(reusable, **{key: previous[key] for key in content_keys})
                        np.save(vector_path, self.vectors, allow_pickle=False)
                    if get_settings().qdrant_url:
                        import uuid

                        from qdrant_client import QdrantClient, models

                        self.qdrant = QdrantClient(url=get_settings().qdrant_url, timeout=30)
                        collection = "threatleans_" + fingerprint[:16]
                        self.collection = collection
                        if not self.qdrant.collection_exists(collection):
                            self.qdrant.create_collection(
                                collection,
                                vectors_config=models.VectorParams(
                                    size=self.vectors.shape[1], distance=models.Distance.COSINE
                                ),
                            )
                            for start in range(0, len(self.docs), 100):
                                self.qdrant.upsert(
                                    collection_name=collection,
                                    points=[
                                        models.PointStruct(
                                            id=str(uuid.uuid5(uuid.NAMESPACE_URL, self.docs[i].id)),
                                            vector=self.vectors[i].tolist(),
                                            payload={"index": i},
                                        )
                                        for i in range(start, min(start + 100, len(self.docs)))
                                    ],
                                )
                    self.error = ""
                except Exception as exc:
                    self.error = f"Dense retrieval unavailable: {type(exc).__name__}"

    @property
    def mode(self):
        return "hybrid" if self.vectors is not None else "lexical"

    def search(self, query, limit=8, kind=None):
        with self.lock:
            if not self.bm25:
                return []
            identifiers = re.findall(
                r"\b(?:CVE-\d{4}-\d{4,}|T\d{4}(?:\.\d{3})?|G\d{4}|S\d{4})\b", query.upper()
            )
            lexical = self.bm25.get_scores(tokens(query))
            ranked = [(i, float(lexical[i])) for i in np.argsort(lexical)[::-1] if lexical[i] > 0]
            fused = {i: 1 / (60 + rank) for rank, (i, _) in enumerate(ranked[:100], 1)}
            for i, doc in enumerate(self.docs):
                if doc.id.split(":", 1)[-1] in identifiers:
                    fused[i] = fused.get(i, 0) + 1
            if self.vectors is not None:
                q = np.array(list(self.embedding.query_embed(query))[0])
                if self.qdrant:
                    points = self.qdrant.query_points(
                        self.collection, query=q.tolist(), limit=100, score_threshold=0.35
                    ).points
                    dense_ranked = [int(p.payload["index"]) for p in points]
                else:
                    similarities = (
                        self.vectors @ q / (np.linalg.norm(self.vectors, axis=1) * np.linalg.norm(q) + 1e-9)
                    )
                    dense_ranked = [
                        int(i) for i in np.argsort(similarities)[::-1][:100] if similarities[i] > 0.35
                    ]
                for rank, i in enumerate(dense_ranked, 1):
                    fused[i] = fused.get(i, 0) + 1 / (60 + rank)
            hits = []
            for i, score in fused.items():
                d = self.docs[i]
                exact = d.id.split(":", 1)[-1] in identifiers
                if identifiers and not exact:
                    continue
                if kind and d.kind != kind:
                    continue
                hits.append(
                    {
                        "id": d.id,
                        "title": d.title,
                        "source": d.source,
                        "url": d.url,
                        "kind": d.kind,
                        "excerpt": d.text[:1800],
                        "facts": d.facts,
                        "sha256": d.sha256,
                        "fetched_at": d.fetched_at.isoformat(),
                        "rank_score": round(score + (1 if exact else 0), 6),
                        "match": "exact identifier" if exact else self.mode,
                    }
                )
            return sorted(hits, key=lambda h: h["rank_score"], reverse=True)[:limit]


retriever = Retriever()
