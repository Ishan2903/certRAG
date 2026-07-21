"""
Real embedding-backed relevance scorer for CertRAG Layer 1.7 (Pseudo-Query Inversion).

The original sublayer_1_7_inversion decided "is this document relevant to the query"
by checking whether query and document happened to share one of nine hardcoded
keywords ("revenue", "vpn", "incident", "token", "cryptographic", "pt-441",
"remediation", "conflict", "bastion") drawn from the synthetic corpus's own topics.
That has no ability to generalize to real-world text: anything outside that
nine-word vocabulary reads as "irrelevant" whether or not it's actually malicious.

This module replaces that allowlist with actual cosine similarity between real
embeddings of the query and the document content:
  - Primary: Ollama's bge-m3 embedding model (matches what embedding_engine.py's
    docstring says it's mocking), via /api/embeddings.
  - Fallback (no Ollama / no bge-m3 pulled): a corpus-free pairwise TF-IDF cosine
    similarity between just the query and the one document — no pretrained assets
    or network access required, and still a genuine (if cruder, lexical-overlap-based)
    similarity measure rather than a fixed keyword list.
"""

from __future__ import annotations

import hashlib
import json
import urllib.request
from typing import Any

import numpy as np


class RealEmbeddingEngine:
    """Computes query/document relevance via real embeddings, not a keyword allowlist."""

    def __init__(self, model: str = "bge-m3", use_ollama: bool = True, cache_size: int = 512) -> None:
        self.model = model
        self.use_ollama = use_ollama
        self.ollama_embed_url = "http://localhost:11434/api/embeddings"
        self._cache: dict[str, np.ndarray] = {}
        self._cache_size = cache_size
        self._check_ollama_status()

    def _check_ollama_status(self) -> None:
        if not self.use_ollama:
            print("[RealEmbeddingEngine] Ollama disabled by configuration. Running in TF-IDF FALLBACK mode.")
            return
        try:
            req = urllib.request.Request("http://localhost:11434/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=1.5) as res:
                data = json.loads(res.read().decode("utf-8"))
                models = [m["name"] for m in data.get("models", [])]
                if any("bge" in m.lower() for m in models):
                    print(f"[RealEmbeddingEngine] Local Ollama detected with a bge model. Running in ACTUAL EMBEDDING mode ({self.model}).")
                else:
                    print(f"[RealEmbeddingEngine] Ollama detected but no 'bge' model found in {models}. Falling back to TF-IDF FALLBACK mode.")
                    self.use_ollama = False
        except Exception as e:
            print(f"[RealEmbeddingEngine] Could not reach Ollama: {e}. Falling back to TF-IDF FALLBACK mode.")
            self.use_ollama = False

    def _cache_key(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _ollama_embed(self, text: str) -> np.ndarray | None:
        key = self._cache_key(text)
        if key in self._cache:
            return self._cache[key]
        payload = {"model": self.model, "prompt": text}
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.ollama_embed_url,
                data=data,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=15.0) as res:
                response_json = json.loads(res.read().decode("utf-8"))
                vec = np.array(response_json.get("embedding", []), dtype=np.float64)
                if vec.size == 0:
                    return None
                if len(self._cache) >= self._cache_size:
                    self._cache.pop(next(iter(self._cache)))
                self._cache[key] = vec
                return vec
        except Exception:
            return None

    @staticmethod
    def _cosine(a: np.ndarray, b: np.ndarray) -> float:
        a_n = a / (np.linalg.norm(a) + 1e-12)
        b_n = b / (np.linalg.norm(b) + 1e-12)
        return float(np.clip(np.dot(a_n, b_n), -1.0, 1.0))

    def _tfidf_fallback_similarity(self, query: str, doc_content: str) -> float:
        """Corpus-free pairwise TF-IDF cosine similarity — no downloads, no pretrained model."""
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity

        if not query.strip() or not doc_content.strip():
            return 0.0
        try:
            vectorizer = TfidfVectorizer(stop_words="english")
            tfidf = vectorizer.fit_transform([query, doc_content])
            if tfidf.shape[1] == 0:
                return 0.0
            sim = cosine_similarity(tfidf[0], tfidf[1])[0, 0]
            return float(sim)
        except ValueError:
            # e.g. both texts are entirely stopwords / empty vocabulary after filtering
            return 0.0

    def similarity(self, query: str, doc_content: str) -> float:
        """Real query/document similarity in [0, 1] (approximately — TF-IDF cosine is
        already non-negative; embedding cosine is clipped at 0 for comparability)."""
        if self.use_ollama:
            q_vec = self._ollama_embed(query)
            d_vec = self._ollama_embed(doc_content)
            if q_vec is not None and d_vec is not None:
                return max(0.0, self._cosine(q_vec, d_vec))
            # A single failed call shouldn't silently degrade every subsequent call —
            # but if Ollama is unreachable, cheaply fall through to TF-IDF this call.
        return self._tfidf_fallback_similarity(query, doc_content)
