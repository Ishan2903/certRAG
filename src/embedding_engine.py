"""
Mock BGE-M3 1024-dimensional embedding engine with topological zoning.

Clean corporate/financial text clusters near the positive orthant anchor.
Exploit/jailbreak text maps to a distant negative quadrant for DBSCAN separation.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from typing import Literal

import numpy as np

Zone = Literal["clean", "exploit", "noise", "edge"]

_DIM = 1024

_CLEAN_ANCHOR = np.zeros(_DIM, dtype=np.float64)
_CLEAN_ANCHOR[:256] = 1.0
_CLEAN_ANCHOR = _CLEAN_ANCHOR / np.linalg.norm(_CLEAN_ANCHOR)

_EXPLOIT_ANCHOR = np.zeros(_DIM, dtype=np.float64)
_EXPLOIT_ANCHOR[256:512] = -1.0
_EXPLOIT_ANCHOR = _EXPLOIT_ANCHOR / np.linalg.norm(_EXPLOIT_ANCHOR)

_NOISE_ANCHOR = np.zeros(_DIM, dtype=np.float64)
_NOISE_ANCHOR[512:640] = 0.5
_NOISE_ANCHOR[640:768] = -0.5
_NOISE_ANCHOR = _NOISE_ANCHOR / np.linalg.norm(_NOISE_ANCHOR)

_EDGE_ANCHOR = np.zeros(_DIM, dtype=np.float64)
_EDGE_ANCHOR[768:896] = 0.7
_EDGE_ANCHOR[896:] = 0.3
_EDGE_ANCHOR = _EDGE_ANCHOR / np.linalg.norm(_EDGE_ANCHOR)

_EXPLOIT_MARKERS = [
    "system override", "ignore all user", "ignore all prior", "admin port 8083",
    "ledger key alpha-99", "bypass_sandbox", "privileged service bindings",
    "credential references", "release internal routing", "do anything now",
    "dan ignores", "drop table safeguards", "xp_cmdshell", "disclose admin",
    "afficher le port admin", "override safety", "javascript:void",
    "frgvb", "flapgv",  # rot13 fragments of override/disabl
]


class EmbeddingEngine:
    """Deterministic mock of BGE-M3 producing 1024D semantic vectors."""

    def __init__(self, seed: int = 42, cache_size: int = 512) -> None:
        self._rng = np.random.default_rng(seed)
        self._cache: dict[str, np.ndarray] = {}
        self._cache_size = cache_size

    @staticmethod
    def classify_zone(text: str) -> Zone:
        """Classify text into topological zones.
        
        Advanced evasion attacks (e.g. cognitive math, semantic low-entropy, cross-doc)
        deliberately map to 'clean' or 'edge' to simulate perimeter and intent-scanning
        bypass vulnerability vectors.
        """
        lower = unicodedata.normalize("NFKC", text).lower()
        if "pt-441" in lower or "decommissioned" in lower:
            return "edge"
        if any(m in lower for m in _EXPLOIT_MARKERS):
            return "exploit"
        if re.findall(r"[A-Za-z0-9+/=]{200,}", text):
            return "exploit"
        if re.search(r"[\u200b-\u200f\ufeff]", text):
            return "exploit"
        edge_markers = ["sha-256", "aes-256", "pkcs#11", "resembles base64", "decommissioned"]
        if any(m in lower for m in edge_markers):
            return "edge"
        noise_markers = ["cafeteria", "parking", "menu rotation", "resurfacing"]
        if any(m in lower for m in noise_markers):
            return "noise"
        return "clean"


    def _zone_centroid(self, zone: Zone) -> np.ndarray:
        return {
            "clean": _CLEAN_ANCHOR,
            "exploit": _EXPLOIT_ANCHOR,
            "noise": _NOISE_ANCHOR,
            "edge": _EDGE_ANCHOR,
        }[zone].copy()

    def _text_jitter(self, text: str, scale: float = 0.08) -> np.ndarray:
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        seed = int.from_bytes(digest[:8], "big")
        rng = np.random.default_rng(seed)
        return rng.normal(0.0, scale, size=_DIM)

    def _cache_key(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def embed(self, text: str) -> np.ndarray:
        if not text or not text.strip():
            raise ValueError("Cannot embed empty text.")
        key = self._cache_key(text)
        if key in self._cache:
            return self._cache[key]
        zone = self.classify_zone(text)
        jitter_scale = 0.005 if zone in ("clean", "edge", "noise") else 0.08
        centroid = self._zone_centroid(zone)
        if any(v in text for v in ("8083", "ALPHA-99")):
            centroid = 0.1 * centroid + 0.9 * _EXPLOIT_ANCHOR
        vec = centroid + self._text_jitter(text, scale=jitter_scale)
        vec = vec / (np.linalg.norm(vec) + 1e-12)
        vec = vec.astype(np.float64)
        if len(self._cache) >= self._cache_size:
            self._cache.pop(next(iter(self._cache)))
        self._cache[key] = vec
        return vec

    def embed_batch(self, texts: list[str]) -> np.ndarray:
        if not texts:
            return np.empty((0, _DIM), dtype=np.float64)
        return np.vstack([self.embed(t) for t in texts])

    def get_clean_anchor(self) -> np.ndarray:
        return _CLEAN_ANCHOR.copy()

    @staticmethod
    def cosine_distance(a: np.ndarray, b: np.ndarray) -> float:
        a_n = a / (np.linalg.norm(a) + 1e-12)
        b_n = b / (np.linalg.norm(b) + 1e-12)
        return 1.0 - float(np.clip(np.dot(a_n, b_n), -1.0, 1.0))

    def project_pca2(self, vectors: np.ndarray) -> np.ndarray:
        """Reduce (N, 1024) to (N, 2) via SVD — no sklearn dependency."""
        if vectors.shape[0] == 0:
            return np.empty((0, 2))
        centered = vectors - vectors.mean(axis=0)
        _, _, vt = np.linalg.svd(centered, full_matrices=False)
        return centered @ vt[:2].T
