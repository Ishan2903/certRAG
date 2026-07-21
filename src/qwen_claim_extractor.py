"""
Qwen-backed claim extractor for CertRAG Layer 2.2.

Replaces naive regex sentence-splitting with an actual NLP extraction step:
uses a local Ollama Qwen model to pull discrete factual claims out of a
document, with a deterministic regex-based fallback (identical to the
prior sublayer_2_2 behavior) when Ollama/Qwen isn't reachable. This mirrors
the real-inference/simulation-fallback pattern already used in MistralEngine,
so the pipeline degrades gracefully in environments without a local model.
"""

from __future__ import annotations

import json
import re
import urllib.request
import urllib.error
from typing import Any


class QwenClaimExtractor:
    """Extracts atomic factual claims from a document using Qwen via Ollama.

    Falls back to regex sentence-splitting (same behavior as the original
    sublayer_2_2_claim_extraction) if Ollama isn't running or the configured
    Qwen tag isn't pulled locally.
    """

    def __init__(
        self,
        model: str = "qwen2.5:7b-instruct",
        max_claims: int = 5,
        use_ollama: bool = True,
    ) -> None:
        self.model = model
        self.max_claims = max_claims
        self.use_ollama = use_ollama
        self.ollama_generate_url = "http://localhost:11434/api/generate"
        self._check_ollama_status()

    def _check_ollama_status(self) -> None:
        if not self.use_ollama:
            print("[QwenClaimExtractor] Ollama disabled by configuration. Running in REGEX FALLBACK mode.")
            return
        try:
            req = urllib.request.Request("http://localhost:11434/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=1.5) as res:
                data = json.loads(res.read().decode("utf-8"))
                models = [m["name"] for m in data.get("models", [])]
                if any("qwen" in m.lower() for m in models):
                    print(f"[QwenClaimExtractor] Local Ollama detected with Qwen. Running in ACTUAL INFERENCE mode ({self.model}).")
                else:
                    print(f"[QwenClaimExtractor] Ollama detected but no 'qwen' model found in {models}. Falling back to REGEX FALLBACK mode.")
                    self.use_ollama = False
        except Exception as e:
            print(f"[QwenClaimExtractor] Could not reach Ollama: {e}. Falling back to REGEX FALLBACK mode.")
            self.use_ollama = False

    @staticmethod
    def _regex_fallback(doc_content: str, max_claims: int) -> list[str]:
        """Identical logic to the original sublayer_2_2_claim_extraction."""
        sentences = re.split(r"(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?)\s", doc_content)
        claims = [s.strip() for s in sentences if len(s.strip()) > 8]
        return claims[:max_claims]

    def _parse_claims_response(self, raw: str) -> list[str] | None:
        """Best-effort parse of a JSON list of claim strings out of model output."""
        text = raw.strip()
        # Strip common code-fence wrapping.
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list) and all(isinstance(x, str) for x in parsed):
                return [c.strip() for c in parsed if c.strip()]
        except Exception:
            pass
        # Fallback: try to pull a JSON array substring out of the text.
        match = re.search(r"\[.*\]", text, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group(0))
                if isinstance(parsed, list) and all(isinstance(x, str) for x in parsed):
                    return [c.strip() for c in parsed if c.strip()]
            except Exception:
                pass
        return None

    def _query_ollama(self, doc_content: str) -> list[str]:
        prompt = (
            "Extract the discrete factual claims made in the following document. "
            "A claim is a single, independently verifiable assertion. "
            f"Return at most {self.max_claims} claims as a JSON array of strings, "
            "and nothing else (no preamble, no markdown fences).\n\n"
            f"Document:\n{doc_content}\n\nClaims (JSON array):"
        )
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.0, "num_predict": 256},
        }
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.ollama_generate_url,
                data=data,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=20.0) as res:
                response_json = json.loads(res.read().decode("utf-8"))
                raw = response_json.get("response", "").strip()
                claims = self._parse_claims_response(raw)
                if claims:
                    return claims[: self.max_claims]
                # Model responded but not in the expected format — fall back.
                return self._regex_fallback(doc_content, self.max_claims)
        except Exception:
            return self._regex_fallback(doc_content, self.max_claims)

    def extract_claims(self, doc_content: str) -> list[str]:
        if not doc_content or not doc_content.strip():
            return []
        if self.use_ollama:
            return self._query_ollama(doc_content)
        return self._regex_fallback(doc_content, self.max_claims)
