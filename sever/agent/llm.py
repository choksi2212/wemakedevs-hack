"""LLM seam — provider-agnostic narration layer.

The agent's LOAD-BEARING moments (path queries, scoring, interdiction,
receipts) are deterministic Cypher + Python. The LLM narrates findings and
explains hops — provider-agnostic via env config:

    SEVER_LLM_BASE_URL   e.g. https://api.vultrinference.com/v1  (any OpenAI-compatible endpoint)
    SEVER_LLM_API_KEY    provider key
    SEVER_LLM_MODEL      e.g. glm-5.3

When env config is absent, the OfflineNarrator is used — the product runs fully offline.
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod


class LLM(ABC):
    @abstractmethod
    def complete(self, system: str, user: str) -> str: ...


class OfflineNarrator(LLM):
    """Offline narrator: no LLM garnish — ATT&CK templates carry the narration;
    deterministic by construction (the demo never depends on a model)."""

    name = "null"

    def complete(self, system: str, user: str) -> str:
        return ""


class ResilientLLM(LLM):
    """Degrade-to-offline wrapper around a live narrator.

    A wrong SEVER_LLM_API_KEY cannot be detected at construction time (the
    OpenAI client does no I/O until the first request), so the seam must
    degrade on the first complete() FAILURE too — not only on missing env.
    When the live narrator raises (auth rejected, provider down, timeout),
    narration permanently falls back to the OfflineNarrator: the LLM is
    garnish, so the agent loop never crashes on it (live-verified against a
    rejected key on glm-5.3, audit2/agent-loop).
    """

    def __init__(self, live: LLM, fallback: LLM | None = None) -> None:
        self._live = live
        self._fallback = fallback if fallback is not None else OfflineNarrator()
        self._degraded = False
        self.name = live.name

    @property
    def degraded(self) -> bool:
        return self._degraded

    def complete(self, system: str, user: str) -> str:
        if self._degraded:
            return self._fallback.complete(system, user)
        try:
            return self._live.complete(system, user)
        except Exception:
            # auth failures do not heal — latch the degradation so a dead
            # provider is never retried on the loop's hot path
            self._degraded = True
            self.name = "degraded->null"
            return self._fallback.complete(system, user)


class OpenAICompatLLM(LLM):
    """Any OpenAI-compatible endpoint (Vultr Inference, Ollama, Groq, ...)."""

    def __init__(self, base_url: str, api_key: str, model: str, timeout: float = 30.0) -> None:
        from openai import OpenAI

        self._client = OpenAI(base_url=base_url, api_key=api_key, timeout=timeout)
        self._model = model
        self.name = f"openai-compat:{model}"

    def complete(self, system: str, user: str) -> str:
        resp = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0.2,
            max_tokens=1024,  # reasoning models burn tokens before content (glm-5.3: ~150+)
        )
        return resp.choices[0].message.content or ""


def build_llm() -> LLM:
    """From env; falls back to the OfflineNarrator so the agent never hard-fails.

    Degrades on BOTH failure modes: missing env (offline product) AND a live
    narrator that fails at request time (dead key, provider down) — the
    ResilientLLM wrapper makes that degradation latch instead of raise.
    """
    base_url = os.environ.get("SEVER_LLM_BASE_URL")
    api_key = os.environ.get("SEVER_LLM_API_KEY")
    model = os.environ.get("SEVER_LLM_MODEL")
    if not (base_url and api_key and model):
        return OfflineNarrator()
    try:
        return ResilientLLM(OpenAICompatLLM(base_url, api_key, model))
    except Exception:
        return OfflineNarrator()
