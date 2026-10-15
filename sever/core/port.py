"""GraphPort — the one interface both graph backends implement.

- FalkorGraphPort: the live FalkorDB engine — THE substrate. There is no
  offline double: rule 3 of the hackathon (remove FalkorDB and the product
  breaks) is enforced by having exactly one implementation. Tests run against
  the real engine via docker compose; DB-free units (ETL, findings schema,
  tenant generation, LLM seam) run anywhere.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from sever.etl.ad_collectors import NormalizedGraph
from sever.core.jewels import DEFAULT_HOP_CAP


class GraphPort(ABC):
    """Backend-agnostic operations SEVER depends on."""

    @abstractmethod
    def load(self, graph: NormalizedGraph) -> None:
        """Bulk-load a normalized graph into this tenant."""

    @abstractmethod
    def node_count(self) -> int: ...

    @abstractmethod
    def edge_count(self) -> int: ...

    @abstractmethod
    def mark_owned(self, objectid: str) -> None:
        """Flag a principal as compromised (start of the attack path)."""

    @abstractmethod
    def owned_ids(self) -> list[str]:
        """Currently-owned principals."""

    @abstractmethod
    def crown_jewels(self) -> list[str]:
        """Crown-jewel target objectids (Domain Admins / Enterprise Admins)."""

    @abstractmethod
    def reachability(self, hop_cap: int = DEFAULT_HOP_CAP) -> int:
        """HEADLINE METRIC: count of owned principals with a path to any crown jewel."""

    @abstractmethod
    def paths_to_jewels(self, objectid: str, hop_cap: int = DEFAULT_HOP_CAP) -> list[list[tuple[str, str, str]]]:
        """Enumerate attack paths for one owned principal as hop lists:
        [(src, rel, dst), ...] — one list per path."""

    @abstractmethod
    def edge_frequency(self, hop_cap: int = DEFAULT_HOP_CAP) -> dict[tuple[str, str, str], int]:
        """Per-edge occurrence count across all owned->jewel paths (scoring input)."""

    @abstractmethod
    def add_edge(self, src: str, dst: str, rel: str, props: dict[str, Any] | None = None) -> bool:
        """Live mutation: grant a new edge (synthetic finding application).
        Returns True if a new edge was created."""

    @abstractmethod
    def cut(self, src: str, dst: str, rel: str) -> int:
        """THE INTERDICTION (human-gated): remove edge(s) src-[rel]->dst.
        Returns number of relationships removed (0 = edge absent = no-op)."""

    @abstractmethod
    def profile(self, query: str, params: dict[str, Any] | None = None) -> str:
        """PROFILE receipt for a query (audit trail for every claim)."""

    @abstractmethod
    def receipt(self) -> dict[str, Any]:
        """Snapshot dict: counts + owned + jewels — serialized into demo receipts."""
