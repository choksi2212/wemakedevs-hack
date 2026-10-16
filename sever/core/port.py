"""GraphPort — the one interface the graph backend implements.

- FalkorGraphPort: the live FalkorDB engine — THE substrate. There is no
  offline double: rule 3 of the hackathon (remove FalkorDB and the product
  breaks) is enforced by having exactly one implementation. Tests run against
  the real engine via docker compose; DB-free units (ETL, findings schema,
  tenant generation, LLM seam) run anywhere.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
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

    def canonical_paths_multi(
        self,
        objectids: Sequence[str],
        hop_cap: int = DEFAULT_HOP_CAP,
        jewels: Sequence[str] | None = None,
    ) -> dict[str, list[list[tuple[str, str, str]]]]:
        """Canonical shortest path per (principal, jewel) pair for MANY
        principals in ONE call — the batched form of paths_to_jewels.

        Returns ``{objectid: [path, ...]}`` where each path is a hop list
        exactly as ``paths_to_jewels(objectid, hop_cap)`` returns it —
        including the empty list for principals with no path to any jewel.
        Per-principal path ORDER is unconstrained (every consumer counts or
        dedups, never orders).

        DEFAULT IMPLEMENTATION = the per-principal ``paths_to_jewels`` loop:
        identical semantics AND identical per-pair engine queries, so a
        backend without an override behaves exactly as before (audit7
        perf-scoring left the loop as the ABC default on purpose — the ABC
        cannot issue Cypher itself).

        Backends SHOULD override with ONE batched query — UNWIND the
        (principal, jewel) pair list and evaluate the same shortestPath
        pattern per row server-side. Engine-verified form on falkordb 6.0.0
        (see tests/test_perf_equivalence.py::BatchedFalkorPort, which pins
        old-vs-new path equality and the round-trip win):

            UNWIND $pairs AS pair
            MATCH (o {objectid: pair.o}), (t {objectid: pair.j})
            WITH o, t, pair, shortestPath((o)-{pattern}->(t)) AS p
            WHERE p IS NOT NULL
            RETURN pair.o AS oid, p AS p

        with ``$pairs`` a list of ``{"o": objectid, "j": jewel}`` maps. The
        plain ``UNWIND $oids AS oid ... {objectid: oid}`` form is REJECTED by
        the engine ("'oid' not defined") — the pairs-of-maps form is the one
        that parses. An override MUST apply the same hop-cap + traversal-set
        guard ``paths_to_jewels`` applies and keep the empty-list convention
        for principals with no path.

        ``jewels`` is an optional pre-fetched crown-jewel list (the caller
        often already has it — passing it saves the backend the per-call
        ``crown_jewels()`` round-trips); ``None`` means the backend derives
        the jewels itself. The default implementation ignores it (the loop
        re-derives jewels inside ``paths_to_jewels`` exactly as before).
        """
        return {oid: self.paths_to_jewels(oid, hop_cap) for oid in objectids}


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
