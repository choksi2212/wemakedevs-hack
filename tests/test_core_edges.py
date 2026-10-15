"""DB-free edge cases: jewel detection (rename/case), self-edges, ranking,
verdicts. Engine-dependent semantics live in tests/test_live_semantics.py."""
from __future__ import annotations

from sever.core.falkor_port import FalkorGraphPort
from sever.core.jewels import GA_HOLDER_SUFFIX, is_crown_jewel
from sever.core.port import GraphPort
from sever.core.scoring import interdict, rank_cut_candidates
from sever.etl.ad_collectors import NormalizedGraph


class _StubGraph:
    """Minimal falkordb-py graph stand-in: records queries, canned results."""

    def __init__(self, results=None):
        from collections import deque

        self.calls: list[tuple[str, object]] = []
        self._results = deque(results or [])

    def query(self, query, params=None, timeout=None):
        self.calls.append((query, params))

        class _R:
            result_set = [self._results.popleft()] if self._results else []

        return _R()


class _StubPort(GraphPort):
    """Scriptable port for scoring receipts (no engine)."""

    def __init__(self, reach_seq=(1,), removed=1, jewels=("J",), owned=("O",)):
        self.reach_seq = list(reach_seq)
        self.removed = removed
        self._jewels = list(jewels)
        self._owned = list(owned)
        self.cut_calls: list[tuple[str, str, str]] = []

    def load(self, graph): ...
    def node_count(self) -> int: return 1
    def edge_count(self) -> int: return 1
    def mark_owned(self, objectid): ...
    def owned_ids(self) -> list[str]: return list(self._owned)
    def crown_jewels(self) -> list[str]: return list(self._jewels)
    def reachability(self, hop_cap: int = 12) -> int:
        return self.reach_seq.pop(0) if self.reach_seq else 0
    def paths_to_jewels(self, objectid, hop_cap: int = 12, ties: bool = False): return []
    def edge_frequency(self, hop_cap: int = 12): return {}
    def add_edge(self, src, dst, rel, props=None): return False
    def cut(self, src, dst, rel):
        self.cut_calls.append((src, dst, rel))
        return self.removed
    def profile(self, query, params=None): return ""
    def receipt(self): return {}


# ---- crown-jewel detection: rename-proof (SID) + case-proof (suffix) ----

def test_ad_jewel_is_sid_based_not_name_based():
    # a RENAMED Domain Admins group is still the jewel (RID -512 in the SID)
    assert is_crown_jewel("S-1-5-21-x-512", "Group")
    assert is_crown_jewel("S-1-5-21-x-519", "Group")  # Enterprise Admins
    # a decoy NAMED 'Domain Admins' with a different RID is NOT
    assert not is_crown_jewel("S-1-5-21-x-1106", "Group", "Domain Admins")
    # RID -512 on a non-Group label does not count
    assert not is_crown_jewel("S-1-5-21-x-512", "User")


def test_az_jewel_suffix_is_case_insensitive():
    assert is_crown_jewel("az-1", "AZUser", "097ef6c2-GlobalAdministrator")
    # case-varied suffixes must not slip past the detector
    assert is_crown_jewel("az-2", "AZUser", "jdoe-globaladministrator")
    assert is_crown_jewel("az-3", "AZUser", "jdoe-GLOBALADMINISTRATOR")
    assert is_crown_jewel("az-4", "AZUser", "jdoe-GlobalAdministrator")
    # non-holders and other labels are not jewels
    assert not is_crown_jewel("az-5", "AZUser", "plain_user")
    assert not is_crown_jewel("az-6", "AZUser", "")
    assert not is_crown_jewel("az-7", "AZGroup", "x-GlobalAdministrator")
    assert GA_HOLDER_SUFFIX == "-GlobalAdministrator"


# ---- self-referencing edges: rejected on both ingestion paths ----

def test_etl_rejects_self_edges():
    g = NormalizedGraph()
    g.add_node("A", "User"); g.add_node("B", "User")
    assert g.add_edge("A", "A", "MEMBER_OF") is False
    assert g.add_edge("", "B", "MEMBER_OF") is False
    assert g.add_edge("A", "", "MEMBER_OF") is False
    assert g.add_edge("A", "B", "MEMBER_OF") is True
    assert len(g.edges) == 1


def test_live_mutation_rejects_self_edges_without_querying():
    stub = _StubGraph()
    port = FalkorGraphPort(client=stub)
    # mirrors the ETL contract: a self-referencing grant is never valid
    assert port.add_edge("X", "X", "GENERIC_ALL") is False
    assert stub.calls == []  # rejected before any query is issued


# ---- ties-mode (algo.SPpaths) parsing + app-side guard, engine-free ----

class _FakeNode:
    def __init__(self, oid):
        self.properties = {"objectid": oid}
        self.id = oid


class _FakeEdge:
    def __init__(self, rel):
        self.relation = rel


class _FakePath:
    def __init__(self, oids, rels):
        self._nodes = [_FakeNode(o) for o in oids]
        self._edges = [_FakeEdge(r) for r in rels]

    def nodes(self):
        return self._nodes

    def edges(self):
        return self._edges


class _SPpathsGraph:
    """Serves crown-jewel queries, then canned SPpaths rows in order."""

    def __init__(self, sp_rows):
        self._sp_rows = list(sp_rows)

    def query(self, query, params=None, timeout=None):
        if "ENDS WITH '-512'" in query:
            rows = [["S-j"]]
        elif "toLower" in query:  # AZ jewels query
            rows = [["az-j"]]
        elif "algo.SPpaths" in query:
            rows = self._sp_rows.pop(0) if self._sp_rows else []
        else:
            rows = []
        result = type("_R", (), {"result_set": rows})()
        return result


def test_ties_mode_drops_structural_and_overlong_paths():
    # two jewels (S-j from the AD query, az-j from the AZ query): each
    # paths_to_jewels call consumes one canned SPpaths response per jewel
    valid = _FakePath(["o", "m", "j"], ["MEMBER_OF", "GENERIC_ALL"])
    structural = _FakePath(["o", "j"], ["CONTAINED_BY"])
    overlong_oids = ["o"] + ["n%d" % i for i in range(12)] + ["j"]  # 13 hops
    overlong = _FakePath(overlong_oids, ["MEMBER_OF"] * 13)
    valid_hops = [("o", "MEMBER_OF", "m"), ("m", "GENERIC_ALL", "j")]
    overlong_hops = [
        (overlong_oids[i], "MEMBER_OF", overlong_oids[i + 1]) for i in range(13)
    ]

    # jewel S-j yields [valid, structural]; jewel az-j yields [overlong]
    rows = [
        [[valid], [structural]],   # -> S-j pair
        [[overlong]],               # -> az-j pair
    ]

    port = FalkorGraphPort(client=_SPpathsGraph(rows))
    assert port.paths_to_jewels("o", 12, ties=True) == [valid_hops]

    port = FalkorGraphPort(client=_SPpathsGraph(list(rows)))
    # at cap 13 the 13-hop path is within the bound; CONTAINED_BY never passes
    assert port.paths_to_jewels("o", 13, ties=True) == [valid_hops, overlong_hops]


# ---- ranking + receipt verdicts ----

def test_rank_cut_candidates_empty_and_ties():
    assert rank_cut_candidates({}) == []
    freq = {
        ("B", "MEMBER_OF", "C"): 2,
        ("A", "MEMBER_OF", "Z"): 2,
        ("M", "DCSYNC", "J"): 5,
    }
    ranked = rank_cut_candidates(freq, limit=2)
    # highest coverage first; deterministic tuple-order tie-break behind it
    assert ranked[0]["src"] == "M" and ranked[0]["paths_on"] == 5
    assert ranked[1]["src"] == "A"
    assert len(rank_cut_candidates(freq, limit=1)) == 1


def test_interdict_verdicts():
    collapsed = interdict(_StubPort(reach_seq=[1, 0], removed=1), "O", "J", "R")
    assert collapsed["verdict"] == "collapsed"
    degraded = interdict(_StubPort(reach_seq=[1, 1], removed=1), "O", "J", "R")
    assert degraded["verdict"] == "degraded"
    no_effect = interdict(_StubPort(reach_seq=[1, 1], removed=0), "O", "J", "R")
    assert no_effect["verdict"] == "no_effect"
    assert no_effect["cut"]["relationships_removed"] == 0
