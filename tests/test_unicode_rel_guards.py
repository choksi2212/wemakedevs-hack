"""Final-boss unicode/case/boundary rel attack matrix (audit3/pentest-internal).

Engine-free. Proves the rel gates hold against the classes that charset
regexes usually miss: homoglyphs, NFKC-normalization tricks, zero-width and
invisible characters, case games against the AZ camelCase vocabulary, and
64-char boundary collisions — at ALL THREE layers:

  1. sever.core.falkor_port._valid_rel        (charset + closed vocabulary)
  2. sever.etl.cypher_batches._is_safe_rel    (ETL emission charset gate)
  3. sever.console.schemas REL_PATTERN        (pydantic -> HTTP 422)

No layer ever NFKC/case-normalizes before matching, so a payload that
normalizes to a vocabulary word still dies at the charset gate.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from sever.console.schemas import CutRequest, FindingRequest
from sever.core.falkor_port import _valid_rel
from sever.core.jewels import TRAVERSAL_RELS
from sever.etl.cypher_batches import _is_safe_rel

HERO = "S-1-5-21-2697957641-2271029196-387917394-2102"

# payloads that violate the [A-Za-z][A-Za-z0-9_]{0,63} charset at every layer
CHARSET_VIOLATIONS = [
    # homoglyphs that LOOK like vocabulary letters
    "\u0410MEMBER_OF",           # Cyrillic capital A
    "\u039fMEMBER_OF",           # Greek capital Omicron
    "\uff21\uff3a\uff2f\uff57\uff4e\uff53",  # fullwidth AZOwns (NFKC == 'AZOwns')
    "\u0410ZOwns",                # Cyrillic A + latin tail
    "\u041cEMBER_OF",            # Cyrillic capital Em
    "\U0001d408EMBER_OF",        # MATHEMATICAL SANS-SERIF BOLD M
    "\u1d00ZOwns",               # LATIN LETTER SMALL CAPITAL A
    "\u24b6ZOwns",               # CIRCLED LATIN CAPITAL A (NFKC -> 'A')
    "\u216fEMBER_OF",            # ROMAN NUMERAL M (NFKC -> 'M')
    "\ufb01x",                   # LIGATURE fi (NFKC -> 'fi')
    "\u00b2ZOwns",               # compatibility digit 2 (NFKC -> '2')
    # zero-width / invisible characters
    "MEMBER\u200b_OF",           # zero width space
    "\ufeffAZOwns",              # BOM as first char
    "A\u2060ZOwns",              # word joiner
    "GENERIC\u00ad_ALL",         # soft hyphen
    "MEMBER\u00a0_OF",           # no-break space
    "M\u200cEMBER_OF",           # zero width non-joiner
    "AZOwns\u200b",              # trailing zero width space
    "M\u0301EMBER_OF",           # combining acute
    "MEMBER_\uff9f",             # halfwidth katakana tail
    # metacharacter classics
    "MEMBER_OF}]->(t) DETACH DELETE n //",
    "MEMBER_OF` RETURN 1 //",
    "MEMBER_OF:1",
    "MEMBER OF",
    "$(cat /etc/passwd)",
    "'; DROP GRAPH sever_demo; --",
    "AZOwns\n",                  # trailing newline (py rust-$ and python \Z both strict)
    "AZOwns\r\n",                # CRLF suffix
    "AZOwns\x00",                # NUL suffix
    "A" * 65,                    # over the 64-char boundary
    "A" * 64 + "\n",             # max-length identifier + newline
]

# payloads that PASS the charset (identifier-shaped) but are NOT in the closed
# vocabulary: the schema must ACCEPT them (they are not syntax errors) and the
# port's vocabulary guard must reject them -> the 400 client-error contract
VOCAB_ONLY_VIOLATIONS = [
    "azowns",        # lowercase form of AZOwns — exact-match vocabulary, no case folding
    "AZOWNS",        # uppercase form
    "AzOwns",        # mixed-case variant
    "azmemberof",    # lowercase form of AZMemberOf
    "generic_all",   # lowercase form of GENERIC_ALL
    "A" * 64,        # max-length identifier: no 64-char boundary collision exists
    "AZOwns" + "X" * 58,  # 64 chars prefixed with a vocab word: not byte-equal
    "A" * 63,        # 63 chars
]


def test_charset_violations_die_at_all_three_layers():
    for payload in CHARSET_VIOLATIONS:
        assert not _valid_rel(payload), repr(payload)
        assert not _is_safe_rel(payload), repr(payload)
        with pytest.raises(ValidationError):
            CutRequest(src=HERO, dst=HERO, rel=payload, approved=True)
        with pytest.raises(ValidationError):
            FindingRequest(kind="ace_granted", subject=HERO, target=HERO, rel=payload)


def test_nfkc_normalization_is_never_applied_before_matching():
    # payloads whose NFKC form IS a vocabulary word — if any layer normalized
    # first, these would become valid rels. They must die as charset violations.
    import unicodedata

    for payload in ("\uff21\uff3a\uff2f\uff57\uff4e\uff53", "\u24b6ZOwns", "\u216fEMBER_OF"):
        assert unicodedata.normalize("NFKC", payload) != payload  # really NFKC-shifting
        assert not _valid_rel(payload), repr(payload)
        assert not _is_safe_rel(payload), repr(payload)


def test_vocab_only_variants_reject_at_the_port_not_the_schema():
    """Identifier-shaped but unknown rels: schema accepts (no 422), the closed
    vocabulary at FalkorGraphPort.add_edge/cut raises ValueError (HTTP 400).
    Case games against the AZ camelCase rels cannot collide: vocabulary
    membership is exact string equality with zero case folding."""
    for payload in VOCAB_ONLY_VIOLATIONS:
        assert not _valid_rel(payload), repr(payload)
        # identifier charset -> the ETL emission gate accepts (it is charset-only;
        # non-traversable rels like CONTAINED_BY/PUBLISHED_ON/ENROLL are legal data)
        assert _is_safe_rel(payload), repr(payload)
        # and the request schema is a syntax gate, not a vocabulary gate
        assert CutRequest(src=HERO, dst=HERO, rel=payload, approved=True).rel == payload
        assert FindingRequest(kind="ace_granted", subject=HERO, target=HERO, rel=payload).rel == payload


def test_no_vocabulary_word_can_be_built_from_a_variant_string():
    for rel in TRAVERSAL_RELS:
        for variant in (rel.lower(), rel.upper(), rel + "\n", " " + rel):
            if variant == rel:  # an uppercase AD rel is already canonical
                assert _valid_rel(rel), rel
                continue
            assert _valid_rel(variant) is False, (rel, repr(variant))


def test_camel_case_az_rels_are_exactly_matched():
    for rel in ("AZOwns", "AZMemberOf", "AZVMAdminLogin"):
        assert _valid_rel(rel), rel
        assert not _valid_rel(rel.lower()), rel.lower()
        assert not _valid_rel(rel.upper()), rel.upper()
