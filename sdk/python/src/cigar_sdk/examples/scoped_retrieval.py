"""Explicit offline retrieval recipe for the existing semantic_candidates port.

Build this snapshot from host-owned records and a host-owned scope, before running
any ranker. Rebuild after source or policy changes. A snapshot hash identifies the
ranker's inputs; it is not a CIGAR authorization grant or an integrity signature.
Callbacks are caller-trusted code and must supply their own execution/resource
boundary. This example never imports a model, discovers credentials or calls a
provider. Its tokenizer/score are independent of CIGAR's exact budget tokenizer.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

_MAX_DOCUMENTS = 100_000
_MAX_DOCUMENT_BYTES = 1024 * 1024
_MAX_CORPUS_BYTES = 64 * 1024 * 1024
_MAX_QUERY_BYTES = 16 * 1024
_MAX_CANDIDATES = 256
_TOKENIZER = "nfc-casefold-unicode-alnum.v1"
_RANKER = "bm25-k1-1.2-b-0.75.v1"
_TERMS = re.compile(r"[^\W_]+", re.UNICODE)


@dataclass(frozen=True, slots=True, repr=False)
class RetrievalDocument:
    """An explicit copy of host-admitted text and its current source revision."""

    id: str
    source: str
    source_revision: str
    text: str


def _text_bytes(value: str, bound: int, *, allow_empty: bool = False) -> bytes:
    if not isinstance(value, str) or (not value and not allow_empty):
        raise ValueError("invalid retrieval text")
    if len(value) > bound:
        raise ValueError("retrieval input exceeds limit")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise ValueError("invalid retrieval text") from None
    if len(encoded) > bound:
        raise ValueError("retrieval input exceeds limit")
    return encoded


def _limit(value: int) -> None:
    if type(value) is not int or not 1 <= value <= _MAX_CANDIDATES:
        raise ValueError("invalid candidate limit")


def _terms(text: str) -> list[str]:
    return _TERMS.findall(unicodedata.normalize("NFC", text).casefold())


@dataclass(frozen=True, slots=True, repr=False, init=False)
class ScopedCorpus:
    """A bounded snapshot containing only explicitly authorized records.

    The constructor never enumerates or reads unselected mapping values. All
    corpus statistics and callback input derive from the resulting snapshot.
    This does not isolate hostile callbacks inside the same Python process.
    """

    records: tuple[RetrievalDocument, ...]
    identity: str

    def __init__(
        self,
        records: Mapping[str, RetrievalDocument],
        *,
        allowed: Sequence[str],
        policy_revision: str,
    ) -> None:
        _text_bytes(policy_revision, 4096)
        if isinstance(allowed, str | bytes) or len(allowed) > _MAX_DOCUMENTS:
            raise ValueError("invalid retrieval scope")
        selected: list[RetrievalDocument] = []
        seen: set[str] = set()
        total = 0
        for node_id in allowed:
            _text_bytes(node_id, 4096)
            if node_id in seen:
                raise ValueError("duplicate retrieval scope ID")
            seen.add(node_id)
            record = records.get(node_id)
            if type(record) is not RetrievalDocument or record.id != node_id:
                raise ValueError("retrieval scope record unavailable")
            fields = [
                _text_bytes(record.id, 4096),
                _text_bytes(record.source, 4096),
                _text_bytes(record.source_revision, 4096),
                _text_bytes(record.text, _MAX_DOCUMENT_BYTES, allow_empty=True),
            ]
            total += sum(len(field) for field in fields)
            if total > _MAX_CORPUS_BYTES:
                raise ValueError("retrieval corpus exceeds limit")
            selected.append(record)
        selected.sort(key=lambda record: record.id.encode("utf-8"))
        # Length-prefixed fields avoid delimiter ambiguity without allocating a
        # second complete corpus serialization. This is an example-local identity.
        digest = hashlib.sha256()
        for value in ["cigar.scoped-retrieval.v1", policy_revision, _TOKENIZER, _RANKER]:
            encoded = value.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        digest.update(len(selected).to_bytes(8, "big"))
        for record in selected:
            for value in (record.id, record.source, record.source_revision, record.text):
                encoded = value.encode("utf-8")
                digest.update(len(encoded).to_bytes(8, "big"))
                digest.update(encoded)
        object.__setattr__(self, "records", tuple(selected))
        object.__setattr__(self, "identity", digest.hexdigest())

    def checked_candidates(self, candidates: Sequence[str], *, limit: int = 256) -> list[str]:
        """Validate explicit external ranks without silently truncating or filtering them."""
        _limit(limit)
        if isinstance(candidates, str | bytes) or len(candidates) > limit:
            raise ValueError("invalid ranked candidates")
        permitted = {record.id for record in self.records}
        output: list[str] = []
        seen: set[str] = set()
        for node_id in candidates:
            _text_bytes(node_id, 4096)
            if node_id not in permitted or node_id in seen:
                raise ValueError("invalid ranked candidates")
            seen.add(node_id)
            output.append(node_id)
        return output

    def rank_with(
        self,
        query: str,
        ranker: Callable[[str, tuple[RetrievalDocument, ...], int], Sequence[str]],
        *,
        limit: int = 256,
    ) -> list[str]:
        """Call an explicitly provided ranker with scoped text, then validate its IDs.

        The caller owns callback selection, timeouts and any external disclosures.
        Never reuse its outputs after this snapshot/policy changes. Cache keys
        also need the exact query, limit and external ranker/model identity.
        """
        _limit(limit)
        _text_bytes(query, _MAX_QUERY_BYTES, allow_empty=True)
        return self.checked_candidates(ranker(query, self.records, limit), limit=limit)

    def bm25(self, query: str, *, limit: int = 256) -> list[str]:
        """One-shot reference ranking. Reuse ScopedBM25 for repeated queries."""
        return ScopedBM25(self).rank(query, limit=limit)


@dataclass(frozen=True, slots=True, repr=False, init=False)
class ScopedBM25:
    """An explicit reusable index tied to one immutable scoped input snapshot."""

    corpus: ScopedCorpus
    _postings: Mapping[str, tuple[tuple[int, int], ...]]
    _lengths: tuple[int, ...]
    _average: float

    def __init__(self, corpus: ScopedCorpus) -> None:
        postings: dict[str, list[tuple[int, int]]] = {}
        lengths: list[int] = []
        for index, record in enumerate(corpus.records):
            counts = Counter(_terms(record.text))
            lengths.append(sum(counts.values()))
            for term, frequency in counts.items():
                postings.setdefault(term, []).append((index, frequency))
        object.__setattr__(self, "corpus", corpus)
        object.__setattr__(
            self, "_postings", MappingProxyType({term: tuple(items) for term, items in postings.items()})
        )
        object.__setattr__(self, "_lengths", tuple(lengths))
        object.__setattr__(self, "_average", sum(lengths) / len(lengths) if lengths else 0.0)

    def rank(self, query: str, *, limit: int = 256) -> list[str]:
        """Deterministic reference ranks; no claim of semantic or task-level superiority.

        Unique query terms, no stemming/stopwords, k1=1.2 and b=0.75. IDF is
        log(1 + (N-df+0.5)/(df+0.5)); ties use UTF-8 ID order. Text only: source
        labels and record IDs do not become relevance features. Only positive
        lexical matches are returned. Statistics use the scoped corpus exclusively.
        """
        _limit(limit)
        _text_bytes(query, _MAX_QUERY_BYTES, allow_empty=True)
        terms = sorted(set(_terms(query)))
        if len(terms) > 64:
            raise ValueError("retrieval query exceeds term limit")
        if not terms or not self._average:
            return []
        scores: dict[int, float] = {}
        for term in terms:
            posting = self._postings.get(term, ())
            weight = math.log1p((len(self._lengths) - len(posting) + 0.5) / (len(posting) + 0.5))
            for index, tf in posting:
                norm = 1.2 * (0.25 + 0.75 * self._lengths[index] / self._average)
                scores[index] = scores.get(index, 0.0) + weight * tf * 2.2 / (tf + norm)
        ranked = sorted(
            ((self.corpus.records[index].id, score) for index, score in scores.items()),
            key=lambda item: (-item[1], item[0].encode("utf-8")),
        )
        return [node_id for node_id, _ in ranked[:limit]]


if __name__ == "__main__":
    # No graph, service, file discovery, or model invocation is required to rank.
    records = {
        "retry": RetrievalDocument("retry", "public", "1", "Keep the operation ID when retrying."),
        "secret": RetrievalDocument("secret", "private", "7", "Private unrelated instructions."),
    }
    corpus = ScopedCorpus(records, allowed=["retry"], policy_revision="public-only.v1")
    print(json.dumps({"semantic_candidates": corpus.bm25("retry operation"), "corpus": corpus.identity}))
