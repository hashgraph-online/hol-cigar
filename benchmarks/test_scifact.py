"""Authored harness tests, not independent evidence-selection results."""

from __future__ import annotations

import gzip
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import scifact
from evaluation import EvaluationError


def archive(path, payloads, extra=None):
    with tarfile.open(path, "w:gz") as stream:
        for name, payload in payloads.items():
            data = (
                payload
                if isinstance(payload, bytes)
                else (json.dumps(payload) + "\n").encode()
            )
            member = tarfile.TarInfo("data/" + name)
            member.size = len(data)
            stream.addfile(member, io.BytesIO(data))
        if extra:
            stream.addfile(extra)


def fixture():
    return {
        "corpus.jsonl": {
            "doc_id": 7,
            "title": "Original title",
            "abstract": ["Sentence one.", "Sentence two."],
            "structured": False,
        },
        "claims_train.jsonl": {
            "id": 1,
            "claim": "Training",
            "evidence": {},
            "cited_doc_ids": [7],
        },
        "claims_dev.jsonl": {
            "id": 2,
            "claim": "Sentence two",
            "evidence": {"7": [{"label": "CONTRADICT", "sentences": [1]}]},
            "cited_doc_ids": [7],
        },
        "claims_test.jsonl": {"id": 3, "claim": "Test", "cited_doc_ids": [7]},
    }


class SciFactTests(unittest.TestCase):
    def test_preparation_separates_gold_from_query_and_corpus(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            archive(root / "data.tar.gz", fixture())
            metadata = scifact.prepare(root / "data.tar.gz", root / "prepared")
            self.assertEqual(metadata["queries"], 1)
            self.assertEqual(
                scifact.json_lines((root / "prepared/queries.jsonl").read_bytes()),
                [{"id": "claim-2", "query": "Sentence two"}],
            )
            document = scifact.json_lines(
                (root / "prepared/corpus.jsonl").read_bytes()
            )[0]
            self.assertEqual(
                document["text"], "Original title\nSentence one.\nSentence two."
            )
            self.assertNotIn(
                b"CONTRADICT", (root / "prepared/queries.jsonl").read_bytes()
            )
            self.assertIn(b"CONTRADICT", (root / "prepared/oracle.jsonl").read_bytes())

    def test_archive_rejects_links_traversal_duplicate_files_and_expansion(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for index, kind in enumerate(
                (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE)
            ):
                member = tarfile.TarInfo("data/hostile")
                member.type = kind
                member.linkname = "/tmp/target"
                target = root / f"bad-{index}.tar.gz"
                archive(target, fixture(), member)
                with self.assertRaises(EvaluationError):
                    scifact.archive_members(target)
            for index, name in enumerate(("../corpus.jsonl", "other/corpus.jsonl")):
                target = root / f"path-{index}.tar.gz"
                archive(target, {**fixture(), name: {}})
                with self.assertRaises(EvaluationError):
                    scifact.archive_members(target)
            with gzip.open(root / "large.gz", "wb") as stream:
                stream.write(b"x" * 101)
            with (
                patch.object(scifact, "MAX_TAR", 100),
                self.assertRaises(EvaluationError),
            ):
                scifact.archive_members(root / "large.gz")

    def test_duplicate_json_keys_and_record_ids_are_rejected(self):
        with self.assertRaises(EvaluationError):
            scifact.json_lines(b'{"id":1,"id":2}\n')
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            values = fixture()
            values["corpus.jsonl"] = (
                json.dumps(values["corpus.jsonl"]) + "\n"
            ).encode() * 2
            archive(root / "data.tar.gz", values)
            with self.assertRaises(EvaluationError):
                scifact.prepare(root / "data.tar.gz", root / "prepared")
            self.assertFalse((root / "prepared").exists())

    def test_split_overlap_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            values = fixture()
            values["claims_test.jsonl"]["id"] = 2
            archive(root / "data.tar.gz", values)
            with self.assertRaises(EvaluationError):
                scifact.prepare(root / "data.tar.gz", root / "prepared")

    def test_original_claim_id_zero_is_valid_and_not_an_overlap(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            values = fixture()
            values["claims_train.jsonl"]["id"] = 0
            archive(root / "data.tar.gz", values)
            metadata = scifact.prepare(root / "data.tar.gz", root / "prepared")
            self.assertEqual(metadata["split_counts"]["claims_train.jsonl"], 1)
            self.assertEqual(metadata["queries"], 1)

    def test_flat_control_stops_at_first_oversize_without_skipping_or_gold(self):
        class Error(Exception):
            code = "BudgetUnsatisfiable"

        class Graph:
            requests = []

            def compile(self, value):
                self.requests.append(value)
                if "large" in value["required"]:
                    raise Error()
                return {"ids": value["required"]}

        graph = Graph()
        result, calls = scifact.flat_prefix(
            graph, ["first", "large", "later"], 512, Error
        )
        self.assertEqual((result, calls), ({"ids": ["first"]}, 3))
        self.assertEqual(graph.requests[0]["allowed"], [])
        self.assertEqual(graph.requests[0]["query"], scifact.CONFIG["flat_empty_query"])
        self.assertTrue(all(row["query"] == "" for row in graph.requests[1:]))
        self.assertEqual(graph.requests[-1]["allowed"], ["first", "large"])
        result, calls = scifact.flat_prefix(Graph(), ["large", "later"], 512, Error)
        self.assertEqual((result, calls), ({"ids": []}, 2))

    def test_flat_control_preserves_unexpected_errors(self):
        class Error(Exception):
            code = "Transport"

        class Graph:
            def compile(self, _):
                raise Error()

        with self.assertRaises(Error):
            scifact.flat_prefix(Graph(), ["first"], 512, Error)

    def test_source_identity_covers_code_data_and_excludes_bytecode(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "code.py").write_text("first")
            first = scifact.source_identity(root)
            (root / "code.pyc").write_bytes(b"generated")
            self.assertEqual(first, scifact.source_identity(root))
            (root / "data.json").write_text("{}")
            self.assertNotEqual(first, scifact.source_identity(root))


if __name__ == "__main__":
    unittest.main()
