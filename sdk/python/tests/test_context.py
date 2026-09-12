"""Run against a bundled artifact or explicitly selected release worker, never a mock graph."""
from __future__ import annotations

import copy
import json
import os
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cigar_sdk import LocalContextError, LocalContextGraph


class LocalContextTests(unittest.TestCase):
    def graph(self, **kwargs):
        path = os.environ.get("CIGAR_TEST_WORKER")
        graph = LocalContextGraph("sdk-test", worker_path=path, **kwargs)
        self.addCleanup(graph.close)
        return graph

    def test_incremental_cache_and_exact_rendering(self):
        graph = self.graph()
        document = {"id": "a", "source": "src/a.rs", "text": "fn authorize_user() { /* café 🦀 */ }\n"}
        self.assertTrue(graph.upsert(document))
        self.assertFalse(graph.upsert(document))
        self.assertEqual(graph.stats()["revision"], 1)
        result = graph.compile({"query": "authorizeUser", "max_tokens": 256, "reserve_tokens": 32})
        self.assertIn("authorize_user", result["rendered"])
        self.assertLessEqual(result["snapshot"]["stats"]["rendered_tokens"], 224)
        self.assertEqual(result, graph.verify(result["snapshot"]))
        before = graph.stats()["cache"]["hits"]
        self.assertEqual(result, graph.compile({"query": "authorizeUser", "max_tokens": 256, "reserve_tokens": 32}))
        self.assertGreater(graph.stats()["cache"]["hits"], before)
        graph.clear_cache()
        self.assertEqual(graph.stats()["cache"], {"hits": 0, "misses": 0, "entries": 0, "text_bytes": 0})

    def test_atomic_source_replacement_and_retained_hard_edges(self):
        graph = self.graph(limits={"max_documents": 2})
        a = {"id": "a", "source": "a", "text": "alpha"}
        b = {"id": "b", "source": "b", "text": "beta"}
        graph.upsert(a)
        graph.upsert(b)
        graph.link("a", "b", "requires")
        before = graph.stats()
        with self.assertRaises(LocalContextError) as raised:
            graph.replace_source("a", [{**a, "text": "changed"}, {**a, "id": "b"}])
        self.assertEqual(raised.exception.code, "InvalidInput")
        self.assertEqual(graph.stats(), before)
        with self.assertRaises(LocalContextError) as raised:
            graph.compile({"required": ["a"], "allowed": ["a"]})
        self.assertEqual(raised.exception.code, "RequiredUnavailable")
        graph.replace_source("b", [])
        with self.assertRaises(LocalContextError) as raised:
            graph.compile({"required": ["a"]})
        self.assertEqual(raised.exception.code, "RequiredUnavailable")
        graph.unlink("a", "b", "requires")
        self.assertEqual(graph.compile({"required": ["a"]})["snapshot"]["stats"]["selected_sources"], 1)

    def test_chunks_deltas_integrity_and_budget(self):
        graph = self.graph()
        chunks = graph.chunks({"id": "a", "source": "a", "text": "\u03b1\r\n\u03b2\n\u03b3", "start_line": 4}, 2, 1)
        self.assertEqual([c["start_line"] for c in chunks], [4, 5])
        graph.replace_source("a", chunks)
        base = graph.compile({"required": [chunks[0]["id"]]})["snapshot"]
        graph.replace_source("a", [{"id": "a", "source": "a", "text": "replacement"}])
        target = graph.compile({"required": ["a"]})
        delta = graph.delta(base, target["snapshot"])
        self.assertEqual(graph.apply_delta(base, delta), target)
        tampered = copy.deepcopy(target["snapshot"])
        tampered["blocks"][0]["text"] = "tampered"
        with self.assertRaises(LocalContextError) as raised:
            graph.verify(tampered)
        self.assertEqual(raised.exception.code, "Integrity")
        with self.assertRaises(LocalContextError) as raised:
            graph.apply_delta(target["snapshot"], delta)
        self.assertEqual(raised.exception.code, "BaseMismatch")
        with self.assertRaises(LocalContextError) as raised:
            graph.compile({"required": ["a"], "max_tokens": 1})
        self.assertEqual(raised.exception.code, "BudgetUnsatisfiable")

    def test_serializes_threads_and_closes_idempotently(self):
        graph = self.graph()
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda i: graph.upsert({"id": str(i), "source": "a", "text": "alpha"}), range(20)))
        self.assertEqual(graph.stats()["documents"], 20)
        graph.close()
        graph.close()
        with self.assertRaises(LocalContextError) as raised:
            graph.stats()
        self.assertEqual(raised.exception.code, "Closed")

    def test_prompt_view_preserves_source_and_rejects_changed_citations(self):
        graph = self.graph()
        text = "Require the same identity on retry. Reject a mismatched signature. café 🦀"
        graph.upsert({"id": "source:" + "a" * 100, "source": "contract.rs", "text": text})
        snapshot = graph.compile({"query": "retry", "max_tokens": 512})["snapshot"]
        prompt = graph.prompt_view(snapshot, 512)
        self.assertEqual(graph.verify_prompt(prompt, snapshot), prompt)
        self.assertEqual(json.loads(prompt["rendered"])["text"], text)
        self.assertEqual(graph.resolve_citation("c1", prompt, snapshot), snapshot["blocks"][0]["citations"])
        changed = copy.deepcopy(prompt)
        changed["citations"]["c1"][0]["source"] = "unrelated.rs"
        with self.assertRaises(LocalContextError) as raised:
            graph.verify_prompt(changed, snapshot)
        self.assertEqual(raised.exception.code, "Integrity")
        with self.assertRaises(LocalContextError) as raised:
            graph.prompt_view(snapshot, 1)
        self.assertEqual(raised.exception.code, "BudgetUnsatisfiable")

    def test_bad_paths_and_options_fail_without_launch(self):
        for timeout in [0, -1, float("nan"), float("inf"), 1e100]:
            with self.assertRaises(LocalContextError):
                LocalContextGraph("test", timeout=timeout)
        with self.assertRaises(LocalContextError):
            LocalContextGraph("test", worker_path=Path("relative-path"))

    def test_invalid_frame_closes_transport_without_content_echo(self):
        graph = self.graph()
        with self.assertRaises(LocalContextError) as raised:
            graph.compile({"secret_query_typo": "PRIVATE"})
        self.assertEqual(raised.exception.code, "Transport")
        self.assertNotIn("PRIVATE", str(raised.exception))
        with self.assertRaises(LocalContextError) as raised:
            graph.stats()
        self.assertEqual(raised.exception.code, "Closed")

    def test_cache_can_be_disabled(self):
        graph = self.graph(limits={"cache_entries": 0})
        graph.upsert({"id": "a", "source": "a", "text": "alpha"})
        graph.compile({"query": "alpha"})
        self.assertEqual(graph.stats()["cache"]["entries"], 0)

    @unittest.skipUnless(os.environ.get("CIGAR_TEST_STALLED_WORKER"), "release transport fixture required")
    def test_deadline_kills_worker_including_blocked_pipe_writes(self):
        commands = [{"op": "stats"},
                    {"op": "upsert", "document": {"id": "a", "source": "a", "text": "x" * 1_000_000}}]
        for command in commands:
            graph = LocalContextGraph("test", worker_path=os.environ["CIGAR_TEST_STALLED_WORKER"], timeout=2)
            start = time.monotonic()
            with self.assertRaises(LocalContextError) as raised:
                graph._call(command)
            self.assertEqual(raised.exception.code, "Timeout")
            self.assertLess(time.monotonic() - start, 5)
            self.assertIsNotNone(graph._process.poll())
            self.assertFalse(graph._thread.is_alive())
            graph.close()


if __name__ == "__main__":
    unittest.main()
