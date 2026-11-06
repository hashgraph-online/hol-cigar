"""Lazy runtime types preserve Python 3.14 annotation/export introspection."""

import os
import subprocess
import sys


def test_queries_avoid_unused_type_construction_and_introspection_still_resolves():
    code = """
import inspect, os, sys, typing
from cigar_sdk.context import LocalContextGraph
import cigar_sdk.context as context
assert 'cigar_sdk.context_types' not in sys.modules
assert 'LocalDocument' in dir(context)
with LocalContextGraph('lazy-types', worker_path=os.environ.get('CIGAR_TEST_WORKER')) as graph:
    graph.upsert({'id': 'doc', 'source': 'doc', 'text': 'Retain exact ordinary evidence.'})
    result = graph.compile({'query': 'evidence', 'max_tokens': 2048})
    assert result['snapshot']['blocks']
    assert 'cigar_sdk.context_types' not in sys.modules
assert 'LocalDocument' in str(inspect.signature(LocalContextGraph.upsert))
from cigar_sdk.context_types import LocalDocument, LocalContextResult
assert typing.get_type_hints(LocalContextGraph.upsert)['document'] is LocalDocument
assert typing.get_type_hints(LocalContextGraph.compile)['return'] is LocalContextResult
assert context.LocalDocument is LocalDocument
assert context.LocalContextResult is LocalContextResult
assert context.queue.Queue is not None
try:
    context.unknown_runtime_type
except AttributeError:
    pass
else:
    raise AssertionError('unknown module export')
"""
    subprocess.run([sys.executable, "-c", code], check=True, timeout=30, env=os.environ.copy())


def test_fresh_module_star_import_retains_lazy_types_and_original_public_members():
    code = """
import sys
import cigar_sdk.context as context
assert 'cigar_sdk.context_types' not in sys.modules
namespace = {}
exec('from cigar_sdk.context import *', namespace)
from cigar_sdk.context_types import LocalDocument, LocalContextResult
assert namespace['LocalDocument'] is LocalDocument
assert namespace['LocalContextResult'] is LocalContextResult
assert namespace['LocalContextGraph'] is context.LocalContextGraph
assert namespace['queue'].Queue is context.queue.Queue
assert namespace['Path'] is context.Path
assert set(context._WIRE_NAMES) <= namespace.keys()
"""
    subprocess.run([sys.executable, "-c", code], check=True, timeout=30)
