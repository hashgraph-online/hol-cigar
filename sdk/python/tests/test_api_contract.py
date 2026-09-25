"""Compatibility with the real published 0.11.0 Python installation."""

import json
import subprocess
import sys
from pathlib import Path

from api_snapshot import snapshot


def test_public_api_retains_published_exports_signatures_and_types():
    baseline = json.loads((Path(__file__).parent / "fixtures/public-api-0.11.0.json").read_text())
    current = snapshot()
    assert current["abi"] == baseline["abi"]
    for name, expected in baseline["exports"].items():
        assert current["exports"][name] == expected, name


def test_fresh_import_is_lazy_and_all_access_paths_resolve():
    code = '''
import sys
import cigar_sdk
assert not {"cigar_sdk.client", "cigar_sdk.context", "cigar_sdk.generated.models",
            "cigar_sdk.workflow_session"} & sys.modules.keys()
assert set(cigar_sdk.__all__) <= set(dir(cigar_sdk))
from concurrent.futures import ThreadPoolExecutor
with ThreadPoolExecutor(max_workers=16) as executor:
    names = list(cigar_sdk.__all__) * 4
    values = list(executor.map(lambda name: getattr(cigar_sdk, name), names))
assert all(value is getattr(cigar_sdk, name) for name, value in zip(names, values))
namespace = {}
exec("from cigar_sdk import *", namespace)
assert all(namespace[name] is getattr(cigar_sdk, name) for name in cigar_sdk.__all__)
try:
    cigar_sdk.unknown_export
except AttributeError:
    pass
else:
    raise AssertionError("unknown attribute accepted")
'''
    subprocess.run([sys.executable, "-c", code], check=True, timeout=30)
