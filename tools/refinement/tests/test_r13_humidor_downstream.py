from __future__ import annotations

# ruff: noqa: E402

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refinement.downstream import (
    DownstreamNominationError,
    export_nomination,
    verify_nomination,
)


def _git(*arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _record(path: Path, value: dict[str, object]) -> Path:
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return path


def _event(candidate: str, tree: str, champion: str, champion_tree: str) -> dict[str, object]:
    return {
        "schema_version": "cigar.refinement-loop-event.v1",
        "event_id": "1220" + "1" * 64,
        "sequence": 6,
        "previous_event_id": "1220" + "2" * 64,
        "run_id": "run-downstream",
        "iteration": 0,
        "phase": "terminal",
        "status": "nominate",
        "resume_phase": None,
        "trial_id": "trial-downstream",
        "champion_revision": champion,
        "champion_tree": champion_tree,
        "candidate_revision": candidate,
        "candidate_tree": tree,
        "reservation_id": None,
        "artifact_ids": ["1220" + "3" * 64],
        "failure_category": None,
    }


def _ledger(candidate: str, tree: str) -> dict[str, object]:
    return {
        "schema_version": "cigar.refinement-ledger-entry.v1",
        "entry_id": "1220" + "4" * 64,
        "sequence": 4,
        "previous_entry_id": "1220" + "5" * 64,
        "iteration_id": "trial-downstream",
        "event_type": "trial_nominated",
        "source_revision": candidate,
        "source_tree": tree,
        "artifact_ids": ["1220" + "3" * 64],
        "decision": "nominate",
        "evidence_class": "development",
    }


def test_exports_and_verifies_content_free_internal_nomination(tmp_path: Path) -> None:
    candidate = _git("rev-parse", "HEAD")
    champion = _git("rev-parse", "HEAD^")
    tree = _git("rev-parse", "HEAD^{tree}")
    champion_tree = _git("rev-parse", "HEAD^^{tree}")
    event = _record(tmp_path / "event.json", _event(candidate, tree, champion, champion_tree))
    ledger = _record(tmp_path / "ledger.json", _ledger(candidate, tree))
    key = tmp_path / "key"
    key.write_bytes(b"k" * 32)
    key.chmod(0o600)

    nomination = export_nomination(ROOT, event, ledger, key, "downstream-test")

    assert nomination["contains_private_content"] is False
    assert nomination["merge_authority"] is False
    assert nomination["publication_authority"] is False
    assert nomination["changed_paths"]
    assert all("path" in row and "surfaces" in row for row in nomination["changed_paths"])
    verify_nomination(ROOT, nomination, key)


def test_rejects_stale_candidate_tree(tmp_path: Path) -> None:
    candidate = _git("rev-parse", "HEAD")
    champion = _git("rev-parse", "HEAD^")
    champion_tree = _git("rev-parse", "HEAD^^{tree}")
    event = _record(
        tmp_path / "event.json",
        _event(candidate, "f" * 40, champion, champion_tree),
    )
    ledger = _record(tmp_path / "ledger.json", _ledger(candidate, "f" * 40))
    key = tmp_path / "key"
    key.write_bytes(b"k" * 32)
    key.chmod(0o600)

    with pytest.raises(DownstreamNominationError, match="source trees"):
        export_nomination(ROOT, event, ledger, key, "downstream-test")
