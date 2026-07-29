#!/usr/bin/env python3
"""Export one nominated CIGAR refinement candidate for HUMIDOR qualification."""

from __future__ import annotations

# ruff: noqa: E402

import argparse
import hashlib
import hmac
import os
import stat
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refinement.canonical import (
    canonical_bytes,
    identity,
    load_file,
    multihash_bytes,
    safe_relative_path,
    secure_read,
)
from tools.refinement.schema import SchemaRegistry

MAX_KEY_BYTES = 1024
GATED_SURFACES = frozenset(
    {
        "public-profile",
        "abi",
        "sdk",
        "storage",
        "effects",
        "replay",
        "release-artifact",
    }
)


class DownstreamNominationError(RuntimeError):
    """A nominated candidate is stale, unsafe, private, or ambiguous."""


def _git(repository: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(  # noqa: S603
            ["git", "-C", os.fspath(repository), *arguments],
            check=True,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise DownstreamNominationError("Git identity operation failed") from error
    try:
        return completed.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise DownstreamNominationError("Git returned non-UTF-8 output") from error


def _source(repository: Path, revision: str) -> dict[str, str]:
    resolved = _git(repository, "rev-parse", f"{revision}^{{commit}}")
    tree = _git(repository, "rev-parse", f"{revision}^{{tree}}")
    if resolved != revision:
        raise DownstreamNominationError("candidate or champion revision is not exact")
    return {"revision": resolved, "tree": tree}


def _surfaces(path: str) -> list[str]:
    surface: set[str] = set()
    if path.startswith(("conformance/profiles/", "packaging/product-", "spec/")):
        surface.add("public-profile")
    if path.startswith(("schemas/", "crates/cigar-protocol/", "crates/cigar-api/")):
        surface.add("abi")
    if path.startswith(("sdk/", "schemas/proto/", "schemas/openapi/")):
        surface.add("sdk")
    if path.startswith(("migrations/", "crates/cigar-store/")):
        surface.add("storage")
    if path.startswith("crates/cigar-effects/"):
        surface.add("effects")
    if path.startswith("crates/cigar-replay/"):
        surface.add("replay")
    if path.startswith(("packaging/", "scripts/release/", "release/")):
        surface.add("release-artifact")
    return sorted(surface or {"internal"})


def _changed_paths(repository: Path, champion: str, candidate: str) -> list[dict[str, Any]]:
    raw = _git(repository, "diff", "--name-only", "--diff-filter=ACDMRT", champion, candidate)
    paths = raw.splitlines()
    if not paths or len(paths) > 4096:
        raise DownstreamNominationError("candidate changed-path inventory is empty or too large")
    result: list[dict[str, Any]] = []
    for path in paths:
        try:
            safe_relative_path(path)
        except ValueError as error:
            raise DownstreamNominationError("candidate contains an unsafe path") from error
        result.append({"path": path, "surfaces": _surfaces(path)})
    if paths != sorted(set(paths)):
        raise DownstreamNominationError("candidate changed-path inventory is not unique and sorted")
    return result


def _key(path: Path, repository: Path) -> bytes:
    if not path.is_absolute() or path.resolve(strict=True) != path or path.is_symlink():
        raise DownstreamNominationError("attestation key must be an absolute canonical file")
    if path.is_relative_to(repository):
        raise DownstreamNominationError("attestation key is inside the source repository")
    metadata = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}
        or not 32 <= metadata.st_size <= MAX_KEY_BYTES
    ):
        raise DownstreamNominationError("attestation key metadata violates custody policy")
    return secure_read(path, maximum_bytes=MAX_KEY_BYTES)


def _unsigned(document: dict[str, Any]) -> dict[str, Any]:
    result = dict(document)
    attestation = dict(result.pop("attestation"))
    attestation["mac"] = ""
    result["attestation"] = attestation
    return result


def export_nomination(
    repository: Path,
    event_path: Path,
    ledger_path: Path,
    key_path: Path,
    key_id: str,
    *,
    experimental_profile: bool = False,
) -> dict[str, Any]:
    repository = repository.resolve(strict=True)
    registry = SchemaRegistry(repository / "schemas" / "refinement")
    event = load_file(event_path.resolve(strict=True))
    ledger = load_file(ledger_path.resolve(strict=True))
    if not isinstance(event, dict) or not isinstance(ledger, dict):
        raise DownstreamNominationError("nomination evidence is not an object")
    registry.validate("loop-event-v1.schema.json", event)
    registry.validate("ledger-v1.schema.json", ledger)
    if (
        event["phase"] != "terminal"
        or event["status"] != "nominate"
        or ledger["event_type"] != "trial_nominated"
        or ledger["decision"] != "nominate"
        or ledger["iteration_id"] != event["trial_id"]
        or ledger["source_revision"] != event["candidate_revision"]
        or ledger["source_tree"] != event["candidate_tree"]
    ):
        raise DownstreamNominationError("loop event and ledger do not bind one nomination")

    champion = _source(repository, event["champion_revision"])
    candidate = _source(repository, event["candidate_revision"])
    if (
        champion["tree"] != event["champion_tree"]
        or candidate["tree"] != event["candidate_tree"]
    ):
        raise DownstreamNominationError("Git source trees do not match nomination evidence")
    ancestry = _git(
        repository,
        "merge-base",
        "--is-ancestor",
        champion["revision"],
        candidate["revision"],
    )
    if ancestry:
        raise DownstreamNominationError("unexpected Git output during ancestry check")

    changed_paths = _changed_paths(
        repository,
        champion["revision"],
        candidate["revision"],
    )
    downstream_required = any(
        surface in GATED_SURFACES
        for item in changed_paths
        for surface in item["surfaces"]
    )
    key = _key(key_path, repository)
    body = {
        "schema_version": "cigar.refinement-downstream-nomination.v1",
        "trial_id": event["trial_id"],
        "decision": "nominate",
        "evidence_class": ledger["evidence_class"],
        "champion_source": champion,
        "candidate_source": candidate,
        "ledger_entry_id": ledger["entry_id"],
        "loop_event_id": event["event_id"],
        "changed_paths": changed_paths,
        "downstream_gate_required": downstream_required,
        "experimental_profile": experimental_profile,
        "operation": "request-humidor-qualification",
        "merge_authority": False,
        "publication_authority": False,
        "contains_private_content": False,
    }
    nomination_id = identity(body)
    document = {
        **body,
        "nomination_id": nomination_id,
        "attestation": {
            "algorithm": "hmac-sha256-v1",
            "key_id": key_id,
            "key_fingerprint": multihash_bytes(key),
            "custody": "external-independent",
            "mac": "",
        },
    }
    document["attestation"]["mac"] = hmac.new(
        key,
        canonical_bytes(_unsigned(document)),
        hashlib.sha256,
    ).hexdigest()
    registry.validate("downstream-nomination-v1.schema.json", document)
    return document


def verify_nomination(
    repository: Path,
    document: dict[str, Any],
    key_path: Path,
) -> None:
    repository = repository.resolve(strict=True)
    SchemaRegistry(repository / "schemas" / "refinement").validate(
        "downstream-nomination-v1.schema.json",
        document,
    )
    body = {
        key: value
        for key, value in document.items()
        if key not in {"nomination_id", "attestation"}
    }
    if document["nomination_id"] != identity(body):
        raise DownstreamNominationError("nomination identity is invalid")
    key = _key(key_path, repository)
    if document["attestation"]["key_fingerprint"] != multihash_bytes(key):
        raise DownstreamNominationError("nomination key fingerprint is invalid")
    expected = hmac.new(
        key,
        canonical_bytes(_unsigned(document)),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(document["attestation"]["mac"], expected):
        raise DownstreamNominationError("nomination attestation is invalid")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--event", type=Path, required=True)
    parser.add_argument("--ledger-entry", type=Path, required=True)
    parser.add_argument("--attestation-key", type=Path, required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--experimental-profile", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = export_nomination(
            arguments.repository,
            arguments.event,
            arguments.ledger_entry,
            arguments.attestation_key,
            arguments.key_id,
            experimental_profile=arguments.experimental_profile,
        )
        sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
        return 0
    except (DownstreamNominationError, OSError, ValueError) as error:
        print(f"downstream nomination: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
