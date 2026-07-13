"""Independently verify the bounded CIGAR replay reproduction vector."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

MAX_FIXTURE_BYTES = 1_048_576
MAX_RETAINED_BYTES = 1_048_576
MAX_ENCODED_RETAINED_BYTES = 1_398_104
MAX_ARTIFACTS = 64
MAX_OBSERVATIONS = 1_024
MAX_JSON_DEPTH = 64
DEPENDENCY_ORDER = [
    "source",
    "blob",
    "policy",
    "index",
    "manifest",
    "bundle",
    "tokenizer",
    "adapter",
    "consumer",
    "tool_schema",
    "environment",
]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key in replay vector: {key}")
        result[key] = value
    return result


def _validate_depth(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("replay vector JSON nesting exceeds its bound")
    if isinstance(value, dict):
        for child in value.values():
            _validate_depth(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _validate_depth(child, depth + 1)


def _strict_object(value: Any, keys: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{context} has unknown or missing fields")
    return value


def _string(
    record: dict[str, Any],
    key: str,
    context: str,
    maximum: int = 256,
    allow_empty: bool = False,
) -> str:
    value = record[key]
    if (
        not isinstance(value, str)
        or (not value and not allow_empty)
        or len(value) > maximum
    ):
        raise ValueError(f"{context}.{key} must be a bounded string")
    return value


def _boolean(record: dict[str, Any], key: str, context: str) -> bool:
    value = record[key]
    if not isinstance(value, bool):
        raise ValueError(f"{context}.{key} must be a boolean")
    return value


def _string_array(value: Any, context: str, maximum: int = 64) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"{context} must be a bounded array")
    if any(not isinstance(item, str) or not item or len(item) > 256 for item in value):
        raise ValueError(f"{context} contains a non-string or unbounded value")
    return value


def _decode_exact_base64url(value: str, context: str, allow_empty: bool) -> bytes:
    if not value:
        if allow_empty:
            return b""
        raise ValueError(f"{context} must not be empty")
    if len(value) > MAX_ENCODED_RETAINED_BYTES or any(
        character
        not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in value
    ):
        raise ValueError(f"{context} is not bounded unpadded base64url")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError(f"{context} is invalid base64url") from error
    if (
        len(decoded) > MAX_RETAINED_BYTES
        or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value
    ):
        raise ValueError(f"{context} is non-canonical or exceeds its bound")
    return decoded


def _multihash(value: bytes) -> str:
    return "1220" + hashlib.sha256(value).hexdigest()


def _observation_multihash(observations: list[bytes]) -> str:
    digest = hashlib.sha256()
    for observation in observations:
        if len(observation) > 0xFFFFFFFF:
            raise ValueError("recorded observation exceeds u32 framing")
        digest.update(len(observation).to_bytes(4, "big"))
        digest.update(observation)
    return "1220" + digest.hexdigest()


def _verify_digest(value: str, context: str) -> None:
    if (
        len(value) != 68
        or not value.startswith("1220")
        or any(character not in "0123456789abcdef" for character in value[4:])
    ):
        raise ValueError(f"{context} is not a lowercase SHA-256 multihash")


def _parse_artifacts(required: list[str], value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > MAX_ARTIFACTS:
        raise ValueError("retained artifact table must be a bounded array")
    artifacts: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        entry = _strict_object(
            raw,
            {"kind", "bytes_base64url", "digest_multihash"},
            f"retained artifact {index}",
        )
        kind = _string(entry, "kind", f"retained artifact {index}")
        if kind not in required or kind in seen:
            raise ValueError("retained artifact kind is unknown or duplicated")
        seen.add(kind)
        encoded = _string(
            entry,
            "bytes_base64url",
            f"retained artifact {index}",
            MAX_ENCODED_RETAINED_BYTES,
        )
        declared = _string(entry, "digest_multihash", f"retained artifact {index}", 68)
        _verify_digest(declared, f"retained artifact {index} digest")
        artifacts.append(
            {"kind": kind, "bytes_base64url": encoded, "digest_multihash": declared}
        )
    return artifacts


def _verify_artifacts(
    required: list[str], artifacts: list[dict[str, str]]
) -> tuple[dict[str, bytes], list[str]]:
    verified: dict[str, bytes] = {}
    for artifact in artifacts:
        kind = artifact["kind"]
        content = _decode_exact_base64url(
            artifact["bytes_base64url"], f"{kind} artifact", False
        )
        if _multihash(content) == artifact["digest_multihash"]:
            verified[kind] = content
    return verified, [kind for kind in required if kind not in verified]


def verify(path: Path) -> dict[str, Any]:
    with path.open("rb") as fixture_file:
        source = fixture_file.read(MAX_FIXTURE_BYTES + 1)
    if not source or len(source) > MAX_FIXTURE_BYTES:
        raise ValueError("fixture size is invalid")
    try:
        text = source.decode("utf-8", errors="strict")
        root_value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("fixture is not bounded valid JSON") from error
    _validate_depth(root_value)
    root = _strict_object(
        root_value,
        {
            "schema_version",
            "digest_algorithm",
            "observation_framing",
            "retained",
            "required_dependencies",
            "retained_artifacts",
            "missing_artifact_probe",
            "tampered_artifact_probe",
            "empty_recorded_response_probe",
            "expected",
        },
        "fixture",
    )
    if (
        _string(root, "schema_version", "fixture") != "cigar.replay-vector.v1"
        or _string(root, "digest_algorithm", "fixture")
        != "sha256-multihash-raw-v1"
        or _string(root, "observation_framing", "fixture")
        != "u32be-length-prefixed-v1"
    ):
        raise ValueError("fixture declares an unsupported profile")

    retained = _strict_object(
        root["retained"],
        {
            "bundle_bytes_base64url",
            "invocation_bytes_base64url",
            "recorded_observation_bytes_base64url",
        },
        "retained",
    )
    bundle = _decode_exact_base64url(
        _string(
            retained,
            "bundle_bytes_base64url",
            "retained",
            MAX_ENCODED_RETAINED_BYTES,
        ),
        "bundle",
        False,
    )
    invocation = _decode_exact_base64url(
        _string(
            retained,
            "invocation_bytes_base64url",
            "retained",
            MAX_ENCODED_RETAINED_BYTES,
        ),
        "invocation",
        False,
    )
    encoded_observations = _string_array(
        retained["recorded_observation_bytes_base64url"],
        "recorded observations",
        MAX_OBSERVATIONS,
    )
    if not encoded_observations:
        raise ValueError("recorded observations must not be empty")
    observations = [
        _decode_exact_base64url(value, f"recorded observation {index}", True)
        for index, value in enumerate(encoded_observations)
    ]

    required = _string_array(root["required_dependencies"], "required dependencies")
    if required != DEPENDENCY_ORDER:
        raise ValueError("required dependency order differs")
    artifacts = _parse_artifacts(required, root["retained_artifacts"])

    expected = _strict_object(
        root["expected"],
        {
            "bundle_digest_multihash",
            "invocation_digest_multihash",
            "observation_digest_multihash",
            "complete",
            "missing_dependencies",
        },
        "expected",
    )
    expected_bundle = _string(expected, "bundle_digest_multihash", "expected", 68)
    expected_invocation = _string(
        expected, "invocation_digest_multihash", "expected", 68
    )
    expected_observations = _string(
        expected, "observation_digest_multihash", "expected", 68
    )
    for context, value in (
        ("bundle digest", expected_bundle),
        ("invocation digest", expected_invocation),
        ("observation digest", expected_observations),
    ):
        _verify_digest(value, context)
    bundle_digest = _multihash(bundle)
    invocation_digest = _multihash(invocation)
    observation_digest = _observation_multihash(observations)
    if (bundle_digest, invocation_digest, observation_digest) != (
        expected_bundle,
        expected_invocation,
        expected_observations,
    ):
        raise ValueError("retained replay digest mismatch")

    verified, missing = _verify_artifacts(required, artifacts)
    complete = not missing
    if complete != _boolean(expected, "complete", "expected"):
        raise ValueError("completeness mismatch")
    if missing != _string_array(
        expected["missing_dependencies"], "expected missing dependencies"
    ):
        raise ValueError("missing dependencies differ")
    if verified.get("bundle") != bundle:
        raise ValueError("retained bundle and bundle dependency artifact differ")

    missing_probe = _strict_object(
        root["missing_artifact_probe"],
        {"kind", "expected_complete", "expected_missing_dependencies"},
        "missing artifact probe",
    )
    missing_kind = _string(missing_probe, "kind", "missing artifact probe")
    if missing_kind not in required:
        raise ValueError("missing artifact probe names an unknown dependency")
    _, missing_probe_dependencies = _verify_artifacts(
        required, [artifact for artifact in artifacts if artifact["kind"] != missing_kind]
    )
    missing_probe_complete = not missing_probe_dependencies
    if missing_probe_complete != _boolean(
        missing_probe, "expected_complete", "missing artifact probe"
    ):
        raise ValueError("missing artifact probe completeness differs")
    if missing_probe_dependencies != _string_array(
        missing_probe["expected_missing_dependencies"],
        "missing artifact probe dependencies",
    ):
        raise ValueError("missing artifact probe dependencies differ")

    tamper_probe = _strict_object(
        root["tampered_artifact_probe"],
        {
            "kind",
            "replacement_bytes_base64url",
            "expected_accepted",
            "expected_missing_dependencies",
        },
        "tampered artifact probe",
    )
    tamper_kind = _string(tamper_probe, "kind", "tampered artifact probe")
    if tamper_kind not in required:
        raise ValueError("tampered artifact probe names an unknown dependency")
    replacement = _string(
        tamper_probe,
        "replacement_bytes_base64url",
        "tampered artifact probe",
        MAX_ENCODED_RETAINED_BYTES,
    )
    replacements = 0
    tampered: list[dict[str, str]] = []
    for artifact in artifacts:
        changed = dict(artifact)
        if artifact["kind"] == tamper_kind:
            changed["bytes_base64url"] = replacement
            replacements += 1
        tampered.append(changed)
    if replacements != 1:
        raise ValueError("tampered artifact probe must identify exactly one artifact")
    _, tampered_missing = _verify_artifacts(required, tampered)
    tamper_accepted = not tampered_missing
    if tamper_accepted != _boolean(
        tamper_probe, "expected_accepted", "tampered artifact probe"
    ):
        raise ValueError("tampered artifact probe acceptance differs")
    if tampered_missing != _string_array(
        tamper_probe["expected_missing_dependencies"],
        "tampered artifact probe dependencies",
    ):
        raise ValueError("tampered artifact probe dependencies differ")

    empty_probe = _strict_object(
        root["empty_recorded_response_probe"],
        {"bytes_base64url", "digest_multihash", "expected_accepted"},
        "empty recorded response probe",
    )
    empty_response = _decode_exact_base64url(
        _string(
            empty_probe,
            "bytes_base64url",
            "empty recorded response probe",
            MAX_ENCODED_RETAINED_BYTES,
            True,
        ),
        "empty recorded response",
        True,
    )
    expected_empty_digest = _string(
        empty_probe, "digest_multihash", "empty recorded response probe", 68
    )
    _verify_digest(expected_empty_digest, "empty recorded response digest")
    empty_digest = _multihash(empty_response)
    empty_accepted = not empty_response and empty_digest == expected_empty_digest
    if empty_accepted != _boolean(
        empty_probe, "expected_accepted", "empty recorded response probe"
    ):
        raise ValueError("empty recorded response probe acceptance differs")

    return {
        "schema_version": "cigar.replay-reproduction-result.v1",
        "bundle_digest_multihash": bundle_digest,
        "invocation_digest_multihash": invocation_digest,
        "observation_digest_multihash": observation_digest,
        "complete": complete,
        "missing_dependencies": missing,
        "missing_artifact_probe": {
            "complete": missing_probe_complete,
            "missing_dependencies": missing_probe_dependencies,
        },
        "tampered_artifact_probe": {
            "accepted": tamper_accepted,
            "missing_dependencies": tampered_missing,
        },
        "empty_recorded_response_probe": {
            "accepted": empty_accepted,
            "digest_multihash": empty_digest,
        },
    }


def main() -> None:
    """Verify one replay vector and emit its stable reproduction result."""

    path = Path(sys.argv[1] if len(sys.argv) > 1 else "schemas/vectors/replay-v1.json")
    print(json.dumps(verify(path), ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
