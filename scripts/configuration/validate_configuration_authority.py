#!/usr/bin/env python3
"""Validate the closed macOS development configuration authority and source drift."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "cigar.configuration-authority.v1"
PROFILES = ["embedded", "local_sidecar", "remote_client", "shared_service"]
PRECEDENCE = [
    "compiled_default",
    "system_config",
    "user_config",
    "project_config",
    "explicit_config",
    "environment",
    "cli_flag",
    "programmatic_api",
]
SETTING_KEYS = {
    "id",
    "owner",
    "profiles",
    "precedence",
    "allowed_sources",
    "default_semantics",
    "required_semantics",
    "secret_classification",
    "value_form",
    "provenance_label",
    "project_configuration_forbidden",
    "macos_disposition",
}
TOP_LEVEL_KEYS = {
    "$schema",
    "schema_version",
    "platform_scope",
    "precedence_order",
    "profiles",
    "ambient_authority",
    "file_policies",
    "source_inventories",
    "settings",
    "secret_provider_qualification",
}
HANDLE_CLASSIFICATIONS = {
    "secret_handle",
    "encrypted_secret_handle",
    "trusted_handle",
    "integrity_handle",
    "provider_handle",
}
SECRET_CLASSIFICATIONS = {"secret_handle", "encrypted_secret_handle", "provider_handle"}
CLASSIFICATIONS = {
    "non_secret",
    "sensitive_reference",
    "secret_handle",
    "encrypted_secret_handle",
    "trusted_handle",
    "integrity_handle",
    "provider_handle",
    "aggregate",
}
VALUE_FORMS = {"typed_value", "path_or_provider_handle"}
FILE_POLICY_IDS = [
    "configuration",
    "trusted_handle",
    "secret_handle",
    "immutable_secret_handle",
]
EXPECTED_AUTHORITY_SHA256 = (
    "a899c3312ebdfad8d29ecf7a52c63bf8bd3bcf92ee478d425364aec46bdde94d"
)


class AuthorityError(ValueError):
    """One content-safe authority validation failure."""


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuthorityError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicates,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AuthorityError(f"unable to load strict JSON: {path}") from error


def _require_exact_keys(value: Any, keys: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AuthorityError(f"{context} must be an object")
    actual = set(value)
    if actual != keys:
        raise AuthorityError(
            f"{context} fields differ: missing={sorted(keys - actual)} unknown={sorted(actual - keys)}"
        )
    return value


def _require_nonempty_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise AuthorityError(f"{context} must be a nonempty string")
    return value


def _require_closed_list(value: Any, allowed: list[str], context: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) for item in value)
    ):
        raise AuthorityError(f"{context} must be a nonempty string array")
    if len(value) != len(set(value)):
        raise AuthorityError(f"{context} contains duplicates")
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise AuthorityError(f"{context} contains unknown values: {unknown}")
    return value


def _require_string_list(value: Any, context: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise AuthorityError(f"{context} must be a nonempty string array")
    if len(value) != len(set(value)):
        raise AuthorityError(f"{context} contains duplicates")
    return value


def validate_schema_document(schema: Any) -> None:
    root = _require_exact_keys(
        schema,
        {
            "$schema",
            "$id",
            "title",
            "type",
            "additionalProperties",
            "required",
            "properties",
            "$defs",
        },
        "schema",
    )
    if root["$schema"] != "https://json-schema.org/draft/2020-12/schema":
        raise AuthorityError("schema dialect drifted")
    if root["type"] != "object" or root["additionalProperties"] is not False:
        raise AuthorityError("authority schema root is not closed")
    if (
        set(root["required"]) != TOP_LEVEL_KEYS
        or set(root["properties"]) != TOP_LEVEL_KEYS
    ):
        raise AuthorityError("authority schema top-level fields drifted")
    definitions = root["$defs"]
    if not isinstance(definitions, dict):
        raise AuthorityError("schema definitions must be an object")
    try:
        profile_enum = definitions["profileId"]["enum"]
        source_enum = definitions["sourceId"]["enum"]
        classification_enum = definitions["setting"]["properties"][
            "secret_classification"
        ]["enum"]
        value_form_enum = definitions["setting"]["properties"]["value_form"]["enum"]
        setting_closed = definitions["setting"]["additionalProperties"]
    except (KeyError, TypeError) as error:
        raise AuthorityError("schema setting definitions are incomplete") from error
    if profile_enum != PROFILES or source_enum != PRECEDENCE:
        raise AuthorityError("schema closed profile/source enums drifted")
    if (
        set(classification_enum) != CLASSIFICATIONS
        or set(value_form_enum) != VALUE_FORMS
    ):
        raise AuthorityError("schema secret classification/value form enums drifted")
    if setting_closed is not False:
        raise AuthorityError("schema settings are not closed")


def _extract_struct_fields(source: str, struct_name: str) -> list[str]:
    match = re.search(
        rf"(?:pub\s+)?struct\s+{re.escape(struct_name)}\s*\{{(?P<body>.*?)^\}}",
        source,
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AuthorityError(f"source inventory struct is missing: {struct_name}")
    fields = re.findall(
        r"^\s*(?:pub(?:\([^)]*\))?\s+)?([a-z][a-z0-9_]*)\s*:",
        match.group("body"),
        re.MULTILINE,
    )
    if not fields or len(fields) != len(set(fields)):
        raise AuthorityError(
            f"source inventory fields are empty or duplicated: {struct_name}"
        )
    return fields


def _inventory_source_path(repo_root: Path, value: Any) -> Path:
    raw = _require_nonempty_string(value, "source inventory path")
    if (
        "\\" in raw
        or "//" in raw
        or any(ord(character) < 0x20 for character in raw)
        or not raw.endswith(".rs")
    ):
        raise AuthorityError("source inventory path is not a normalized Rust path")
    relative = Path(raw)
    if relative.is_absolute() or any(
        part in {"", ".", ".."} for part in relative.parts
    ):
        raise AuthorityError(
            "source inventory path must be normalized and repo-relative"
        )
    root = repo_root.resolve()
    candidate = root / relative
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise AuthorityError(f"source inventory path is unavailable: {raw}") from error
    if not resolved.is_relative_to(root) or resolved != candidate:
        raise AuthorityError(
            "source inventory path escapes the repository or traverses a symlink"
        )
    return candidate


def _validate_source_inventory(document: dict[str, Any], repo_root: Path) -> None:
    setting_ids = {setting["id"] for setting in document["settings"]}
    seen_inventory: set[tuple[str, str]] = set()
    inventories = document["source_inventories"]
    if not isinstance(inventories, list) or not inventories:
        raise AuthorityError("source_inventories must be a nonempty array")
    for index, raw in enumerate(inventories):
        inventory = _require_exact_keys(
            raw, {"path", "struct", "setting_prefix"}, f"source_inventories[{index}]"
        )
        relative_text = _require_nonempty_string(
            inventory["path"], f"source_inventories[{index}].path"
        )
        source_path = _inventory_source_path(repo_root, relative_text)
        relative = Path(relative_text)
        struct_name = _require_nonempty_string(
            inventory["struct"], f"source_inventories[{index}].struct"
        )
        prefix = _require_nonempty_string(
            inventory["setting_prefix"], f"source_inventories[{index}].setting_prefix"
        )
        identity = (relative.as_posix(), struct_name)
        if identity in seen_inventory:
            raise AuthorityError(f"duplicate source inventory: {identity}")
        seen_inventory.add(identity)
        try:
            source = source_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise AuthorityError(
                f"source inventory path is unavailable: {relative}"
            ) from error
        fields = _extract_struct_fields(source, struct_name)
        expected = {f"{prefix}.{field}" for field in fields}
        missing = sorted(expected - setting_ids)
        if missing:
            raise AuthorityError(
                f"source inventory settings are missing for {struct_name}: {missing}"
            )


def _require_source_guard(path: Path, fragments: list[str]) -> None:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise AuthorityError(f"guarded source is unavailable: {path}") from error
    missing = [fragment for fragment in fragments if fragment not in source]
    if missing:
        raise AuthorityError(f"source hardening guard drifted in {path}: {missing}")


def _validate_source_guards(repo_root: Path) -> None:
    _require_source_guard(
        repo_root / "crates/cigar-cli/src/configuration.rs",
        [
            "#[serde(deny_unknown_fields)]",
            'std::env::var_os("CIGAR_AUTHORIZATION")',
            'std::env::var_os("CIGAR_TOKEN")',
            "local_transports > 1",
            "same_file(&opened, &after_read)",
            "metadata.nlink() != 1",
            "OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC",
            "OFlags::DIRECTORY",
            "openat(",
            "url.username().is_empty()",
            "url.query().is_some()",
        ],
    )
    _require_source_guard(
        repo_root / "crates/cigar-cli/src/client.rs",
        [".no_proxy()", "reqwest::redirect::Policy::none()", ".referer(false)"],
    )
    _require_source_guard(
        repo_root / "crates/cigar-daemon/src/process.rs",
        [
            "safe_configuration_metadata",
            "same_file(&opened, &after_read)",
            "metadata.nlink() == 1",
            "OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC",
            "OFlags::DIRECTORY",
            "openat(",
        ],
    )
    _require_source_guard(
        repo_root / "crates/cigar-daemon/src/production_bootstrap.rs",
        [
            "ProductionFilePolicy::Restricted",
            "ProductionFilePolicy::Immutable",
            "same_regular_file(&opened, &after_read)",
            "EncryptedDevelopmentKeystore::open_existing_bytes",
            "OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC",
            "OFlags::DIRECTORY",
            "openat(",
        ],
    )
    _require_source_guard(
        repo_root / "crates/cigar-daemon/src/production_effect_transport.rs",
        [
            ".https_only(true)",
            "reqwest::redirect::Policy::none()",
            ".no_proxy()",
            ".referer(false)",
            ".retry(reqwest::retry::never())",
            ".resolve_to_addrs(&endpoint.host, addresses)",
            ".tls_certs_only(roots)",
            "read_secret_bytes",
            "pinned_addresses",
            "Zeroizing",
        ],
    )
    _require_source_guard(
        repo_root / "crates/cigar-crypto/src/keystore.rs",
        [
            "OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC",
            "OFlags::DIRECTORY",
            "openat(",
        ],
    )
    _require_source_guard(
        repo_root / "sdk/rust/src/remote.rs",
        [
            "OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC",
            "OFlags::DIRECTORY",
            "openat(",
        ],
    )
    for relative in [
        "crates/cigar-daemon/src/config.rs",
        "crates/cigar-daemon/src/telemetry.rs",
        "crates/cigar-store/src/object.rs",
        "sdk/rust/src/remote.rs",
    ]:
        _require_source_guard(
            repo_root / relative,
            [
                "username().is_empty()",
                "password().is_none()",
                "query().is_none()",
                "fragment().is_none()",
            ],
        )
    _require_source_guard(
        repo_root / "crates/cigar-rust-s3/src/request/blocking.rs",
        [
            "ProxySettings::builder().build()",
            "session.follow_redirects(false)",
            'env("HTTP_PROXY"',
            'env("http_proxy"',
            'join(".netrc")',
        ],
    )
    _require_source_guard(
        repo_root / "crates/cigar-rust-s3/src/request/tokio_backend.rs",
        [
            ".no_proxy()",
            "reqwest::redirect::Policy::none()",
            ".referer(false)",
            'env("HTTP_PROXY"',
            'env("http_proxy"',
            'join(".netrc")',
        ],
    )


def validate_document(
    document: Any, repo_root: Path | None = None, *, source_checks: bool = True
) -> None:
    root = _require_exact_keys(document, TOP_LEVEL_KEYS, "authority")
    if (
        root["$schema"] != "./authority-v1.schema.json"
        or root["schema_version"] != SCHEMA_VERSION
    ):
        raise AuthorityError("authority schema identity is not frozen v1")
    if root["precedence_order"] != PRECEDENCE:
        raise AuthorityError("global precedence order drifted")
    if root["platform_scope"] != {
        "operating_system": "macos",
        "architectures": ["aarch64"],
        "status": "development_only",
    }:
        raise AuthorityError("platform scope exceeds macOS arm64 development")

    profiles = root["profiles"]
    if (
        not isinstance(profiles, list)
        or [profile.get("id") for profile in profiles if isinstance(profile, dict)]
        != PROFILES
    ):
        raise AuthorityError("profiles must be the four frozen profiles in order")
    for index, profile in enumerate(profiles):
        _require_exact_keys(
            profile,
            {
                "id",
                "owner",
                "configuration_boundary",
                "project_configuration",
                "network_authority",
                "secret_authority",
                "mode_invariants",
            },
            f"profiles[{index}]",
        )
        for field in [
            "owner",
            "configuration_boundary",
            "project_configuration",
            "network_authority",
            "secret_authority",
        ]:
            _require_nonempty_string(profile[field], f"profiles[{index}].{field}")
        _require_string_list(
            profile["mode_invariants"], f"profiles[{index}].mode_invariants"
        )

    file_policies = root["file_policies"]
    if not isinstance(file_policies, list) or len(file_policies) != len(
        FILE_POLICY_IDS
    ):
        raise AuthorityError("file_policies must contain the four frozen policies")
    if [
        policy.get("id") for policy in file_policies if isinstance(policy, dict)
    ] != FILE_POLICY_IDS:
        raise AuthorityError("file policy identities or order drifted")
    for index, raw in enumerate(file_policies):
        policy = _require_exact_keys(
            raw,
            {"id", "owner", "mode", "links", "size", "read_binding"},
            f"file_policies[{index}]",
        )
        for field in ["owner", "mode", "links", "size", "read_binding"]:
            _require_nonempty_string(policy[field], f"file_policies[{index}].{field}")
        if (
            "link count one" not in policy["links"]
            or "descriptor" not in policy["read_binding"]
        ):
            raise AuthorityError(
                f"file policy is not descriptor/link bound: {policy['id']}"
            )

    settings = root["settings"]
    if not isinstance(settings, list) or not settings:
        raise AuthorityError("settings must be nonempty")
    seen_ids: set[str] = set()
    seen_labels: set[tuple[str, str, str]] = set()
    for index, raw in enumerate(settings):
        setting = _require_exact_keys(raw, SETTING_KEYS, f"settings[{index}]")
        setting_id = _require_nonempty_string(setting["id"], f"settings[{index}].id")
        if setting_id in seen_ids:
            raise AuthorityError(f"duplicate setting id: {setting_id}")
        seen_ids.add(setting_id)
        _require_nonempty_string(setting["owner"], f"settings[{index}].owner")
        setting_profiles = _require_closed_list(
            setting["profiles"], PROFILES, f"settings[{index}].profiles"
        )
        if setting_profiles != [
            profile for profile in PROFILES if profile in setting_profiles
        ]:
            raise AuthorityError(
                f"setting profiles are not in frozen order: {setting_id}"
            )
        allowed = _require_closed_list(
            setting["allowed_sources"], PRECEDENCE, f"settings[{index}].allowed_sources"
        )
        precedence = _require_closed_list(
            setting["precedence"], PRECEDENCE, f"settings[{index}].precedence"
        )
        expected_precedence = [source for source in PRECEDENCE if source in allowed]
        if allowed != expected_precedence or precedence != expected_precedence:
            raise AuthorityError(
                f"setting precedence is not the ordered allowed-source projection: {setting_id}"
            )
        project_forbidden = setting["project_configuration_forbidden"]
        if not isinstance(project_forbidden, bool):
            raise AuthorityError(
                f"project configuration disposition is not boolean: {setting_id}"
            )
        if project_forbidden and "project_config" in allowed:
            raise AuthorityError(
                f"project configuration is both forbidden and allowed: {setting_id}"
            )
        classification = setting["secret_classification"]
        if classification not in CLASSIFICATIONS:
            raise AuthorityError(f"unknown secret classification: {setting_id}")
        if setting["value_form"] not in VALUE_FORMS:
            raise AuthorityError(f"unknown setting value form: {setting_id}")
        if (
            classification in HANDLE_CLASSIFICATIONS
            and setting["value_form"] != "path_or_provider_handle"
        ):
            raise AuthorityError(f"handle setting accepts a raw value: {setting_id}")
        if classification in SECRET_CLASSIFICATIONS:
            if not project_forbidden or "project_config" in allowed:
                raise AuthorityError(
                    f"secret authority may originate in project config: {setting_id}"
                )
        if setting["macos_disposition"] not in {"active", "rejected_on_macos"}:
            raise AuthorityError(f"unknown macOS disposition: {setting_id}")
        for field in ["default_semantics", "required_semantics", "provenance_label"]:
            _require_nonempty_string(setting[field], f"settings[{index}].{field}")
        for profile in setting_profiles:
            label_identity = (profile, setting["owner"], setting["provenance_label"])
            if (
                label_identity in seen_labels
                and setting["provenance_label"] == "authorization"
            ):
                raise AuthorityError(
                    "authorization provenance labels are ambiguous within one profile"
                )
            seen_labels.add(label_identity)

        profile_rule: list[str] | None = None
        if setting_id.startswith(
            ("daemon.tls", "daemon.oidc", "daemon.shared_storage")
        ):
            profile_rule = ["shared_service"]
        elif setting_id.startswith(("sdk.remote", "cli.remote_endpoint")):
            profile_rule = ["remote_client"]
        elif setting_id.startswith("sdk.embedded"):
            profile_rule = ["embedded"]
        elif setting_id.startswith(("cli.local_", "cli.windows_named_pipe")):
            profile_rule = ["local_sidecar"]
        if profile_rule is not None and setting_profiles != profile_rule:
            raise AuthorityError(f"mode-incompatible profile binding: {setting_id}")

    ambient = _require_exact_keys(
        root["ambient_authority"],
        {
            "disposition",
            "proxy_environment",
            "credential_environment",
            "filesystem_conventions",
            "transport_requirements",
        },
        "ambient_authority",
    )
    if ambient["disposition"] != "ignored_or_rejected_never_inherited":
        raise AuthorityError("ambient authority disposition drifted")
    for field in [
        "proxy_environment",
        "credential_environment",
        "filesystem_conventions",
        "transport_requirements",
    ]:
        _require_string_list(ambient[field], f"ambient_authority.{field}")
    required_proxy = {
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    }
    if set(ambient["proxy_environment"]) != required_proxy:
        raise AuthorityError("ambient proxy environment inventory is incomplete")
    required_credentials = {
        "CIGAR_AUTHORIZATION",
        "CIGAR_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    }
    if not required_credentials.issubset(set(ambient["credential_environment"])):
        raise AuthorityError("ambient credential environment inventory is incomplete")
    if "$HOME/.netrc" not in ambient["filesystem_conventions"]:
        raise AuthorityError("ambient netrc convention is not forbidden")

    qualification = _require_exact_keys(
        root["secret_provider_qualification"],
        {"frozen", "open"},
        "secret_provider_qualification",
    )
    if (
        not isinstance(qualification["frozen"], list)
        or not isinstance(qualification["open"], list)
        or not qualification["frozen"]
        or not qualification["open"]
    ):
        raise AuthorityError(
            "secret provider qualification must retain frozen and open records"
        )
    providers: set[str] = set()
    for disposition in ["frozen", "open"]:
        for index, raw in enumerate(qualification[disposition]):
            provider = _require_exact_keys(
                raw,
                {"provider", "profiles", "status"},
                f"secret_provider_qualification.{disposition}[{index}]",
            )
            provider_id = _require_nonempty_string(
                provider["provider"],
                f"secret_provider_qualification.{disposition}[{index}].provider",
            )
            if (
                re.fullmatch(r"[a-z][a-z0-9_]*", provider_id) is None
                or provider_id in providers
            ):
                raise AuthorityError(
                    f"provider identity is invalid or duplicated: {provider_id}"
                )
            providers.add(provider_id)
            provider_profiles = _require_closed_list(
                provider["profiles"],
                PROFILES,
                f"secret_provider_qualification.{disposition}[{index}].profiles",
            )
            if provider_profiles != [
                profile for profile in PROFILES if profile in provider_profiles
            ]:
                raise AuthorityError(
                    f"provider profiles are not in frozen order: {provider_id}"
                )
            _require_nonempty_string(
                provider["status"],
                f"secret_provider_qualification.{disposition}[{index}].status",
            )

    if source_checks:
        if repo_root is None:
            raise AuthorityError("source checks require a repository root")
        _validate_source_inventory(root, repo_root)
        _validate_source_guards(repo_root)


def authority_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    default_root = Path(__file__).resolve().parents[2]
    parser.add_argument("--repo-root", type=Path, default=default_root)
    parser.add_argument("--authority", type=Path)
    parser.add_argument("--schema", type=Path)
    parser.add_argument("--skip-source-checks", action="store_true")
    parser.add_argument("--skip-digest", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    repo_root = args.repo_root.resolve()
    authority_path = (
        args.authority or repo_root / "spec/configuration/authority-v1.json"
    )
    schema_path = (
        args.schema or repo_root / "spec/configuration/authority-v1.schema.json"
    )
    try:
        schema = load_json(schema_path)
        validate_schema_document(schema)
        document = load_json(authority_path)
        validate_document(
            document, repo_root, source_checks=not args.skip_source_checks
        )
        if not args.skip_digest:
            digest = authority_digest(authority_path)
            if (
                EXPECTED_AUTHORITY_SHA256 == "TO_BE_FROZEN"
                or digest != EXPECTED_AUTHORITY_SHA256
            ):
                raise AuthorityError("authority digest drifted")
    except AuthorityError as error:
        print(f"configuration authority invalid: {error}", file=sys.stderr)
        return 1
    print(f"configuration authority valid: {authority_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
