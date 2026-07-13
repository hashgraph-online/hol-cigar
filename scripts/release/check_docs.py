#!/usr/bin/env python3
"""Check published documentation links, anchors, code blocks, and declared commands."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import tomllib
import urllib.parse
from pathlib import Path
from typing import Any

from release_lib import (
    ReleaseError,
    expand_files,
    load_json,
    load_json_bytes,
    process_failure_summary,
    repo_root,
    require_distinct_output,
    resolve_beneath,
    run_bounded,
    safe_relative_path,
    sha256_bytes,
    write_json,
)


_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
_HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$")
_FENCE = re.compile(r"^```([A-Za-z0-9_+-]*)\s*$")
_DIRECTIVE = re.compile(
    r"^<!--\s*docs-check:\s*(command|illustrative)\s*([a-z0-9._-]+)?\s*-->$"
)
_SHELL_LANGUAGES = {"bash", "console", "powershell", "sh", "shell", "zsh"}


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument(
        "--execute",
        action="append",
        choices=["local", "installed-candidate", "live"],
        default=[],
    )
    parser.add_argument("--execute-local", action="store_true")
    parser.add_argument(
        "--variables", type=Path, help="strict JSON mapping used to expand ${NAME}"
    )
    parser.add_argument("--report", type=Path)
    return parser.parse_args()


def _slug(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    return re.sub(r"[\s-]+", "-", text).strip("-")


def _anchors(path: Path) -> set[str]:
    result: set[str] = set()
    counts: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = _HEADING.match(line)
        if match is None:
            continue
        base = _slug(match.group(1))
        count = counts.get(base, 0)
        counts[base] = count + 1
        result.add(base if count == 0 else f"{base}-{count}")
    return result


def _published_files(root: Path, manifest: dict[str, Any]) -> list[Path]:
    includes = manifest.get("include")
    if not isinstance(includes, list) or not all(
        isinstance(item, str) for item in includes
    ):
        raise ReleaseError("documentation include manifest is invalid")
    files = [
        path
        for relative, path in expand_files(root, includes, [])
        if relative.endswith(".md")
    ]
    if not files:
        raise ReleaseError("documentation manifest expanded to no Markdown files")
    return files


def _site_assets(root: Path, manifest: dict[str, Any]) -> set[str]:
    assets = manifest.get("assets")
    if (
        not isinstance(assets, list)
        or not assets
        or not all(isinstance(value, str) and value for value in assets)
        or len(set(assets)) != len(assets)
    ):
        raise ReleaseError("documentation asset allowlist is invalid")
    result: set[str] = set()
    for relative in assets:
        relative = safe_relative_path(relative)
        path = resolve_beneath(root, relative)
        if not path.is_file() or path.suffix.lower() == ".md":
            raise ReleaseError(
                f"documentation asset is not an allowed regular non-Markdown file: {relative}"
            )
        result.add(relative)
    return result


def _check_links(
    root: Path, files: list[Path], assets: set[str]
) -> tuple[int, set[str]]:
    anchors = {path.resolve(): _anchors(path) for path in files}
    published = set(anchors)
    count = 0
    referenced_assets: set[str] = set()
    errors: list[str] = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        for raw in _LINK.findall(text):
            target_text = raw.split(maxsplit=1)[0].strip("<>")
            if target_text.startswith(("http://", "https://", "mailto:", "data:")):
                continue
            decoded = urllib.parse.unquote(target_text)
            file_part, separator, fragment = decoded.partition("#")
            target = path if not file_part else path.parent / file_part
            try:
                resolved = target.resolve(strict=True)
            except OSError:
                errors.append(
                    f"{path.relative_to(root)}: missing link target {target_text}"
                )
                continue
            if resolved != root and root not in resolved.parents:
                errors.append(
                    f"{path.relative_to(root)}: link escapes repository {target_text}"
                )
                continue
            relative = resolved.relative_to(root).as_posix()
            if resolved not in published and relative not in assets:
                errors.append(
                    f"{path.relative_to(root)}: link target is not a published page or allowlisted asset {target_text}"
                )
                continue
            if relative in assets:
                referenced_assets.add(relative)
            if separator and fragment:
                if resolved.suffix.lower() != ".md":
                    errors.append(
                        f"{path.relative_to(root)}: fragment on non-Markdown target {target_text}"
                    )
                else:
                    target_anchors = anchors.get(resolved, _anchors(resolved))
                    if fragment not in target_anchors:
                        errors.append(
                            f"{path.relative_to(root)}: missing anchor {target_text}"
                        )
            count += 1
    if errors:
        raise ReleaseError("; ".join(errors[:30]))
    return count, referenced_assets


def _check_blocks(
    root: Path, files: list[Path], commands: dict[str, dict[str, Any]]
) -> tuple[int, set[str]]:
    blocks = 0
    referenced: set[str] = set()
    errors: list[str] = []
    for path in files:
        lines = path.read_text(encoding="utf-8").splitlines()
        index = 0
        while index < len(lines):
            opening = _FENCE.match(lines[index])
            if opening is None:
                index += 1
                continue
            language = opening.group(1).lower()
            start = index
            index += 1
            content: list[str] = []
            while index < len(lines) and lines[index] != "```":
                content.append(lines[index])
                index += 1
            if index == len(lines):
                errors.append(
                    f"{path.relative_to(root)}:{start + 1}: unclosed code fence"
                )
                break
            blocks += 1
            command_id: str | None = None
            if language in _SHELL_LANGUAGES:
                directive = None
                probe = start - 1
                while probe >= 0 and start - probe <= 3 and not lines[probe].strip():
                    probe -= 1
                if probe >= 0:
                    directive = _DIRECTIVE.match(lines[probe].strip())
                if directive is None:
                    errors.append(
                        f"{path.relative_to(root)}:{start + 1}: shell block has no docs-check directive"
                    )
                elif directive.group(1) == "command":
                    command_id = directive.group(2)
                    if command_id not in commands:
                        errors.append(
                            f"{path.relative_to(root)}:{start + 1}: unknown docs command {command_id}"
                        )
                    elif command_id in referenced:
                        errors.append(
                            f"{path.relative_to(root)}:{start + 1}: docs command is referenced by multiple blocks: {command_id}"
                        )
                    else:
                        referenced.add(command_id)
                elif directive.group(2) is not None:
                    errors.append(
                        f"{path.relative_to(root)}:{start + 1}: illustrative block must not name a command"
                    )
            payload = "\n".join(content)
            if (
                command_id in commands
                and sha256_bytes(payload.encode("utf-8"))
                != commands[command_id]["block_sha256"]
            ):
                errors.append(
                    f"{path.relative_to(root)}:{start + 1}: shell block differs from docs command {command_id}"
                )
            try:
                if language == "json":
                    load_json_bytes(payload.encode("utf-8"), f"{path}:{start + 1}")
                elif language == "toml":
                    tomllib.loads(payload)
                elif language in {"python", "py"}:
                    compile(payload, f"{path}:{start + 1}", "exec")
            except (ReleaseError, tomllib.TOMLDecodeError, SyntaxError) as error:
                errors.append(
                    f"{path.relative_to(root)}:{start + 1}: invalid {language} block: {error}"
                )
            index += 1
    if errors:
        raise ReleaseError("; ".join(errors[:30]))
    return blocks, referenced


def _validate_commands(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ReleaseError("documentation command manifest is empty")
    result: dict[str, dict[str, Any]] = {}
    for command in value:
        if not isinstance(command, dict):
            raise ReleaseError("documentation command entry is not an object")
        has_steps = "steps" in command
        expected_keys = (
            {"id", "block_sha256", "mode", "cwd", "steps"}
            if has_steps
            else {
                "id",
                "block_sha256",
                "mode",
                "cwd",
                "argv",
                "expected_exit",
            }
        )
        if set(command) != expected_keys:
            raise ReleaseError(
                f"documentation command has an unexpected shape: {command.get('id')}"
            )
        identifier = command.get("id")
        block_digest = command.get("block_sha256")
        mode = command.get("mode")
        cwd = command.get("cwd")
        if (
            not isinstance(identifier, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9._-]*", identifier) is None
            or identifier in result
            or not isinstance(block_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", block_digest) is None
            or mode not in {"local", "installed-candidate", "live"}
            or not isinstance(cwd, str)
            or not cwd
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in cwd)
        ):
            raise ReleaseError(
                f"documentation command identity, mode, cwd, or block binding is invalid: {identifier}"
            )
        steps = (
            command.get("steps")
            if has_steps
            else [
                {
                    "argv": command.get("argv"),
                    "expected_exit": command.get("expected_exit"),
                }
            ]
        )
        if not isinstance(steps, list) or not steps:
            raise ReleaseError(
                f"documentation command has no executable steps: {identifier}"
            )
        for step in steps:
            if not isinstance(step, dict) or set(step) != {"argv", "expected_exit"}:
                raise ReleaseError(
                    f"documentation command step has an unexpected shape: {identifier}"
                )
            argv = step.get("argv")
            expected_exit = step.get("expected_exit")
            if (
                not isinstance(argv, list)
                or not argv
                or not all(
                    isinstance(item, str)
                    and item
                    and len(item.encode("utf-8")) <= 4096
                    and not any(
                        ord(character) < 0x20 or ord(character) == 0x7F
                        for character in item
                    )
                    for item in argv
                )
                or not isinstance(expected_exit, int)
                or isinstance(expected_exit, bool)
                or expected_exit < 0
                or expected_exit > 255
            ):
                raise ReleaseError(
                    f"documentation command argv or expected exit is invalid: {identifier}"
                )
        result[identifier] = command
    return result


def _expand(value: str, variables: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in variables:
            raise ReleaseError(f"documentation command variable is not defined: {key}")
        return variables[key]

    expanded = re.sub(r"\$\{([A-Z0-9_]+)\}", replace, value)
    if len(expanded.encode("utf-8")) > 4096 or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in expanded
    ):
        raise ReleaseError(
            "expanded documentation command value is invalid or unbounded"
        )
    return expanded


def _execute(
    root: Path,
    commands: list[dict[str, Any]],
    modes: set[str],
    variables: dict[str, str],
) -> tuple[int, int]:
    executed = 0
    failed = 0
    for command in commands:
        if command.get("mode") not in modes:
            continue
        cwd_value = _expand(command.get("cwd", "."), variables)
        cwd = Path(cwd_value)
        if cwd_value == ".":
            cwd = root
        elif not cwd.is_absolute():
            cwd = resolve_beneath(root, cwd_value)
        steps = command.get("steps")
        if steps is None:
            steps = [
                {
                    "argv": command.get("argv"),
                    "expected_exit": command.get("expected_exit", 0),
                }
            ]
        if not isinstance(steps, list) or not steps:
            raise ReleaseError(
                f"documentation command {command.get('id')} has no executable steps"
            )
        for step in steps:
            argv = step.get("argv")
            if (
                not isinstance(argv, list)
                or not argv
                or not all(isinstance(item, str) for item in argv)
            ):
                raise ReleaseError(
                    f"documentation command {command.get('id')} argv is invalid"
                )
            expanded = [_expand(item, variables) for item in argv]
            environment = os.environ.copy()
            environment.update(
                {"TZ": "UTC", "LC_ALL": "C", "LANG": "C", "NO_COLOR": "1"}
            )
            result = run_bounded(expanded, cwd=cwd, env=environment, timeout=300)
            executed += 1
            if result.returncode != step.get("expected_exit", 0):
                failed += 1
                raise ReleaseError(
                    process_failure_summary(
                        result, f"documentation command {command['id']}"
                    )
                )
    return executed, failed


def main() -> int:
    arguments = parse_arguments()
    root = arguments.root.resolve()
    manifest = load_json(root / "docs/site-manifest.v1.json")
    command_manifest = load_json(root / "docs/commands.v1.json")
    expected_manifest_keys = {
        "schema_version",
        "product_version",
        "context_abi",
        "version_selectors",
        "include",
        "assets",
        "required_pages",
    }
    if (
        not isinstance(manifest, dict)
        or set(manifest) != expected_manifest_keys
        or manifest.get("schema_version") != "cigar.docs-site.v1"
        or not isinstance(command_manifest, dict)
        or set(command_manifest) != {"schema_version", "commands"}
        or command_manifest.get("schema_version") != "cigar.docs-commands.v1"
    ):
        raise ReleaseError("unsupported documentation manifest")
    commands = _validate_commands(command_manifest.get("commands"))
    if manifest.get("version_selectors") != ["0.1", "latest"]:
        raise ReleaseError("documentation version selectors are missing or stale")
    files = _published_files(root, manifest)
    published = {path.resolve() for path in files}
    required_pages = manifest.get("required_pages")
    if (
        not isinstance(required_pages, list)
        or not required_pages
        or not all(isinstance(value, str) and value for value in required_pages)
        or len(set(required_pages)) != len(required_pages)
    ):
        raise ReleaseError("required documentation page inventory is invalid")
    for required in required_pages:
        if resolve_beneath(root, required) not in published:
            raise ReleaseError(
                f"required documentation page is not published: {required}"
            )
    assets = _site_assets(root, manifest)
    links, referenced_assets = _check_links(root, files, assets)
    if referenced_assets != assets:
        raise ReleaseError(
            f"documentation asset allowlist contains unreferenced entries: {sorted(assets - referenced_assets)}"
        )
    blocks, referenced = _check_blocks(root, files, commands)
    unreferenced = set(commands) - referenced
    if unreferenced:
        raise ReleaseError(
            f"documentation commands are not referenced by a published page: {sorted(unreferenced)}"
        )
    modes = set(arguments.execute)
    if arguments.execute_local:
        modes.add("local")
    variables: dict[str, str] = {}
    if arguments.variables is not None:
        loaded = load_json(arguments.variables.resolve())
        if not isinstance(loaded, dict) or not all(
            isinstance(key, str)
            and re.fullmatch(r"[A-Z][A-Z0-9_]*", key) is not None
            and isinstance(value, str)
            and value
            and len(value.encode("utf-8")) <= 4096
            and not any(
                ord(character) < 0x20 or ord(character) == 0x7F for character in value
            )
            for key, value in loaded.items()
        ):
            raise ReleaseError(
                "documentation command variables must be a string mapping"
            )
        variables = loaded
    executed, failed = _execute(root, list(commands.values()), modes, variables)
    report = {
        "schema_version": "cigar.docs-check.v1",
        "status": "passed",
        "product_version": manifest["product_version"],
        "context_abi": manifest["context_abi"],
        "pages": len(files),
        "links": links,
        "code_blocks": blocks,
        "declared_commands": len(commands),
        "executed_commands": executed,
        "failed_commands": failed,
        "executed_modes": sorted(modes),
    }
    if arguments.report is not None:
        report_path = arguments.report.resolve()
        inputs = [root / "docs/site-manifest.v1.json", root / "docs/commands.v1.json"]
        if arguments.variables is not None:
            inputs.append(arguments.variables)
        require_distinct_output(report_path, inputs, "documentation report")
        write_json(report_path, report)
    print(
        f"documentation passed: {len(files)} pages, {links} links, {blocks} code blocks, {executed} executed command steps"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.TimeoutExpired, ReleaseError) as error:
        raise SystemExit(f"documentation check failed: {error}") from error
