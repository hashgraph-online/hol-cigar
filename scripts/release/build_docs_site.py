#!/usr/bin/env python3
"""Build the deterministic, dependency-free CIGAR documentation site from its published manifest."""

from __future__ import annotations

import argparse
import hashlib
import html
import os
import re
import stat
import tempfile
import unicodedata
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evidence_workspace import (
    EvidenceLimits,
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    safe_relative_path as safe_evidence_path,
)
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    expand_files,
    load_json,
    repo_root,
    require_distinct_output,
    resolve_beneath,
    safe_relative_path,
    write_bytes,
    write_json,
)


_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_FENCE = re.compile(r"^```([A-Za-z0-9_+,-]*)\s*$")
_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument("--out", type=Path)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="absolute external documentation workspace (or set CIGAR_EVIDENCE_DIR)",
    )
    parser.add_argument("--check", action="store_true")
    return parser.parse_args()


def selected_evidence_directory(arguments: argparse.Namespace) -> Path | None:
    """Select one protected output root without resolving untrusted components."""

    argument_value = arguments.evidence_dir
    environment_value = os.environ.get("CIGAR_EVIDENCE_DIR")
    if argument_value is not None and environment_value:
        if Path(argument_value) != Path(environment_value):
            raise ReleaseError(
                "--evidence-dir conflicts with CIGAR_EVIDENCE_DIR; provide one location"
            )
    raw = argument_value if argument_value is not None else environment_value
    if raw is None or os.fspath(raw) == "":
        return None
    selected = Path(raw)
    if not selected.is_absolute():
        raise ReleaseError("evidence directory must be an absolute path")
    return selected


def _documentation_inputs(root: Path) -> list[Path]:
    """Return every repository file consumed by the site builder."""

    manifest_path = root / "docs/site-manifest.v1.json"
    manifest = load_json(manifest_path)
    includes = manifest.get("include") if isinstance(manifest, dict) else None
    assets = manifest.get("assets") if isinstance(manifest, dict) else None
    if not isinstance(includes, list) or not all(
        isinstance(value, str) for value in includes
    ):
        raise ReleaseError("documentation include manifest is invalid")
    if not isinstance(assets, list) or not all(
        isinstance(value, str) for value in assets
    ):
        raise ReleaseError("documentation asset allowlist is invalid")
    inputs = {manifest_path}
    inputs.update(path for _, path in expand_files(root, includes, []))
    inputs.update(resolve_beneath(root, safe_relative_path(value)) for value in assets)
    return sorted(inputs, key=lambda path: path.as_posix())


def _portable_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


@dataclass(frozen=True)
class _StagedFile:
    relative: str
    source: Path
    sha256: str
    bytes: int
    payload: bytes


_STAGED_READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_STABLE_FILE_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_uid",
    "st_nlink",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


def _read_stable_staged_file(
    source: Path,
    initial: os.stat_result,
    maximum: int,
    label: str,
) -> bytes:
    """Read one owner-controlled file and prove its identity stayed stable."""

    try:
        file_fd = os.open(source, _STAGED_READ_FLAGS)
    except OSError as error:
        raise ReleaseError(
            f"cannot securely open staged documentation file {label}: {error}"
        ) from error
    try:
        before = os.fstat(file_fd)
        if any(
            getattr(initial, field) != getattr(before, field)
            for field in _STABLE_FILE_FIELDS
        ):
            raise ReleaseError(
                f"staged documentation file changed before validation: {label}"
            )
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum
        ):
            raise ReleaseError(
                f"staged documentation file is not owner-controlled: {label}"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(file_fd, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ReleaseError(
                    f"staged documentation file exceeds the per-file limit: {label}"
                )
            chunks.append(chunk)
        after = os.fstat(file_fd)
        if any(
            getattr(before, field) != getattr(after, field)
            for field in _STABLE_FILE_FIELDS
        ):
            raise ReleaseError(
                f"staged documentation file changed during validation: {label}"
            )
        payload = b"".join(chunks)
        if len(payload) != before.st_size:
            raise ReleaseError(
                f"staged documentation file size changed during validation: {label}"
            )
        return payload
    except OSError as error:
        raise ReleaseError(
            f"cannot read staged documentation file {label}: {error}"
        ) from error
    finally:
        os.close(file_fd)


def _verified_staged_payload(staged: _StagedFile, maximum: int) -> bytes:
    """Reread and compare one file immediately before destination publication."""

    try:
        current = os.lstat(staged.source)
    except OSError as error:
        raise ReleaseError(
            f"cannot inspect validated staged file {staged.relative}: {error}"
        ) from error
    payload = _read_stable_staged_file(
        staged.source,
        current,
        maximum,
        staged.relative,
    )
    if (
        len(payload) != staged.bytes
        or hashlib.sha256(payload).hexdigest() != staged.sha256
    ):
        raise ReleaseError(
            f"staged documentation file changed after validation: {staged.relative}"
        )
    return payload


def _validated_stage_files(
    stage: Path,
    site: dict[str, Any],
) -> list[_StagedFile]:
    """Validate the complete staged site before any destination is published."""

    stage = stage.resolve(strict=True)
    limits = EvidenceLimits()
    limits.validate()
    files: list[_StagedFile] = []
    aliases: set[str] = set()
    directory_count = 1
    total_bytes = 0

    def scan(directory: Path, relative: str, depth: int) -> None:
        nonlocal directory_count, total_bytes
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            raise ReleaseError(
                f"cannot enumerate staged documentation site: {error}"
            ) from error
        for entry in entries:
            child_relative = f"{relative}/{entry.name}" if relative else entry.name
            parts = safe_evidence_path(
                child_relative,
                max_depth=limits.max_path_depth,
            )
            child_relative = "/".join(parts)
            portable = _portable_key(child_relative)
            if portable in aliases:
                raise ReleaseError(
                    f"staged documentation site has a portable path collision: {child_relative}"
                )
            aliases.add(portable)
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise ReleaseError(
                    f"cannot inspect staged documentation entry {child_relative}: {error}"
                ) from error
            if stat.S_ISDIR(metadata.st_mode):
                if depth >= limits.max_path_depth:
                    raise ReleaseError(
                        "staged documentation directory depth limit exceeded"
                    )
                if (
                    metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) & 0o022
                ):
                    raise ReleaseError(
                        f"staged documentation directory is not owner-controlled: {child_relative}"
                    )
                directory_count += 1
                if directory_count > limits.max_directories:
                    raise ReleaseError("staged documentation directory limit exceeded")
                scan(Path(entry.path), child_relative, depth + 1)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ReleaseError(
                    f"staged documentation entry is not a regular file: {child_relative}"
                )
            if (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o022
                or metadata.st_nlink != 1
            ):
                raise ReleaseError(
                    f"staged documentation file is not owner-controlled: {child_relative}"
                )
            if metadata.st_size < 0 or metadata.st_size > limits.max_file_bytes:
                raise ReleaseError(
                    f"staged documentation file exceeds the per-file limit: {child_relative}"
                )
            source = Path(entry.path)
            payload = _read_stable_staged_file(
                source,
                metadata,
                limits.max_file_bytes,
                child_relative,
            )
            total_bytes += len(payload)
            if len(files) >= limits.max_files:
                raise ReleaseError("staged documentation file-count limit exceeded")
            if total_bytes > limits.max_total_bytes:
                raise ReleaseError("staged documentation total-byte limit exceeded")
            files.append(
                _StagedFile(
                    relative=child_relative,
                    source=source,
                    sha256=hashlib.sha256(payload).hexdigest(),
                    bytes=len(payload),
                    payload=payload,
                )
            )

    scan(stage, "", 0)
    by_relative = {entry.relative: entry for entry in files}
    expected_site_keys = {
        "schema_version",
        "product_version",
        "context_abi",
        "version_selectors",
        "pages",
        "asset_count",
    }
    if (
        not isinstance(site, dict)
        or set(site) != expected_site_keys
        or site.get("schema_version") != "cigar.generated-docs-site.v1"
        or not isinstance(site.get("pages"), list)
        or not isinstance(site.get("asset_count"), int)
        or isinstance(site.get("asset_count"), bool)
        or site["asset_count"] < 1
    ):
        raise ReleaseError("generated documentation site inventory is invalid")
    page_outputs: set[str] = set()
    for page in site["pages"]:
        if not isinstance(page, dict) or set(page) != {"source", "output", "title"}:
            raise ReleaseError("generated documentation page inventory is invalid")
        output = page.get("output")
        if not isinstance(output, str) or not output:
            raise ReleaseError("generated documentation page output is invalid")
        output = "/".join(safe_evidence_path(output))
        if output in page_outputs:
            raise ReleaseError("generated documentation page outputs are duplicated")
        page_outputs.add(output)
        staged = by_relative.get(output)
        if staged is None or not staged.payload.startswith(b"<!doctype html>\n"):
            raise ReleaseError(f"generated documentation page is invalid: {output}")
    required = {
        "index.html",
        "assets/style.css",
        "site-manifest.json",
        *page_outputs,
    }
    if not required.issubset(by_relative):
        raise ReleaseError(
            f"generated documentation site is incomplete: {sorted(required - set(by_relative))}"
        )
    if len(files) != len(page_outputs) + site["asset_count"] + 2:
        raise ReleaseError(
            "generated documentation site file inventory is inconsistent"
        )
    if by_relative["index.html"].payload != by_relative["docs/site/index.html"].payload:
        raise ReleaseError("generated documentation landing page is inconsistent")
    if by_relative["site-manifest.json"].payload != canonical_json_bytes(site):
        raise ReleaseError("generated documentation site manifest is not canonical")
    return sorted(files, key=lambda item: item.relative.encode("utf-8"))


class DocsSiteOutput:
    """One protected external or legacy development site destination."""

    def __init__(
        self,
        *,
        direct: Path | None,
        workspace: EvidenceWorkspace | None,
        prefix: str | None,
        inputs: list[Path],
    ) -> None:
        self.direct = direct
        self.workspace = workspace
        self.prefix = prefix
        self.inputs = inputs

    @classmethod
    def open(
        cls,
        arguments: argparse.Namespace,
        root: Path,
        inputs: list[Path],
    ) -> DocsSiteOutput:
        if arguments.out is None:
            raise ReleaseError("--out is required unless --check is used")
        selected = selected_evidence_directory(arguments)
        if selected is None:
            direct = arguments.out.resolve()
            require_distinct_output(direct, inputs, "documentation site")
            return cls(
                direct=direct,
                workspace=None,
                prefix=None,
                inputs=inputs,
            )

        if arguments.out.is_absolute():
            raise ReleaseError(
                "--out must be relative when an evidence directory is selected"
            )
        parts = safe_evidence_path(os.fspath(arguments.out))
        tentative = selected.joinpath(*parts)
        require_distinct_output(tentative, inputs, "documentation site")
        workspace = EvidenceWorkspace.create(selected, repository_root=root)
        try:
            require_distinct_output(
                workspace.root.joinpath(*parts),
                inputs,
                "documentation site",
            )
            return cls(
                direct=None,
                workspace=workspace,
                prefix="/".join(parts),
                inputs=inputs,
            )
        except BaseException:
            workspace.close()
            raise

    def publish(self, stage: Path, site: dict[str, Any]) -> None:
        files = _validated_stage_files(stage, site)
        maximum = (
            self.workspace.limits.max_file_bytes
            if self.workspace
            else EvidenceLimits().max_file_bytes
        )
        verified = [
            (staged, _verified_staged_payload(staged, maximum)) for staged in files
        ]
        if self.workspace is None:
            assert self.direct is not None
            try:
                self.direct.mkdir(parents=True, exist_ok=True)
            except OSError as error:
                raise ReleaseError(
                    f"cannot create documentation output directory: {error}"
                ) from error
            if not self.direct.is_dir() or any(self.direct.iterdir()):
                raise ReleaseError("documentation output directory must be empty")
            destinations = [
                self.direct.joinpath(*staged.relative.split("/"))
                for staged, _ in verified
            ]
            for destination in destinations:
                require_distinct_output(destination, self.inputs, "documentation site")
            for (_, payload), destination in zip(verified, destinations, strict=True):
                write_bytes(destination, payload)
            return

        assert self.prefix is not None
        destinations = [f"{self.prefix}/{staged.relative}" for staged, _ in verified]
        for destination in destinations:
            require_distinct_output(
                self.workspace.root.joinpath(*destination.split("/")),
                self.inputs,
                "documentation site",
            )
        for (staged, _), destination in zip(verified, destinations, strict=True):
            self.workspace.attach_file(
                staged.source,
                destination,
                expected_sha256=staged.sha256,
                expected_bytes=staged.bytes,
            )

    def close(self) -> None:
        if self.workspace is not None:
            self.workspace.close()


def _slug(text: str) -> str:
    value = re.sub(r"<[^>]+>", "", text).strip().lower()
    value = re.sub(r"[^\w\- ]", "", value, flags=re.UNICODE)
    return re.sub(r"[\s-]+", "-", value).strip("-")


def _published(root: Path, manifest: dict[str, Any]) -> list[tuple[str, Path]]:
    includes = manifest.get("include")
    if not isinstance(includes, list) or not all(
        isinstance(value, str) for value in includes
    ):
        raise ReleaseError("documentation include manifest is invalid")
    files = [
        (relative, path)
        for relative, path in expand_files(root, includes, [])
        if relative.endswith(".md")
    ]
    if not files:
        raise ReleaseError("documentation manifest contains no Markdown")
    return files


def _output_relative(source_relative: str) -> str:
    return str(Path(source_relative).with_suffix(".html")).replace(os.sep, "/")


def _inline(
    value: str,
    source_relative: str,
    published: set[str],
    allowed_assets: set[str],
    linked_assets: set[str],
    root: Path,
) -> str:
    output: list[str] = []
    position = 0
    for match in _LINK.finditer(value):
        output.append(html.escape(value[position : match.start()]))
        label = html.escape(match.group(1))
        target = match.group(2).strip("<>")
        if target.startswith(("http://", "https://", "mailto:", "data:")):
            href = target
        else:
            path_part, separator, fragment = urllib.parse.unquote(target).partition("#")
            source_path = Path(source_relative)
            if path_part:
                resolved_relative = (source_path.parent / path_part).as_posix()
                normalized = Path(os.path.normpath(resolved_relative)).as_posix()
            else:
                normalized = source_relative
            resolve_beneath(root, normalized)
            if normalized in published:
                rewritten = (
                    Path(path_part).with_suffix(".html").as_posix() if path_part else ""
                )
                href = rewritten + (f"#{fragment}" if separator else "")
            else:
                if normalized not in allowed_assets:
                    raise ReleaseError(
                        f"documentation link is not a published page or allowlisted asset: {normalized}"
                    )
                href = target
                if path_part:
                    linked_assets.add(normalized)
        output.append(f'<a href="{html.escape(href, quote=True)}">{label}</a>')
        position = match.end()
    output.append(html.escape(value[position:]))
    rendered = "".join(output)
    rendered = re.sub(
        r"`([^`]+)`",
        lambda match: f"<code>{html.escape(html.unescape(match.group(1)))}</code>",
        rendered,
    )
    rendered = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", rendered)
    return rendered


def _render_markdown(
    text: str,
    source_relative: str,
    published: set[str],
    allowed_assets: set[str],
    linked_assets: set[str],
    root: Path,
) -> tuple[str, str]:
    lines = text.splitlines()
    body: list[str] = []
    title = "CIGAR documentation"
    paragraph: list[str] = []
    list_open = False
    heading_counts: dict[str, int] = {}

    def close_paragraph() -> None:
        if paragraph:
            body.append(
                f"<p>{_inline(' '.join(part.strip() for part in paragraph), source_relative, published, allowed_assets, linked_assets, root)}</p>"
            )
            paragraph.clear()

    def close_list() -> None:
        nonlocal list_open
        if list_open:
            body.append("</ul>")
            list_open = False

    index = 0
    while index < len(lines):
        line = lines[index]
        fence = _FENCE.match(line)
        if fence is not None:
            close_paragraph()
            close_list()
            language = fence.group(1).split(",", 1)[0]
            index += 1
            code: list[str] = []
            while index < len(lines) and lines[index] != "```":
                code.append(lines[index])
                index += 1
            if index == len(lines):
                raise ReleaseError(f"unclosed code fence in {source_relative}")
            body.append(
                f'<pre><code class="language-{html.escape(language, quote=True)}">{html.escape(chr(10).join(code))}</code></pre>'
            )
            index += 1
            continue
        heading = _HEADING.match(line)
        if heading is not None:
            close_paragraph()
            close_list()
            level = len(heading.group(1))
            heading_text = heading.group(2)
            base = _slug(heading_text)
            count = heading_counts.get(base, 0)
            heading_counts[base] = count + 1
            anchor = base if count == 0 else f"{base}-{count}"
            if level == 1:
                title = heading_text
            body.append(
                f'<h{level} id="{html.escape(anchor, quote=True)}">'
                f"{_inline(heading_text, source_relative, published, allowed_assets, linked_assets, root)}</h{level}>"
            )
            index += 1
            continue
        if line.startswith("- "):
            close_paragraph()
            if not list_open:
                body.append("<ul>")
                list_open = True
            body.append(
                f"<li>{_inline(line[2:], source_relative, published, allowed_assets, linked_assets, root)}</li>"
            )
            index += 1
            continue
        if not line.strip():
            close_paragraph()
            close_list()
        elif line.lstrip().startswith("<!--"):
            close_paragraph()
        else:
            paragraph.append(line)
        index += 1
    close_paragraph()
    close_list()
    return title, "\n".join(body)


def _page(title: str, body: str, current: Path, output: Path, version: str) -> bytes:
    style = os.path.relpath(output / "assets/style.css", current.parent).replace(
        os.sep, "/"
    )
    home = os.path.relpath(output / "docs/site/index.html", current.parent).replace(
        os.sep, "/"
    )
    quickstart = os.path.relpath(
        output / "docs/guides/quickstart.html", current.parent
    ).replace(os.sep, "/")
    operations = os.path.relpath(
        output / "docs/operations/index.html", current.parent
    ).replace(os.sep, "/")
    content = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="generator" content="cigar-docs-v1"><title>{html.escape(title)} · CIGAR</title>
<link rel="stylesheet" href="{html.escape(style, quote=True)}"></head><body>
<header><a href="{home}">CIGAR docs</a><nav><a href="{quickstart}">Quickstart</a> <a href="{operations}">Operations</a></nav><span>v{html.escape(version)}</span></header>
<main>{body}</main><footer>Context ABI cigar.context.v1</footer></body></html>
"""
    return content.encode("utf-8")


def build(root: Path, output: Path) -> dict[str, Any]:
    manifest = load_json(root / "docs/site-manifest.v1.json")
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
    ):
        raise ReleaseError("unsupported documentation site manifest")
    source_files = _published(root, manifest)
    published = {relative for relative, _ in source_files}
    assets_value = manifest.get("assets")
    if (
        not isinstance(assets_value, list)
        or not assets_value
        or not all(isinstance(value, str) and value for value in assets_value)
        or len(set(assets_value)) != len(assets_value)
    ):
        raise ReleaseError("documentation asset allowlist is invalid")
    allowed_assets: set[str] = set()
    for relative in assets_value:
        relative = safe_relative_path(relative)
        asset = resolve_beneath(root, relative)
        if not asset.is_file() or asset.suffix.lower() == ".md":
            raise ReleaseError(
                f"documentation asset is not an allowed regular non-Markdown file: {relative}"
            )
        allowed_assets.add(relative)
    required_pages = manifest.get("required_pages")
    if (
        not isinstance(required_pages, list)
        or not required_pages
        or not all(isinstance(value, str) and value for value in required_pages)
        or len(set(required_pages)) != len(required_pages)
    ):
        raise ReleaseError("required documentation page inventory is invalid")
    if not set(required_pages).issubset(published):
        raise ReleaseError(
            f"required documentation pages are not published: {sorted(set(required_pages) - published)}"
        )
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ReleaseError("documentation output directory must be empty")
    linked_assets: set[str] = set()
    pages: list[dict[str, str]] = []
    for relative, source in source_files:
        target_relative = _output_relative(relative)
        target = output / target_relative
        title, body = _render_markdown(
            source.read_text(encoding="utf-8"),
            relative,
            published,
            allowed_assets,
            linked_assets,
            root,
        )
        write_bytes(
            target, _page(title, body, target, output, manifest["product_version"])
        )
        pages.append({"source": relative, "output": target_relative, "title": title})
    if linked_assets != allowed_assets:
        raise ReleaseError(
            f"documentation asset allowlist contains unreferenced entries: {sorted(allowed_assets - linked_assets)}"
        )
    for relative in sorted(linked_assets):
        if relative in published:
            continue
        source = resolve_beneath(root, relative)
        if source.is_dir():
            continue
        write_bytes(output / relative, source.read_bytes())
    landing = output / "docs/site/index.html"
    if not landing.is_file():
        raise ReleaseError("documentation landing page was not generated")
    write_bytes(output / "index.html", landing.read_bytes())
    css = b"""*{box-sizing:border-box}body{margin:0;font:16px/1.55 system-ui,sans-serif;color:#1f2933;background:#fbfaf7}header,main,footer{max-width:70rem;margin:auto;padding:1rem 2rem}header{display:flex;gap:1.2rem;align-items:center;border-bottom:1px solid #d8d3c8}header nav{flex:1}a{color:#7a3418}pre{overflow:auto;padding:1rem;background:#1f2933;color:#f8fafc;border-radius:.4rem}code{font-family:ui-monospace,monospace}main{min-height:70vh}footer{border-top:1px solid #d8d3c8;color:#59636e}h1,h2,h3{line-height:1.2}\n"""
    write_bytes(output / "assets/style.css", css)
    site = {
        "schema_version": "cigar.generated-docs-site.v1",
        "product_version": manifest["product_version"],
        "context_abi": manifest["context_abi"],
        "version_selectors": manifest["version_selectors"],
        "pages": sorted(pages, key=lambda entry: entry["output"]),
        "asset_count": len(linked_assets) + 1,
    }
    write_json(output / "site-manifest.json", site)
    return site


def main() -> int:
    arguments = parse_arguments()
    root = arguments.root.resolve()
    if arguments.check:
        if selected_evidence_directory(arguments) is not None:
            raise ReleaseError("--evidence-dir cannot be used with --check")
        with tempfile.TemporaryDirectory(prefix="cigar-docs-site-") as directory:
            stage = Path(directory).resolve()
            site = build(root, stage)
            _validated_stage_files(stage, site)
        print(
            f"generated deterministic documentation site with {len(site['pages'])} pages"
        )
        return 0

    inputs = _documentation_inputs(root)
    output = DocsSiteOutput.open(arguments, root, inputs)
    try:
        with tempfile.TemporaryDirectory(prefix="cigar-docs-site-") as directory:
            stage = Path(directory).resolve()
            site = build(root, stage)
            output.publish(stage, site)
    finally:
        output.close()
    print(f"generated deterministic documentation site with {len(site['pages'])} pages")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceWorkspaceError, OSError, ReleaseError) as error:
        raise SystemExit(f"documentation site build failed: {error}") from error
