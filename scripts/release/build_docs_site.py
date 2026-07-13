#!/usr/bin/env python3
"""Build the deterministic, dependency-free CIGAR documentation site from its published manifest."""

from __future__ import annotations

import argparse
import html
import os
import re
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any

from release_lib import (
    ReleaseError,
    expand_files,
    load_json,
    repo_root,
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
    parser.add_argument("--check", action="store_true")
    return parser.parse_args()


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
        with tempfile.TemporaryDirectory(prefix="cigar-docs-site-") as directory:
            site = build(root, Path(directory))
    else:
        if arguments.out is None:
            raise ReleaseError("--out is required unless --check is used")
        site = build(root, arguments.out.resolve())
    print(f"generated deterministic documentation site with {len(site['pages'])} pages")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as error:
        raise SystemExit(f"documentation site build failed: {error}") from error
