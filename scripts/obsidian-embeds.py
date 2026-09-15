#!/usr/bin/env python3
"""Convert Obsidian embeds (![[page]] / ![[page#Header]]) to Hugo embed-section shortcodes."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from pathlib import Path

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp"}
SKIP_DIRS = {".git", ".venv", ".obsidian", "node_modules"}
EMBED_RE = re.compile(r"!\[\[([^\[\]]+)\]\]")
FENCE_RE = re.compile(r"^([ \t]*)(`{3,}|~{3,})")


class EmbedError(Exception):
    pass


def hugo_slug(text: str) -> str:
    """Match Hugo's default Goldmark github auto-heading IDs."""
    out = []
    for ch in text.strip():
        if ch == "-" or ch == " ":
            out.append("-")
        elif ch == "_" or ch.isalnum():
            out.append(ch.lower())
    return "".join(out)


def iter_markdown(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            if name.endswith(".md"):
                yield Path(dirpath) / name


def index_pages(content_dir: Path) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    for path in iter_markdown(content_dir):
        rel = path.relative_to(content_dir).as_posix()
        page = rel[: -len(".md")] if rel.lower().endswith(".md") else rel
        index.setdefault(path.stem, []).append(page)
    return index


def in_inline_code(line: str, index: int) -> bool:
    return line[:index].count("`") % 2 == 1


def resolve_page(stem: str, pages: dict[str, list[str]], source: Path, raw: str) -> str:
    matches = pages.get(stem, [])
    if not matches:
        raise EmbedError(f"{source}: {raw}: no markdown file named '{stem}.md' under content/")
    if len(matches) > 1:
        listed = ", ".join(matches)
        raise EmbedError(
            f"{source}: {raw}: multiple markdown files named '{stem}.md': {listed}"
        )
    return matches[0]


def shortcode_for(inner: str, pages: dict[str, list[str]], source: Path, raw: str) -> str | None:
    if "|" in inner:
        return None
    name, sep, header = inner.partition("#")
    name = name.strip()
    header = header.strip() if sep else ""
    if not name or header.startswith("^"):
        return None
    ext = Path(name).suffix.lower()
    if ext in IMAGE_EXTS:
        return None
    stem = name[: -len(".md")] if name.lower().endswith(".md") else name
    page = resolve_page(stem, pages, source, raw)
    if header:
        return f'{{{{< embed-section page="{page}" header="{hugo_slug(header)}" >}}}}'
    return f'{{{{< embed-section page="{page}" >}}}}'


def convert_line(line: str, pages: dict[str, list[str]], source: Path) -> tuple[str, list[tuple[str, str]]]:
    subs: list[tuple[str, str]] = []

    def repl(match: re.Match[str]) -> str:
        if in_inline_code(line, match.start()):
            return match.group(0)
        raw = match.group(0)
        replacement = shortcode_for(match.group(1), pages, source, raw)
        if replacement is None:
            return raw
        subs.append((raw, replacement))
        return replacement

    return EMBED_RE.sub(repl, line), subs


def convert_text(text: str, pages: dict[str, list[str]], source: Path) -> tuple[str, list[tuple[str, str]]]:
    out: list[str] = []
    all_subs: list[tuple[str, str]] = []
    fence: tuple[str, int] | None = None
    for line in text.splitlines(keepends=True):
        body = line.splitlines()[0] if line else line
        fence_match = FENCE_RE.match(body)
        if fence:
            out.append(line)
            if (
                fence_match
                and fence_match.group(2)[0] == fence[0]
                and len(fence_match.group(2)) >= fence[1]
            ):
                fence = None
            continue
        if fence_match:
            fence = (fence_match.group(2)[0], len(fence_match.group(2)))
            out.append(line)
            continue
        converted, subs = convert_line(line, pages, source)
        out.append(converted)
        all_subs.extend(subs)
    return "".join(out), all_subs


def die_if_bad_output_dir(content_dir: Path, output_dir: Path) -> None:
    content_dir = content_dir.resolve()
    output_dir = output_dir.resolve()
    if output_dir == content_dir or content_dir in output_dir.parents:
        raise SystemExit("error: --output-dir must be outside the content directory")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("content", type=Path, help="Path to Hugo content/ (Obsidian vault)")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print substitutions without writing files",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Copy content/ here and rewrite the copy (leave the vault unchanged)",
    )
    args = parser.parse_args()

    content_dir = args.content.resolve()
    if not content_dir.is_dir():
        print(f"error: not a directory: {content_dir}", file=sys.stderr)
        return 1

    pages = index_pages(content_dir)
    root = content_dir
    if args.output_dir and not args.dry_run:
        die_if_bad_output_dir(content_dir, args.output_dir)
        output_dir = args.output_dir.resolve()
        if output_dir.exists():
            shutil.rmtree(output_dir)
        shutil.copytree(content_dir, output_dir, symlinks=True)
        root = output_dir

    planned: list[tuple[Path, str, list[tuple[str, str]]]] = []
    errors: list[str] = []
    for path in iter_markdown(root):
        text = path.read_text(encoding="utf-8")
        try:
            converted, subs = convert_text(text, pages, path)
        except EmbedError as exc:
            errors.append(str(exc))
            continue
        if subs:
            planned.append((path, converted, subs))

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    cwd = Path.cwd()
    for path, converted, subs in planned:
        try:
            print(path.relative_to(cwd))
        except ValueError:
            print(path)
        for raw, replacement in subs:
            print(f"  {raw} -> {replacement}")
        if not args.dry_run:
            path.write_text(converted, encoding="utf-8")

    return 0


if __name__ == "__main__":
    sys.exit(main())
