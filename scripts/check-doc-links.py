#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
# SPDX-License-Identifier: MIT

"""Verify that every relative Markdown link and #anchor in the documentation resolves.

Run it with `make check-doc-links`, or directly:

    python3 scripts/check-doc-links.py [--quiet] [paths...]

Three failure modes are reported:

  missing file   a relative link whose target does not exist on disk
  dead anchor    a #fragment that matches no heading in the target file
  pinned version a pkg.go.dev URL that names a module version (see below)

Anchors are the ones that rot silently. Manually numbered headings made this worse — the anchors
README.md used for docs/README.md drifted out of sync with the section numbers and pointed at the
wrong sections — and any restructuring of the documentation tree can reintroduce the same class of
breakage without a single broken build.

Only relative links are checked. External http(s) targets are skipped deliberately: reaching the
network would make the check slow, flaky and dependent on third-party uptime.

The one exception is a *shape* check on pkg.go.dev URLs, which needs no network. A URL that pins
a module version — https://pkg.go.dev/k8s.io/kms@v0.31.3/apis/v2 — freezes at whatever release
happened to be current when it was written, and nothing updates it on a dependency bump. Three
such links had drifted to three different versions (v0.31.3, v0.34.1) while go.mod was on v0.36.3,
in a README, a Go doc comment and the CLI help. Dropping the "@version" makes pkg.go.dev serve the
latest release, which is what a reader following the link wants. Go doc comments are checked too:
they are documentation, and pkg.go.dev renders them.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Repository root, derived from this file's location so the script works from any directory.
REPO = Path(__file__).resolve().parent.parent

# Directories whose Markdown is generated and therefore not hand-maintained. They are still
# *checked*, but they are not walked for extra input paths beyond the defaults below.
DEFAULT_PATHS = [
    Path("README.md"),
    Path("CHANGELOG.md"),
    Path("docs"),
    # scripts/ and tools/ carry their own READMEs that link back into docs/. Leaving them out is
    # how a stale ../../README.md#51-running-the-tests anchor survived the de-numbering pass.
    Path("scripts"),
    Path("tools"),
]

MD_LINK = re.compile(r"\[(?:[^\]]*)\]\(\s*(?P<url>[^)\s]+?)\s*\)")
HEADING = re.compile(r"^#{1,6}\s+(?P<text>.*?)\s*$")
HTML_ANCHOR = re.compile(r'<a\s+(?:id|name)="(?P<id>[^"]+)"')
INLINE_LINK_TEXT = re.compile(r"\[([^\]]*)\]\([^)]*\)")
SKIP_SCHEMES = ("http://", "https://", "mailto:", "tel:", "ftp://")

# A pkg.go.dev URL carrying an "@version" between the module path and the package path. The
# version has to look like a real one (v1.2.3, v0.0.0-2020…-abcdef, v2.0.0-rc4) so that prose
# writing "@<version>" to describe the rule is not itself flagged.
PINNED_PKG_URL = re.compile(r"pkg\.go\.dev/(?P<module>[^@\s)\"]+)@(?P<version>v\d[^/\s)\"]*)")

# Where a pkg.go.dev link can appear. Markdown comes from the paths being checked; Go doc
# comments are added here because they are rendered as documentation too.
GO_SOURCE_PATHS = [Path("cmd"), Path("pkg"), Path("tools"), Path("test")]


def github_slug(text: str) -> str:
    """Reproduce GitHub's heading-to-anchor slug.

    GitHub lowercases, drops every character that is not a word character, space or hyphen, then
    turns each remaining space into a hyphen. Emoji and punctuation vanish but the spaces around
    them do not, which is why "Installation 🔧" anchors as "installation-" and "HSM & TPM guides"
    as "hsm--tpm-guides". Collapsing those runs would silently mismatch real anchors in this repo.
    """
    s = INLINE_LINK_TEXT.sub(r"\1", text.strip()).replace("`", "").lower()
    return re.sub(r"[^\w\s-]", "", s, flags=re.UNICODE).replace(" ", "-")


def anchors_of(path: Path) -> set[str]:
    """Every anchor the given Markdown file exposes."""
    found: set[str] = set()
    seen: dict[str, int] = {}
    in_fence = False

    for line in path.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            # A "#" inside a fenced block is a shell comment, not a heading.
            continue

        if m := HEADING.match(line):
            base = github_slug(m.group("text"))
            # GitHub disambiguates repeated headings with -1, -2, ... suffixes.
            n = seen.get(base, 0)
            seen[base] = n + 1
            found.add(base if n == 0 else f"{base}-{n}")

        found.update(HTML_ANCHOR.findall(line))

    return found


def go_files() -> list[Path]:
    """Every Go source file whose doc comments may carry a pkg.go.dev link."""
    out: list[Path] = []
    for rel in GO_SOURCE_PATHS:
        p = REPO / rel
        if p.is_dir():
            out.extend(sorted(p.rglob("*.go")))
    return out


def pinned_pkg_urls(files: list[Path]) -> list[str]:
    """Report every pkg.go.dev URL that pins a module version."""
    problems: list[str] = []
    for path in files:
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for m in PINNED_PKG_URL.finditer(line):
                here = path.relative_to(REPO)
                problems.append(
                    f"{here}:{n}: pinned version -> pkg.go.dev/{m.group('module')}@{m.group('version')}"
                    f" (drop the @{m.group('version')})"
                )
    return problems


def markdown_files(paths: list[Path]) -> list[Path]:
    out: list[Path] = []
    for rel in paths:
        p = REPO / rel
        if p.is_dir():
            out.extend(sorted(p.rglob("*.md")))
        elif p.suffix == ".md" and p.exists():
            out.append(p)
    # Deduplicate while keeping a stable order.
    return list(dict.fromkeys(out))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", type=Path, default=DEFAULT_PATHS,
                    help="files or directories to check (default: README.md CHANGELOG.md docs/ scripts/ tools/)")
    ap.add_argument("--quiet", action="store_true", help="only print on failure")
    args = ap.parse_args()

    files = markdown_files(args.paths or DEFAULT_PATHS)
    if not files:
        print("check-doc-links: no Markdown files found", file=sys.stderr)
        return 1

    anchor_cache: dict[Path, set[str]] = {}
    problems: list[str] = []
    checked = 0

    for path in files:
        for m in MD_LINK.finditer(path.read_text(encoding="utf-8")):
            url = m.group("url")
            if url.startswith(SKIP_SCHEMES) or url.startswith("#!"):
                continue

            rel, sep, frag = url.partition("#")
            checked += 1
            here = path.relative_to(REPO)

            target = path if rel == "" else (path.parent / rel)
            if rel:
                if not target.exists():
                    problems.append(f"{here}: missing file -> {url}")
                    continue
                if target.is_dir():
                    continue

            if not sep or not frag:
                continue

            target = target.resolve()
            if target.suffix != ".md":
                # Fragments into non-Markdown targets (e.g. a line anchor in a source file) are
                # not resolvable here.
                continue
            if target not in anchor_cache:
                anchor_cache[target] = anchors_of(target)
            if frag not in anchor_cache[target]:
                problems.append(f"{here}: dead anchor -> {url}")

    pkg_files = files + go_files()
    problems.extend(pinned_pkg_urls(pkg_files))

    if problems:
        print(f"check-doc-links: {len(problems)} broken link(s) of {checked} checked:\n", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    if not args.quiet:
        print(f"check-doc-links: {checked} relative links across {len(files)} files all resolve, "
              f"no pinned pkg.go.dev URL in {len(pkg_files)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
