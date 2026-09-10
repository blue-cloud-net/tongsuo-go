#!/usr/bin/env python3
"""
Extract a version's release notes from CHANGELOG.md (English) and
CHANGELOG.zh.md (Chinese). Fails fast (non-zero exit) if either file
is missing the requested version section.

Used by .github/workflows/release.yml (extract-notes job).

Usage: extract_release_notes.py <version-without-leading-v>
Output: writes `release-notes.md` to current working directory.
  Format: English section, blank line, blank line, blank line, Chinese section.
"""
from __future__ import annotations

import os
import re
import sys
import pathlib


def extract(path: pathlib.Path, version: str) -> str:
    """Return the version section body (without the ## [...] heading),
    stripped of leading/trailing blank lines. Returns "" if absent."""
    if not path.is_file():
        print(f"::error::{path} not found", file=sys.stderr)
        return ""
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    start: int | None = None
    for i, ln in enumerate(lines):
        m = re.match(r"^## \[([^\]]+)\]", ln)
        if not m:
            continue
        if start is not None:
            # Found a new "## [" while still inside the target section → end
            break
        if m.group(1) == version:
            start = i + 1
    if start is None:
        return ""
    end = len(lines)
    for j in range(start, len(lines)):
        ln = lines[j]
        if re.match(r"^## \[", ln) or ln.strip() == "---":
            end = j
            break
    section = lines[start:end]
    while section and section[0].strip() == "":
        section.pop(0)
    while section and section[-1].strip() == "":
        section.pop()
    return "\n".join(section)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: extract_release_notes.py <version-without-leading-v>",
              file=sys.stderr)
        return 2
    version = sys.argv[1]
    repo_root = pathlib.Path(
        os.environ.get("GITHUB_WORKSPACE", ".")).resolve()
    en = extract(repo_root / "CHANGELOG.md", version)
    zh = extract(repo_root / "CHANGELOG.zh.md", version)

    # Hard fail if either side is missing: the release MUST be skipped.
    if not en:
        print(f"::error::CHANGELOG.md missing version section [{version}]",
              file=sys.stderr)
        return 1
    if not zh:
        print(f"::error::CHANGELOG.zh.md missing version section [{version}]",
              file=sys.stderr)
        return 1

    # Format: English, then exactly 3 blank lines, then Chinese.
    body = en + "\n\n\n\n" + zh
    out = pathlib.Path("release-notes.md")
    out.write_text(body, encoding="utf-8")
    print(f"::notice::Wrote release-notes.md "
          f"(en={len(en.encode())} bytes, zh={len(zh.encode())} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
