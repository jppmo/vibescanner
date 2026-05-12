from __future__ import annotations

from pathlib import PurePosixPath
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import re

# Path segments that indicate a non-production file (tests, fixtures, examples).
_TEST_SEGMENTS: frozenset[str] = frozenset({
    "test", "tests", "testing",
    "__tests__", "__test__",
    "fixtures", "__fixtures__",
    "spec", "specs", "__specs__",
    "examples", "example",
    "sample", "samples",
    "demo", "demos",
    "mock", "mocks", "__mocks__",
})


def is_test_path(filepath: str) -> bool:
    """True if the file path contains any directory segment indicating test/fixture code."""
    parts = {p.lower() for p in PurePosixPath(filepath.replace("\\", "/")).parts}
    return bool(parts & _TEST_SEGMENTS)


def position_in_string_literal(line: str, pos: int) -> bool:
    r"""True if `pos` in `line` falls inside a string literal (', ", or `).

    Handles escape sequences. Used by detection rules to skip matches that
    appear inside docstrings, fix messages, or example code in comments.
    """
    in_single = False
    in_double = False
    in_back = False
    i = 0
    while i < pos:
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            i += 2
            continue
        if not in_double and not in_back and c == "'":
            in_single = not in_single
        elif not in_single and not in_back and c == '"':
            in_double = not in_double
        elif not in_single and not in_double and c == "`":
            in_back = not in_back
        i += 1
    return in_single or in_double or in_back


def matches_outside_strings(pattern: re.Pattern, line: str) -> list[re.Match]:
    """Return regex matches in `line` that are NOT inside a string literal."""
    return [m for m in pattern.finditer(line) if not position_in_string_literal(line, m.start())]
