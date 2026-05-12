from __future__ import annotations

import re
from typing import ClassVar

from vibescan.models import Finding
from vibescan.rules._helpers import is_test_path, matches_outside_strings
from vibescan.rules.base import BaseRule

# A SQL keyword fragment we use to anchor matches — keeps false positive rate
# down compared to flagging *any* string concat.
_SQL_KEYWORDS = (
    r"SELECT|INSERT|UPDATE|DELETE|REPLACE|MERGE|UPSERT|"
    r"CREATE|DROP|ALTER|TRUNCATE|GRANT|REVOKE"
)

# Python f-string with SQL keyword and an interpolation
# e.g.  cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
_PY_FSTRING_SQL = re.compile(
    rf"\.execute\s*\(\s*f['\"](?:[^'\"]*?\b(?:{_SQL_KEYWORDS})\b[^'\"]*?\{{[^}}]+\}})",
    re.IGNORECASE,
)
# Python %-formatting:  cursor.execute("SELECT ... %s" % var)  — the % outside the string
_PY_PERCENT_SQL = re.compile(
    rf"\.execute\s*\(\s*['\"][^'\"]*?\b(?:{_SQL_KEYWORDS})\b[^'\"]*?['\"]\s*%\s*[\w(]",
    re.IGNORECASE,
)
# Python str.format:  cursor.execute("SELECT ... {}".format(var))
_PY_FORMAT_SQL = re.compile(
    rf'\.execute\s*\(\s*(?:"[^"]*?\b(?:{_SQL_KEYWORDS})\b[^"]*?\{{\}}[^"]*?"|'
    rf"'[^']*?\b(?:{_SQL_KEYWORDS})\b[^']*?\{{\}}[^']*?')\s*\.format\s*\(",
    re.IGNORECASE,
)
# Python +-concatenation:  cursor.execute("SELECT * FROM " + table_name)
_PY_CONCAT_SQL = re.compile(
    rf"\.execute\s*\(\s*['\"][^'\"]*?\b(?:{_SQL_KEYWORDS})\b[^'\"]*?['\"]\s*\+",
    re.IGNORECASE,
)

# JS/TS template literal SQL injection
# e.g.  db.query(`SELECT * FROM users WHERE id = ${id}`)
_JS_TEMPLATE_SQL = re.compile(
    rf"\.(?:query|execute|raw)\s*\(\s*`[^`]*?\b(?:{_SQL_KEYWORDS})\b[^`]*?\$\{{",
    re.IGNORECASE,
)
# JS/TS string concat:  db.query("SELECT * FROM " + table)
_JS_CONCAT_SQL = re.compile(
    rf"\.(?:query|execute|raw)\s*\(\s*['\"][^'\"]*?\b(?:{_SQL_KEYWORDS})\b[^'\"]*?['\"]\s*\+",
    re.IGNORECASE,
)


class SQLInjectionRule(BaseRule):
    """Detect SQL queries built via string concatenation/interpolation.

    Catches the most common AI-generated pattern: f-strings, %-formatting,
    str.format, or +-concatenation feeding into `.execute()` / `.query()` /
    `.raw()`. These bypass parameterized queries and allow SQL injection.
    """

    id = "VCS-014"
    name = "SQL injection via string interpolation"
    severity = "CRITICAL"
    languages: ClassVar[list[str]] = ["python", "javascript", "typescript", "tsx"]

    def visit(self, tree, source: bytes, filepath: str) -> list[Finding]:
        if is_test_path(filepath):
            return []

        text = source.decode(errors="replace")
        lines = text.splitlines()
        findings: list[Finding] = []
        is_python = filepath.endswith(".py")

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//")):
                continue

            if is_python:
                if any(
                    matches_outside_strings(p, line)
                    for p in (_PY_FSTRING_SQL, _PY_PERCENT_SQL, _PY_FORMAT_SQL, _PY_CONCAT_SQL)
                ):
                    findings.append(self._finding(filepath, i, stripped, "python"))
            elif any(matches_outside_strings(p, line) for p in (_JS_TEMPLATE_SQL, _JS_CONCAT_SQL)):
                findings.append(self._finding(filepath, i, stripped, "js"))

        return findings

    def _finding(self, filepath: str, line: int, snippet: str, lang: str) -> Finding:
        fix = (
            "Use parameterized queries instead of string interpolation:\n"
            "  cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
            if lang == "python"
            else
            "Use parameterized queries instead of template literals / concat:\n"
            "  db.query('SELECT * FROM users WHERE id = ?', [userId])\n"
            "  // or with named bindings: db.query('... WHERE id = $1', [userId])"
        )
        return Finding(
            rule_id=self.id,
            rule_name=self.name,
            severity=self.severity,
            filepath=filepath,
            line=line,
            col=0,
            snippet=snippet,
            fix=fix,
        )
