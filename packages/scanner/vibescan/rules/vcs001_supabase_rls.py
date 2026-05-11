from __future__ import annotations

import logging
import re
from pathlib import Path, PurePosixPath
from typing import ClassVar

from vibescan.models import Finding
from vibescan.rules.base import BaseRule

logger = logging.getLogger(__name__)

# Cap repo-wide SQL discovery so a pathological monorepo can't slow scans.
_MAX_REPO_SQL_FILES = 200

# CREATE TABLE [IF NOT EXISTS] [schema.]tablename — captures schema as group(1)
# and table name as group(3) (quoted) or group(4) (unquoted).
_CREATE_RE = re.compile(
    r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?'
    r'(?:(?:"([^"]+)"|(\w+))\.)?(?:"([^"]+)"|(\w+))',
    re.IGNORECASE,
)

# ALTER TABLE [ONLY] [schema.]tablename ENABLE ROW LEVEL SECURITY
_RLS_RE = re.compile(
    r'ALTER\s+TABLE\s+(?:ONLY\s+)?(?:(?:\w+|"[^"]+")\.)?(?:"([^"]+)"|(\w+))\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY',
    re.IGNORECASE,
)

# Schemas managed by Supabase or PostgreSQL itself — RLS is either enforced
# internally (auth.*, storage.*) or doesn't apply (pg_catalog, information_schema).
_INTERNAL_SCHEMAS: frozenset[str] = frozenset({
    "auth",
    "storage",
    "realtime",
    "_realtime",
    "vault",
    "graphql",
    "graphql_public",
    "extensions",
    "pg_catalog",
    "information_schema",
    "supabase_migrations",
    "supabase_functions",
    "pgbouncer",
    "net",
    "pgsodium",
    "pgsodium_masks",
    "cron",
})

# Path segments indicating the file is a test fixture, not a real migration.
_TEST_DIR_SEGMENTS: frozenset[str] = frozenset({
    "test",
    "tests",
    "__tests__",
    "fixtures",
    "__fixtures__",
    "spec",
    "specs",
    "examples",
    "example",
    "sample",
    "samples",
    "demo",
    "demos",
})


def _is_test_path(filepath: str) -> bool:
    parts = {p.lower() for p in PurePosixPath(filepath.replace("\\", "/")).parts}
    return bool(parts & _TEST_DIR_SEGMENTS)


def _find_repo_root(start: Path) -> Path | None:
    """Walk up from a file looking for a git/Supabase project root."""
    cur = start.resolve()
    if cur.is_file():
        cur = cur.parent
    while cur != cur.parent:
        if (cur / ".git").exists() or (cur / "supabase").is_dir():
            return cur
        cur = cur.parent
    return None


def _collect_repo_rls(root: Path) -> set[str]:
    """Scan every SQL file under root for ALTER TABLE ... ENABLE RLS.

    Used to fix the common Supabase split-migration pattern: tables defined
    in `supabase/schemas/01_tables.sql`, RLS enabled in
    `supabase/schemas/02_security.sql` or under `supabase/migrations/`.
    """
    enabled: set[str] = set()
    try:
        sql_files = list(root.rglob("*.sql"))
    except (OSError, ValueError):
        return enabled

    if len(sql_files) > _MAX_REPO_SQL_FILES:
        logger.debug("Skipping repo-wide RLS scan: %d sql files exceeds cap", len(sql_files))
        return enabled

    for path in sql_files:
        if any(p.lower() in _TEST_DIR_SEGMENTS for p in path.parts):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for m in _RLS_RE.finditer(text):
            name = (m.group(1) or m.group(2) or "").lower()
            if name:
                enabled.add(name)
    return enabled


class SupabaseRLSRule(BaseRule):
    """Detect Supabase tables created without Row Level Security enabled.

    Every Supabase table exposed to the client must have RLS enabled and at
    least one policy. Without it, any authenticated user can read or write
    every row in the table.

    Skipped:
    - Internal Supabase/Postgres schemas (auth, storage, pg_catalog, etc.)
    - Files under test/fixtures/spec/examples directories
    - Plain PostgreSQL/Prisma migrations not in a Supabase context
    """

    id = "VCS-001"
    name = "Supabase RLS not enabled"
    severity = "CRITICAL"
    languages: ClassVar[list[str]] = ["sql"]

    def __init__(self) -> None:
        # Cache: repo_root -> set of RLS-enabled table names across all SQL files
        self._repo_rls_cache: dict[Path, set[str]] = {}

    def _repo_rls(self, filepath: str) -> set[str]:
        root = _find_repo_root(Path(filepath))
        if root is None:
            return set()
        if root not in self._repo_rls_cache:
            self._repo_rls_cache[root] = _collect_repo_rls(root)
        return self._repo_rls_cache[root]

    def visit(self, tree, source: bytes, filepath: str) -> list[Finding]:
        if _is_test_path(filepath):
            return []

        text = source.decode(errors="replace")

        is_supabase = (
            "supabase" in filepath.lower()
            or "auth.uid()" in text.lower()
            or "auth.users" in text.lower()
        )
        if not is_supabase:
            return []

        lines = text.splitlines()

        # Collect (qualified_name, line_no, schema, table) for every CREATE TABLE
        tables: list[tuple[str, int, str | None, str]] = []
        seen_keys: set[str] = set()
        for i, line in enumerate(lines, 1):
            m = _CREATE_RE.search(line)
            if not m:
                continue
            schema = (m.group(1) or m.group(2) or "").lower() or None
            name = (m.group(3) or m.group(4) or "").lower()
            if not name:
                continue
            if schema and schema in _INTERNAL_SCHEMAS:
                continue
            key = f"{schema}.{name}" if schema else name
            if key in seen_keys:
                continue
            seen_keys.add(key)
            tables.append((key, i, schema, name))

        rls_enabled: set[str] = {
            (m.group(1) or m.group(2)).lower() for m in _RLS_RE.finditer(text)
        }
        # Union with RLS declared in sibling SQL files (cross-file tracking).
        # Common Supabase pattern: tables in 01_tables.sql, RLS in 02_security.sql
        # or under supabase/migrations/.
        rls_enabled |= self._repo_rls(filepath)

        findings: list[Finding] = []
        for key, line_no, _schema, name in tables:
            if name in rls_enabled or key in rls_enabled:
                continue
            findings.append(
                Finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    filepath=filepath,
                    line=line_no,
                    col=0,
                    snippet=lines[line_no - 1].strip(),
                    fix=(
                        f"ALTER TABLE {key} ENABLE ROW LEVEL SECURITY;\n"
                        f'CREATE POLICY "authenticated_only" ON {key}\n'
                        f"  FOR ALL TO authenticated\n"
                        f"  USING (auth.uid() IS NOT NULL);"
                    ),
                )
            )

        return findings
