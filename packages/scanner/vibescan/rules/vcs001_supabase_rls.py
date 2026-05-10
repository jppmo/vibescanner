from __future__ import annotations

import re

from vibescan.models import Finding
from vibescan.rules.base import BaseRule

# CREATE TABLE [IF NOT EXISTS] [schema.]tablename  — handles quoted identifiers
_CREATE_RE = re.compile(
    r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:(?:\w+|"[^"]+")\.)?(?:"([^"]+)"|(\w+))',
    re.IGNORECASE,
)

# ALTER TABLE [ONLY] [schema.]tablename ENABLE ROW LEVEL SECURITY
_RLS_RE = re.compile(
    r'ALTER\s+TABLE\s+(?:ONLY\s+)?(?:(?:\w+|"[^"]+")\.)?(?:"([^"]+)"|(\w+))\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY',
    re.IGNORECASE,
)


class SupabaseRLSRule(BaseRule):
    """Detect Supabase tables created without Row Level Security enabled.

    Every Supabase table exposed to the client must have RLS enabled and at
    least one policy. Without it, any authenticated user can read or write
    every row in the table.
    """

    id = "VCS-001"
    name = "Supabase RLS not enabled"
    severity = "CRITICAL"
    languages = ["sql"]

    def visit(self, tree, source, filepath):  # noqa: ANN001
        text = source.decode(errors="replace")

        # RLS is a Supabase concept — only scan SQL in Supabase project contexts.
        # Plain PostgreSQL/Prisma migrations don't need RLS because all access
        # goes through an API server that enforces auth.
        is_supabase = (
            "supabase" in filepath.lower()
            or "auth.uid()" in text.lower()
            or "auth.users" in text.lower()
        )
        if not is_supabase:
            return []

        lines = text.splitlines()

        # Collect table name → line number for every CREATE TABLE
        tables: dict[str, int] = {}
        for i, line in enumerate(lines, 1):
            m = _CREATE_RE.search(line)
            if m:
                name = (m.group(1) or m.group(2)).lower()
                tables[name] = i

        # Collect table names that already have RLS enabled
        rls_enabled: set[str] = {
            (m.group(1) or m.group(2)).lower() for m in _RLS_RE.finditer(text)
        }

        findings: list[Finding] = []
        for name, line_no in tables.items():
            if name in rls_enabled:
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
                        f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY;\n"
                        f'CREATE POLICY "authenticated_only" ON {name}\n'
                        f"  FOR ALL TO authenticated\n"
                        f"  USING (auth.uid() IS NOT NULL);"
                    ),
                )
            )

        return findings
