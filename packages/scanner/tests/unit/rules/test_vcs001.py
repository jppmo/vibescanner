from __future__ import annotations

from pathlib import Path

import pytest

from vibescan.rules.vcs001_supabase_rls import SupabaseRLSRule

FIXTURES = Path(__file__).parents[2] / "fixtures" / "VCS-001"

rule = SupabaseRLSRule()


def scan(sql: str) -> list:
    return rule.visit(None, sql.encode(), "/repo/supabase/migrations/schema.sql")


# ---------------------------------------------------------------------------
# Fixture files — the golden-path contract for this rule
# ---------------------------------------------------------------------------


def test_vulnerable_fixture_produces_one_finding():
    source = (FIXTURES / "vulnerable.sql").read_bytes()
    findings = rule.visit(None, source, "/repo/schema.sql")

    assert len(findings) == 1
    assert findings[0].rule_id == "VCS-001"
    assert findings[0].severity == "CRITICAL"
    assert "users" in findings[0].fix


def test_clean_fixture_produces_no_findings():
    source = (FIXTURES / "clean.sql").read_bytes()
    findings = rule.visit(None, source, "/repo/schema.sql")

    assert findings == []


# ---------------------------------------------------------------------------
# Rule logic — targeted cases
# ---------------------------------------------------------------------------


def test_single_table_without_rls():
    findings = scan("CREATE TABLE users (id uuid);")
    assert len(findings) == 1
    assert findings[0].rule_id == "VCS-001"
    assert findings[0].line == 1


def test_single_table_with_rls():
    sql = """
CREATE TABLE users (id uuid);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
""".strip()
    assert scan(sql) == []


def test_multiple_tables_all_missing_rls():
    sql = """
CREATE TABLE users (id uuid);
CREATE TABLE posts (id uuid);
CREATE TABLE comments (id uuid);
""".strip()
    findings = scan(sql)
    names = {f.fix.split()[2] for f in findings}
    assert names == {"users", "posts", "comments"}


def test_multiple_tables_partial_rls():
    sql = """
CREATE TABLE users (id uuid);
CREATE TABLE posts (id uuid);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
""".strip()
    findings = scan(sql)
    assert len(findings) == 1
    assert "posts" in findings[0].fix


def test_if_not_exists_syntax():
    sql = "CREATE TABLE IF NOT EXISTS users (id uuid);"
    findings = scan(sql)
    assert len(findings) == 1
    assert "users" in findings[0].fix


def test_schema_qualified_create():
    sql = """
CREATE TABLE public.users (id uuid);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
""".strip()
    # schema-stripped name "users" matches the RLS statement — no finding
    assert scan(sql) == []


def test_schema_qualified_rls():
    sql = """
CREATE TABLE users (id uuid);
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
""".strip()
    assert scan(sql) == []


def test_rls_with_only_keyword():
    sql = """
CREATE TABLE users (id uuid);
ALTER TABLE ONLY users ENABLE ROW LEVEL SECURITY;
""".strip()
    assert scan(sql) == []


def test_empty_file_produces_no_findings():
    assert scan("") == []


def test_no_create_table_produces_no_findings():
    assert scan("SELECT 1; INSERT INTO logs VALUES ('x');") == []


def test_finding_snippet_is_the_create_table_line():
    findings = scan("CREATE TABLE orders (id uuid);")
    assert findings[0].snippet == "CREATE TABLE orders (id uuid);"


def test_finding_fix_contains_enable_rls():
    findings = scan("CREATE TABLE orders (id uuid);")
    assert "ENABLE ROW LEVEL SECURITY" in findings[0].fix


def test_finding_fix_contains_create_policy():
    findings = scan("CREATE TABLE orders (id uuid);")
    assert "CREATE POLICY" in findings[0].fix


def test_case_insensitive_create():
    assert len(scan("create table users (id uuid);")) == 1


def test_case_insensitive_rls():
    sql = """
create table users (id uuid);
alter table users enable row level security;
""".strip()
    assert scan(sql) == []


# ---------------------------------------------------------------------------
# Regression: false positives surfaced by the corpus scan
# ---------------------------------------------------------------------------


def test_skips_internal_supabase_auth_schema():
    """auth.users etc are managed by Supabase; never flag them."""
    sql = """
CREATE TABLE auth.users (id uuid);
CREATE TABLE auth.refresh_tokens (id uuid);
CREATE TABLE auth.audit_log_entries (id uuid);
"""
    assert scan(sql) == []


def test_skips_internal_postgres_schemas():
    sql = """
CREATE TABLE pg_catalog.pg_things (id int);
CREATE TABLE storage.objects (id uuid);
CREATE TABLE realtime.subscription (id int);
CREATE TABLE extensions.helper (id int);
CREATE TABLE supabase_migrations.schema_migrations (version text);
"""
    assert scan(sql) == []


def test_flags_user_table_alongside_internal_schema():
    """Real user tables must still fire even when internal-schema tables share the file."""
    sql = """
CREATE TABLE auth.users (id uuid);
CREATE TABLE public.payments (id uuid, amount numeric);
"""
    findings = scan(sql)
    assert len(findings) == 1
    assert "payments" in findings[0].snippet


def test_skips_files_under_test_directories():
    """Test fixture migrations should not be flagged."""
    sql = "CREATE TABLE public.users (id uuid);"
    test_paths = [
        "/repo/test/supabase/migrations/schema.sql",
        "/repo/tests/supabase/migrations/schema.sql",
        "/repo/__tests__/migrations/schema.sql",
        "/repo/fixtures/supabase/schema.sql",
        "/repo/spec/migrations/init.sql",
        "/repo/examples/supabase/schema.sql",
    ]
    for path in test_paths:
        assert rule.visit(None, sql.encode(), path) == [], f"unexpected finding at {path}"
