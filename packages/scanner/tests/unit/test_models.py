from __future__ import annotations

import pytest

from vibescan.models import Finding


def make_finding(**overrides: object) -> Finding:
    defaults = {
        "rule_id": "VCS-001",
        "rule_name": "Supabase RLS not enabled",
        "severity": "CRITICAL",
        "filepath": "/repo/schema.sql",
        "line": 10,
        "col": 0,
        "snippet": "CREATE TABLE users (id uuid);",
        "fix": "ALTER TABLE users ENABLE ROW LEVEL SECURITY;",
        "ai_origin_score": 0.0,
    }
    return Finding(**{**defaults, **overrides})


def test_finding_fields_are_stored():
    f = make_finding(line=42, col=5, ai_origin_score=0.9)
    assert f.line == 42
    assert f.col == 5
    assert f.ai_origin_score == 0.9


def test_finding_default_ai_origin_score():
    f = make_finding()
    assert f.ai_origin_score == 0.0


def test_dedup_key_format():
    f = make_finding()
    key = f.dedup_key()
    assert key.startswith("VCS-001:")
    # hash portion is 16 hex chars
    assert len(key) == len("VCS-001:") + 16


def test_dedup_key_same_snippet_same_key():
    f1 = make_finding(filepath="/repo/a.sql")
    f2 = make_finding(filepath="/repo/b.sql")
    assert f1.dedup_key() == f2.dedup_key()


def test_dedup_key_different_snippet_different_key():
    f1 = make_finding(snippet="CREATE TABLE users (id uuid);")
    f2 = make_finding(snippet="CREATE TABLE posts (id uuid);")
    assert f1.dedup_key() != f2.dedup_key()


def test_dedup_key_different_rule_different_key():
    f1 = make_finding(rule_id="VCS-001")
    f2 = make_finding(rule_id="VCS-002")
    assert f1.dedup_key() != f2.dedup_key()
