from __future__ import annotations

from pathlib import Path

import pytest

from vibescan.rules.vcs011_frontend_exposed_secrets import FrontendExposedSecretsRule

FIXTURES = Path(__file__).parents[2] / "fixtures" / "VCS-011"

rule = FrontendExposedSecretsRule()


def scan(content: str, path: str = "/repo/.env") -> list:
    return rule.visit(None, content.encode(), path)


# ---------------------------------------------------------------------------
# Fixture files
# ---------------------------------------------------------------------------


def test_vulnerable_fixture_produces_findings():
    source = (FIXTURES / "vulnerable.env").read_bytes()
    findings = rule.visit(None, source, "/repo/.env")
    assert len(findings) == 3
    assert all(f.rule_id == "VCS-011" for f in findings)
    assert all(f.severity == "HIGH" for f in findings)


def test_clean_fixture_produces_no_findings():
    source = (FIXTURES / "clean.env").read_bytes()
    findings = rule.visit(None, source, "/repo/.env")
    assert findings == []


# ---------------------------------------------------------------------------
# VITE_ prefix
# ---------------------------------------------------------------------------


def test_vite_stripe_secret_key():
    findings = scan("VITE_STRIPE_SECRET_KEY=sk_live_abc123")
    assert len(findings) == 1
    assert "VITE_STRIPE_SECRET_KEY" in findings[0].snippet


def test_vite_jwt_token():
    findings = scan("VITE_JWT_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.real")
    assert len(findings) == 1


def test_vite_private_key():
    findings = scan("VITE_SIGNING_KEY=supersecretkeyvalue123")
    assert len(findings) == 1


def test_vite_app_name_not_flagged():
    assert scan("VITE_APP_NAME=MyApp") == []


def test_vite_api_url_not_flagged():
    assert scan("VITE_API_URL=https://api.example.com") == []


# ---------------------------------------------------------------------------
# NEXT_PUBLIC_ prefix
# ---------------------------------------------------------------------------


def test_next_public_service_role_key():
    findings = scan("NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.svc")
    assert len(findings) == 1


def test_next_public_anon_key_not_flagged():
    # Supabase anon key is designed to be public
    assert scan("NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.anon") == []


def test_next_public_supabase_url_not_flagged():
    assert scan("NEXT_PUBLIC_SUPABASE_URL=https://abc.supabase.co") == []


def test_next_public_api_url_not_flagged():
    assert scan("NEXT_PUBLIC_API_URL=https://api.myapp.com") == []


def test_next_public_secret():
    findings = scan("NEXT_PUBLIC_OPENAI_SECRET=sk-abc123realvalue")
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# REACT_APP_ prefix
# ---------------------------------------------------------------------------


def test_react_app_password():
    findings = scan("REACT_APP_PASSWORD=realpassword123")
    assert len(findings) == 1


def test_react_app_token():
    findings = scan("REACT_APP_JWT_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.real")
    assert len(findings) == 1


def test_react_app_public_key_not_flagged():
    # PUBLIC_KEY is in safe patterns
    assert scan("REACT_APP_PUBLIC_KEY=pk_test_abc123") == []


def test_react_app_publishable_key_not_flagged():
    assert scan("REACT_APP_PUBLISHABLE_KEY=pk_live_abc123") == []


# ---------------------------------------------------------------------------
# EXPO_PUBLIC_ prefix
# ---------------------------------------------------------------------------


def test_expo_public_secret():
    findings = scan("EXPO_PUBLIC_API_SECRET=realsecretvalue123")
    assert len(findings) == 1


def test_expo_public_app_name_not_flagged():
    assert scan("EXPO_PUBLIC_APP_NAME=MyApp") == []


# ---------------------------------------------------------------------------
# Placeholder suppression
# ---------------------------------------------------------------------------


def test_placeholder_not_flagged():
    placeholders = [
        "VITE_STRIPE_SECRET_KEY=your-key-here",
        "VITE_STRIPE_SECRET_KEY=changeme",
        "VITE_STRIPE_SECRET_KEY=xxxx",
        "VITE_STRIPE_SECRET_KEY=<your-stripe-key>",
        "VITE_STRIPE_SECRET_KEY=",
    ]
    for line in placeholders:
        assert scan(line) == [], f"Should not flag placeholder: {line!r}"


# ---------------------------------------------------------------------------
# Server-only variables (no frontend prefix) — never flag
# ---------------------------------------------------------------------------


def test_server_only_secret_not_flagged():
    assert scan("STRIPE_SECRET_KEY=sk_live_abc123") == []


def test_server_only_service_role_not_flagged():
    assert scan("SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.svc") == []


# ---------------------------------------------------------------------------
# Fix text
# ---------------------------------------------------------------------------


def test_fix_mentions_prefix_removal():
    findings = scan("VITE_STRIPE_SECRET_KEY=sk_live_abc123")
    assert "VITE_" in findings[0].fix


def test_fix_mentions_server_side():
    findings = scan("VITE_STRIPE_SECRET_KEY=sk_live_abc123")
    assert "server" in findings[0].fix.lower()


def test_fix_mentions_rotate():
    findings = scan("VITE_STRIPE_SECRET_KEY=sk_live_abc123")
    assert "rotate" in findings[0].fix.lower()


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_comment_lines_not_flagged():
    assert scan("# VITE_STRIPE_SECRET_KEY=sk_live_abc123") == []


def test_empty_file():
    assert scan("") == []


def test_multiple_findings_in_one_file():
    content = (
        "VITE_STRIPE_SECRET_KEY=sk_live_abc123\n"
        "NEXT_PUBLIC_OPENAI_SECRET=sk-real-key-here\n"
        "REACT_APP_PASSWORD=mypassword123\n"
    )
    findings = scan(content)
    assert len(findings) == 3
