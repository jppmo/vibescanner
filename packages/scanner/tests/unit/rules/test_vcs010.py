from __future__ import annotations

from pathlib import Path

import pytest

from vibescan.rules.vcs010_committed_secrets import CommittedSecretsRule

FIXTURES = Path(__file__).parents[2] / "fixtures" / "VCS-010"

rule = CommittedSecretsRule()


# ---------------------------------------------------------------------------
# Fixture files
# ---------------------------------------------------------------------------


def test_vulnerable_pem_fixture_produces_finding():
    source = (FIXTURES / "vulnerable.pem").read_bytes()
    findings = rule.visit(None, source, "/repo/server.pem")
    assert len(findings) == 1
    assert findings[0].rule_id == "VCS-010"
    assert findings[0].severity == "CRITICAL"


def test_clean_pem_fixture_produces_no_findings():
    source = (FIXTURES / "clean.pem").read_bytes()
    findings = rule.visit(None, source, "/repo/cert.pem")
    assert findings == []


def test_vulnerable_env_fixture_produces_findings():
    source = (FIXTURES / "vulnerable.env").read_bytes()
    findings = rule.visit(None, source, "/repo/.env")
    assert len(findings) >= 3
    assert all(f.rule_id == "VCS-010" for f in findings)
    assert all(f.severity == "CRITICAL" for f in findings)


def test_clean_env_fixture_produces_no_findings():
    # The clean.env fixture uses placeholder values — should not fire
    source = (FIXTURES / "clean.env").read_bytes()
    findings = rule.visit(None, source, "/repo/.env")
    assert findings == []


# ---------------------------------------------------------------------------
# PEM detection
# ---------------------------------------------------------------------------


def test_rsa_private_key_header():
    source = b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n"
    findings = rule.visit(None, source, "/repo/key.pem")
    assert len(findings) == 1
    assert "RSA PRIVATE KEY" in findings[0].snippet


def test_openssh_private_key_header():
    source = b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA...\n-----END OPENSSH PRIVATE KEY-----\n"
    findings = rule.visit(None, source, "/repo/id_ed25519.pem")
    assert len(findings) == 1


def test_ec_private_key_header():
    source = b"-----BEGIN EC PRIVATE KEY-----\ndata\n-----END EC PRIVATE KEY-----\n"
    findings = rule.visit(None, source, "/repo/ec.key")
    assert len(findings) == 1


def test_pkcs8_private_key_header():
    source = b"-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----\n"
    findings = rule.visit(None, source, "/repo/private.key")
    assert len(findings) == 1


def test_pgp_private_key_header():
    source = b"-----BEGIN PGP PRIVATE KEY BLOCK-----\ndata\n-----END PGP PRIVATE KEY BLOCK-----\n"
    findings = rule.visit(None, source, "/repo/signing.key")
    assert len(findings) == 1


def test_certificate_not_flagged():
    source = b"-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----\n"
    findings = rule.visit(None, source, "/repo/cert.pem")
    assert findings == []


def test_public_key_not_flagged():
    source = b"-----BEGIN PUBLIC KEY-----\ndata\n-----END PUBLIC KEY-----\n"
    findings = rule.visit(None, source, "/repo/pubkey.pem")
    assert findings == []


def test_pem_finding_fix_contains_git_rm():
    source = b"-----BEGIN RSA PRIVATE KEY-----\ndata\n"
    findings = rule.visit(None, source, "/repo/server.pem")
    assert "git rm --cached" in findings[0].fix


def test_pem_finding_fix_mentions_rotate():
    source = b"-----BEGIN RSA PRIVATE KEY-----\ndata\n"
    findings = rule.visit(None, source, "/repo/server.pem")
    assert "rotate" in findings[0].fix.lower()


# ---------------------------------------------------------------------------
# .env secret detection
# ---------------------------------------------------------------------------


def test_jwt_secret_real_value():
    findings = rule.visit(None, b"JWT_SECRET=s3cur3pr0dk3y\n", "/repo/.env")
    assert len(findings) == 1
    assert "JWT_SECRET" in findings[0].snippet


def test_stripe_secret_real_value():
    findings = rule.visit(None, b"STRIPE_SECRET_KEY=sk_live_abc123\n", "/repo/.env")
    assert len(findings) == 1


def test_database_password_real_value():
    findings = rule.visit(None, b"DATABASE_PASSWORD=Tr0ub4d0r\n", "/repo/.env")
    assert len(findings) == 1


def test_api_key_real_value():
    findings = rule.visit(None, b"OPENAI_API_KEY=sk-abcdef1234567890\n", "/repo/.env")
    assert len(findings) == 1


def test_placeholder_value_not_flagged():
    for placeholder in ("your-secret-here", "changeme", "xxxx", "<your-key>", "example", ""):
        source = f"JWT_SECRET={placeholder}\n".encode()
        assert rule.visit(None, source, "/repo/.env") == [], f"Falsely flagged placeholder: {placeholder!r}"


def test_database_url_not_flagged():
    # DATABASE_URL doesn't match secret name patterns
    findings = rule.visit(None, b"DATABASE_URL=postgres://user:pass@localhost/db\n", "/repo/.env")
    assert findings == []


def test_env_example_file_skipped():
    source = b"JWT_SECRET=realvalue123abc\n"
    # All these naming patterns should be skipped
    for path in ("/repo/.env.example", "/repo/.env.template", "/repo/.env.sample", "/repo/.env.dist"):
        assert rule.visit(None, source, path) == [], f"Should skip {path}"


def test_example_suffix_skipped():
    source = b"JWT_SECRET=realvalue123abc\n"
    findings = rule.visit(None, source, "/repo/app.env.example")
    assert findings == []


def test_comment_lines_not_flagged():
    source = b"# JWT_SECRET=realvalue123\n"
    assert rule.visit(None, source, "/repo/.env") == []


def test_env_finding_fix_mentions_rotate():
    findings = rule.visit(None, b"JWT_SECRET=realvalue123abc\n", "/repo/.env")
    assert "rotate" in findings[0].fix.lower()


def test_env_finding_fix_mentions_gitignore():
    findings = rule.visit(None, b"JWT_SECRET=realvalue123abc\n", "/repo/.env")
    assert ".gitignore" in findings[0].fix


def test_quoted_value_detected():
    for quoted in ('"realvalue123abc"', "'realvalue123abc'"):
        source = f'JWT_SECRET={quoted}\n'.encode()
        assert len(rule.visit(None, source, "/repo/.env")) == 1, f"Missed quoted value: {quoted}"


def test_empty_env_file():
    assert rule.visit(None, b"", "/repo/.env") == []
