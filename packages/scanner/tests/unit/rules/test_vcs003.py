from __future__ import annotations

from pathlib import Path

import tree_sitter_javascript as ts_js
from tree_sitter import Language, Parser

from vibescan.rules.vcs003_jwt_secret import JWTHardcodedSecretRule

FIXTURES = Path(__file__).parents[2] / "fixtures" / "VCS-003"

rule = JWTHardcodedSecretRule()
_parser = Parser(Language(ts_js.language()))


def scan(js: str) -> list:
    src = js.encode()
    tree = _parser.parse(src)
    return rule.visit(tree, src, "/fake/auth.js")


# ---------------------------------------------------------------------------
# Fixture files
# ---------------------------------------------------------------------------


def test_vulnerable_fixture_produces_two_findings():
    source = (FIXTURES / "vulnerable.js").read_bytes()
    tree = _parser.parse(source)
    findings = rule.visit(tree, source, "/repo/auth.js")

    assert len(findings) == 2
    severities = {f.severity for f in findings}
    assert "CRITICAL" in severities
    assert "HIGH" in severities


def test_clean_fixture_produces_no_findings():
    source = (FIXTURES / "clean.js").read_bytes()
    tree = _parser.parse(source)
    assert rule.visit(tree, source, "/repo/auth.js") == []


# ---------------------------------------------------------------------------
# Hardcoded secret — CRITICAL
# ---------------------------------------------------------------------------


def test_known_bad_secret_flagged_critical():
    findings = scan("const t = jwt.sign({id:1}, 'secret')")
    assert len(findings) >= 1
    assert findings[0].severity == "CRITICAL"
    assert findings[0].rule_id == "VCS-003"


def test_double_quoted_secret_flagged():
    findings = scan('const t = jwt.sign({id:1}, "mysecret")')
    assert findings[0].severity == "CRITICAL"


def test_template_literal_secret_flagged():
    findings = scan("const t = jwt.sign({id:1}, `supersecret`)")
    assert findings[0].severity == "CRITICAL"


def test_env_var_secret_not_flagged_as_critical():
    js = "const t = jwt.sign({id:1}, process.env.JWT_SECRET)"
    findings = scan(js)
    assert all(f.severity != "CRITICAL" for f in findings)


def test_variable_secret_not_flagged_as_critical():
    js = "const t = jwt.sign({id:1}, secret)"
    findings = scan(js)
    assert all(f.severity != "CRITICAL" for f in findings)


def test_known_bad_detail_mentioned_in_fix():
    findings = scan("const t = jwt.sign({id:1}, 'secret')")
    assert "known-bad" in findings[0].fix


def test_fix_suggests_process_env():
    findings = scan("const t = jwt.sign({id:1}, 'secret')")
    assert "process.env.JWT_SECRET" in findings[0].fix


def test_hardcoded_secret_fix_also_mentions_expiry():
    # When the secret is hardcoded we fold both issues into one finding
    findings = scan("const t = jwt.sign({id:1}, 'secret')")
    assert "expiresIn" in findings[0].fix


# ---------------------------------------------------------------------------
# Missing expiresIn — HIGH
# ---------------------------------------------------------------------------


def test_missing_options_flagged_high():
    js = "const t = jwt.sign({id:1}, process.env.JWT_SECRET)"
    findings = scan(js)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"


def test_options_without_expires_in_flagged_high():
    js = "const t = jwt.sign({id:1}, process.env.JWT_SECRET, { algorithm: 'HS256' })"
    findings = scan(js)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"


def test_options_with_expires_in_not_flagged():
    js = "const t = jwt.sign({id:1}, process.env.JWT_SECRET, { expiresIn: '1h' })"
    assert scan(js) == []


def test_options_with_expires_in_and_other_keys_not_flagged():
    js = "const t = jwt.sign({id:1}, process.env.JWT_SECRET, { expiresIn: '7d', algorithm: 'HS256' })"
    assert scan(js) == []


def test_variable_options_not_flagged():
    # Can't statically check a variable reference — skip rather than false positive
    js = "const t = jwt.sign({id:1}, process.env.JWT_SECRET, opts)"
    assert scan(js) == []


# ---------------------------------------------------------------------------
# Pre-filter and edge cases
# ---------------------------------------------------------------------------


def test_file_without_jsonwebtoken_skipped():
    # No "jsonwebtoken" or ".sign(" in source → pre-filter exits early
    findings = rule.visit(None, b"const x = 1", "/fake/unrelated.js")
    assert findings == []


def test_tree_none_returns_empty():
    assert rule.visit(None, b"jwt.sign({}, 'secret')", "/fake/f.js") == []


def test_non_sign_method_not_flagged():
    js = "const t = obj.verify({id:1}, 'secret')"
    assert scan(js) == []


def test_multiple_sign_calls_each_checked():
    js = """
const t1 = jwt.sign({a:1}, 'secret1')
const t2 = jwt.sign({b:2}, 'secret2')
""".strip()
    findings = scan(js)
    assert len(findings) == 2
    assert all(f.severity == "CRITICAL" for f in findings)


def test_finding_line_number_points_to_secret():
    js = "const t = jwt.sign(\n  { id: 1 },\n  'mysecret'\n)"
    findings = scan(js)
    assert findings[0].line == 3  # 'mysecret' is on line 3
