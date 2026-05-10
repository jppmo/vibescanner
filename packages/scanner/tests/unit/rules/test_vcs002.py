from __future__ import annotations

from pathlib import Path

from vibescan.rules.vcs002_firebase_rules import FirebaseOpenRulesRule

FIXTURES = Path(__file__).parents[2] / "fixtures" / "VCS-002"

rule = FirebaseOpenRulesRule()


def scan_rules(content: str) -> list:
    return rule.visit(None, content.encode(), "/fake/firestore.rules")


def scan_json(content: str) -> list:
    return rule.visit(None, content.encode(), "/fake/database.rules.json")


# ---------------------------------------------------------------------------
# Fixture files
# ---------------------------------------------------------------------------


def test_vulnerable_firestore_fixture_produces_one_finding():
    source = (FIXTURES / "vulnerable.rules").read_bytes()
    findings = rule.visit(None, source, "/repo/firestore.rules")
    assert len(findings) == 1
    assert findings[0].rule_id == "VCS-002"
    assert findings[0].severity == "CRITICAL"


def test_clean_firestore_fixture_produces_no_findings():
    source = (FIXTURES / "clean.rules").read_bytes()
    assert rule.visit(None, source, "/repo/firestore.rules") == []


def test_vulnerable_database_fixture_produces_two_findings():
    source = (FIXTURES / "vulnerable_database.json").read_bytes()
    findings = rule.visit(None, source, "/repo/database.rules.json")
    assert len(findings) == 2
    perms = {f.fix for f in findings}
    assert '".read": "auth != null"' in perms
    assert '".write": "auth != null"' in perms


def test_clean_database_fixture_produces_no_findings():
    source = (FIXTURES / "clean_database.json").read_bytes()
    assert rule.visit(None, source, "/repo/database.rules.json") == []


# ---------------------------------------------------------------------------
# Firestore rule logic
# ---------------------------------------------------------------------------


def test_read_write_if_true():
    assert len(scan_rules("allow read, write: if true;")) == 1


def test_read_only_if_true():
    findings = scan_rules("allow read: if true;")
    assert len(findings) == 1


def test_write_only_if_true():
    findings = scan_rules("allow write: if true;")
    assert len(findings) == 1


def test_all_operations_if_true():
    findings = scan_rules("allow read, write, create, update, delete: if true;")
    assert len(findings) == 1


def test_safe_auth_check_not_flagged():
    assert scan_rules("allow read, write: if request.auth != null;") == []


def test_uid_check_not_flagged():
    assert scan_rules("allow read, write: if request.auth.uid == userId;") == []


def test_multiple_open_rules_in_one_file():
    content = """
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{id} {
      allow read: if true;
    }
    match /posts/{id} {
      allow write: if true;
    }
  }
}
""".strip()
    assert len(scan_rules(content)) == 2


def test_firestore_finding_fix_uses_auth_check():
    findings = scan_rules("allow read, write: if true;")
    assert "request.auth != null" in findings[0].fix


def test_firestore_finding_snippet_is_the_offending_line():
    findings = scan_rules("      allow read, write: if true;")
    assert findings[0].snippet == "allow read, write: if true;"


def test_case_insensitive_allow():
    assert len(scan_rules("ALLOW READ, WRITE: IF TRUE;")) == 1


def test_empty_rules_file_produces_no_findings():
    assert scan_rules("") == []


# ---------------------------------------------------------------------------
# Realtime Database JSON logic
# ---------------------------------------------------------------------------


def test_read_true_boolean():
    assert len(scan_json('{ ".read": true }')) == 1


def test_write_true_boolean():
    assert len(scan_json('{ ".write": true }')) == 1


def test_read_true_string():
    assert len(scan_json('{ ".read": "true" }')) == 1


def test_write_true_string():
    assert len(scan_json('{ ".write": "true" }')) == 1


def test_auth_not_null_is_safe():
    assert scan_json('{ ".read": "auth != null" }') == []


def test_nested_auth_rule_is_safe():
    assert scan_json('{ ".read": "auth.uid != null" }') == []


def test_arbitrary_json_without_firebase_keys_is_skipped():
    assert scan_json('{ "name": "vibescan", "version": "1.0" }') == []


def test_realtime_db_fix_suggests_auth_check():
    findings = scan_json('{ ".read": true }')
    assert findings[0].fix == '".read": "auth != null"'


def test_realtime_db_finding_line_number_is_correct():
    content = '{\n  "rules": {\n    ".write": true\n  }\n}'
    findings = scan_json(content)
    assert findings[0].line == 3
