from __future__ import annotations

from pathlib import Path

from vibescan.rules.vcs014_sql_injection import SQLInjectionRule

FIXTURES = Path(__file__).parents[2] / "fixtures" / "VCS-014"
rule = SQLInjectionRule()


def scan_py(src: str) -> list:
    return rule.visit(None, src.encode(), "/repo/app.py")


def scan_js(src: str) -> list:
    return rule.visit(None, src.encode(), "/repo/app.js")


def test_vulnerable_python_fixture():
    findings = rule.visit(None, (FIXTURES / "vulnerable.py").read_bytes(), "/repo/app.py")
    assert len(findings) >= 4, f"got {len(findings)}: {[f.snippet for f in findings]}"


def test_clean_python_fixture():
    assert rule.visit(None, (FIXTURES / "clean.py").read_bytes(), "/repo/clean.py") == []


def test_vulnerable_js_fixture():
    findings = rule.visit(None, (FIXTURES / "vulnerable.js").read_bytes(), "/repo/app.js")
    assert len(findings) >= 3


def test_clean_js_fixture():
    assert rule.visit(None, (FIXTURES / "clean.js").read_bytes(), "/repo/clean.js") == []


def test_python_fstring():
    src = "cursor.execute(f'SELECT * FROM users WHERE id = {uid}')"
    assert len(scan_py(src)) == 1


def test_python_concat():
    src = 'cursor.execute("SELECT * FROM " + table)'
    assert len(scan_py(src)) == 1


def test_python_percent_format():
    src = 'cursor.execute("SELECT * FROM users WHERE name = %s" % name)'
    assert len(scan_py(src)) == 1


def test_python_dotformat():
    src = 'cursor.execute("SELECT * FROM users WHERE id = {}".format(uid))'
    assert len(scan_py(src)) == 1


def test_python_parameterized_clean():
    src = 'cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))'
    assert scan_py(src) == []


def test_js_template_literal():
    src = "db.query(`SELECT * FROM users WHERE id = ${id}`)"
    assert len(scan_js(src)) == 1


def test_js_concat():
    src = 'db.query("SELECT * FROM " + table)'
    assert len(scan_js(src)) == 1


def test_js_parameterized_clean():
    src = 'db.query("SELECT * FROM users WHERE id = ?", [id])'
    assert scan_js(src) == []


def test_test_dir_skipped():
    src = "cursor.execute(f'SELECT * FROM x WHERE i={i}')"
    assert rule.visit(None, src.encode(), "/repo/tests/test_x.py") == []
