from __future__ import annotations

from pathlib import Path

from vibescan.rules.vcs013_tls_verify_disabled import TLSVerificationDisabledRule

FIXTURES = Path(__file__).parents[2] / "fixtures" / "VCS-013"
rule = TLSVerificationDisabledRule()


def scan_py(src: str) -> list:
    return rule.visit(None, src.encode(), "/repo/app.py")


def scan_js(src: str) -> list:
    return rule.visit(None, src.encode(), "/repo/app.js")


def test_vulnerable_python_fixture():
    findings = rule.visit(None, (FIXTURES / "vulnerable.py").read_bytes(), "/repo/app.py")
    # 2x verify=False, 1x disable_warnings, 1x unverified context, 1x check_hostname
    assert len(findings) >= 5, [f.snippet for f in findings]


def test_clean_python_fixture():
    assert rule.visit(None, (FIXTURES / "clean.py").read_bytes(), "/repo/clean.py") == []


def test_vulnerable_js_fixture():
    findings = rule.visit(None, (FIXTURES / "vulnerable.js").read_bytes(), "/repo/app.js")
    # 3x rejectUnauthorized: false
    assert len(findings) >= 3


def test_clean_js_fixture():
    assert rule.visit(None, (FIXTURES / "clean.js").read_bytes(), "/repo/clean.js") == []


def test_requests_verify_false():
    src = "import requests\nrequests.get('https://x', verify=False)"
    assert len(scan_py(src)) == 1


def test_unverified_ssl_context():
    src = "import ssl\nctx = ssl._create_unverified_context()"
    assert len(scan_py(src)) == 1


def test_reject_unauthorized_false():
    src = "const agent = new https.Agent({ rejectUnauthorized: false });"
    assert len(scan_js(src)) == 1


def test_node_tls_env_zero():
    src = 'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";'
    assert len(scan_js(src)) == 1


def test_test_dir_skipped():
    assert rule.visit(None, b"requests.get(u, verify=False)", "/repo/tests/x.py") == []


def test_comments_skipped():
    assert scan_py("# verify=False here") == []


def test_clean_request_with_verify_true():
    assert scan_py("import requests\nrequests.get('https://x', verify=True)") == []
