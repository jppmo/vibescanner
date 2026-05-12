from __future__ import annotations

from pathlib import Path

from vibescan.rules.vcs012_weak_crypto import WeakCryptoRule

FIXTURES = Path(__file__).parents[2] / "fixtures" / "VCS-012"
rule = WeakCryptoRule()


def scan_py(src: str) -> list:
    return rule.visit(None, src.encode(), "/repo/app.py")


def scan_js(src: str) -> list:
    return rule.visit(None, src.encode(), "/repo/app.js")


def test_vulnerable_python_fixture():
    findings = rule.visit(None, (FIXTURES / "vulnerable.py").read_bytes(), "/repo/vuln.py")
    rules_hit = {(f.severity, f.snippet[:30]) for f in findings}
    # Should catch md5, sha1, DES, AES-ECB at minimum
    assert len(findings) >= 4, f"Expected ≥4 findings, got {len(findings)}: {rules_hit}"


def test_clean_python_fixture():
    findings = rule.visit(None, (FIXTURES / "clean.py").read_bytes(), "/repo/clean.py")
    assert findings == [], f"unexpected: {[f.snippet for f in findings]}"


def test_vulnerable_js_fixture():
    findings = rule.visit(None, (FIXTURES / "vulnerable.js").read_bytes(), "/repo/vuln.js")
    assert len(findings) >= 4


def test_clean_js_fixture():
    findings = rule.visit(None, (FIXTURES / "clean.js").read_bytes(), "/repo/clean.js")
    assert findings == []


def test_md5_python():
    assert len(scan_py("import hashlib\nx = hashlib.md5(b'pw').hexdigest()")) == 1


def test_sha1_python():
    assert len(scan_py("import hashlib\nh = hashlib.sha1(b'data')")) == 1


def test_md5_js():
    src = "const h = crypto.createHash('md5').update(p).digest('hex');"
    assert len(scan_js(src)) == 1


def test_sha1_js():
    src = 'const h = crypto.createHash("sha1");'
    assert len(scan_js(src)) == 1


def test_aes_ecb_python():
    assert len(scan_py("from Crypto.Cipher import AES\nc = AES.new(k, AES.MODE_ECB)")) == 1


def test_aes_gcm_python_clean():
    assert scan_py("from Crypto.Cipher import AES\nc = AES.new(k, AES.MODE_GCM, n)") == []


def test_test_dir_skipped():
    assert rule.visit(None, b"import hashlib\nhashlib.md5(b'')", "/repo/tests/test_x.py") == []
    assert rule.visit(None, b"const h = crypto.createHash('md5');", "/repo/__tests__/x.js") == []


def test_comment_lines_skipped():
    assert scan_py("# hashlib.md5(b'pw')") == []


def test_clean_sha256_python():
    assert scan_py("import hashlib\nh = hashlib.sha256(b'')") == []
