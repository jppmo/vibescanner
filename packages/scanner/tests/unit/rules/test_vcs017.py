from __future__ import annotations

from pathlib import Path

from vibescan.rules.vcs017_path_traversal import PathTraversalRule

FIXTURES = Path(__file__).parents[2] / "fixtures" / "VCS-017"
rule = PathTraversalRule()


def scan_py(src: str) -> list:
    return rule.visit(None, src.encode(), "/repo/app.py")


def scan_js(src: str) -> list:
    return rule.visit(None, src.encode(), "/repo/app.js")


def test_vulnerable_python_fixture():
    findings = rule.visit(None, (FIXTURES / "vulnerable.py").read_bytes(), "/repo/app.py")
    # send_file(request.args.get), open(request.args.get), os.path.join(.., request.form.get)
    assert len(findings) >= 3, [f.snippet for f in findings]


def test_clean_python_fixture():
    assert rule.visit(None, (FIXTURES / "clean.py").read_bytes(), "/repo/clean.py") == []


def test_vulnerable_js_fixture():
    findings = rule.visit(None, (FIXTURES / "vulnerable.js").read_bytes(), "/repo/app.js")
    # res.sendFile(req.query.file), fs.readFile(req.query.path), path.join + req.body
    assert len(findings) >= 3, [f.snippet for f in findings]


def test_clean_js_fixture():
    assert rule.visit(None, (FIXTURES / "clean.js").read_bytes(), "/repo/clean.js") == []


def test_open_with_request_args():
    src = "with open(request.args.get('file')) as f: pass"
    assert len(scan_py(src)) == 1


def test_send_file_with_request():
    src = "return send_file(request.args.get('name'))"
    assert len(scan_py(src)) == 1


def test_python_open_static_path_clean():
    src = "with open('/etc/passwd') as f: pass"  # bad in real life, but not THIS rule
    assert scan_py(src) == []


def test_express_send_file_with_req():
    src = "res.sendFile(req.query.file)"
    assert len(scan_js(src)) == 1


def test_express_fs_readfile_with_req():
    src = "fs.readFile(req.params.path, (e, d) => res.send(d))"
    assert len(scan_js(src)) == 1


def test_express_static_clean():
    src = 'res.sendFile(path.join(__dirname, "public", "index.html"))'
    assert scan_js(src) == []


def test_test_dir_skipped():
    src = "open(request.args.get('x'))"
    assert rule.visit(None, src.encode(), "/repo/tests/test_x.py") == []
