from __future__ import annotations

from pathlib import Path

import tree_sitter_javascript as ts_js
import tree_sitter_python as ts_py
from tree_sitter import Language, Parser

from vibescan.rules.vcs005_missing_server_auth import MissingServerAuthRule

FIXTURES = Path(__file__).parents[2] / "fixtures" / "VCS-005"

rule = MissingServerAuthRule()
_js_parser = Parser(Language(ts_js.language()))
_py_parser = Parser(Language(ts_py.language()))


def scan_js(content: str) -> list:
    src = content.encode()
    return rule.visit(_js_parser.parse(src), src, "/fake/routes.js")


def scan_py(content: str) -> list:
    src = content.encode()
    return rule.visit(_py_parser.parse(src), src, "/fake/routes.py")


# ---------------------------------------------------------------------------
# Fixture files
# ---------------------------------------------------------------------------


def test_vulnerable_js_fixture_two_findings():
    source = (FIXTURES / "vulnerable.js").read_bytes()
    findings = rule.visit(_js_parser.parse(source), source, "/repo/routes.js")
    # /api/users and /api/users/:id — login is public and skipped
    assert len(findings) == 2
    assert all(f.rule_id == "VCS-005" for f in findings)


def test_clean_js_fixture_no_findings():
    source = (FIXTURES / "clean.js").read_bytes()
    assert rule.visit(_js_parser.parse(source), source, "/repo/routes.js") == []


def test_vulnerable_py_fixture_two_findings():
    source = (FIXTURES / "vulnerable_api.py").read_bytes()
    findings = rule.visit(_py_parser.parse(source), source, "/repo/api.py")
    # /users and /users/{user_id} — login is public and skipped
    assert len(findings) == 2


def test_clean_py_fixture_no_findings():
    source = (FIXTURES / "clean_api.py").read_bytes()
    assert rule.visit(_py_parser.parse(source), source, "/repo/api.py") == []


# ---------------------------------------------------------------------------
# Express.js — route detection
# ---------------------------------------------------------------------------


def test_express_unprotected_get_flagged():
    js = "router.get('/api/items', (req, res) => { res.json([]) })"
    assert len(scan_js(js)) == 1


def test_express_with_middleware_not_flagged():
    js = "router.get('/api/items', authenticate, (req, res) => { res.json([]) })"
    assert scan_js(js) == []


def test_express_req_user_check_not_flagged():
    js = "router.get('/api/items', (req, res) => { if (!req.user) return res.sendStatus(401); res.json([]) })"
    assert scan_js(js) == []


def test_express_req_auth_not_flagged():
    js = "router.get('/api/items', (req, res) => { const u = req.auth; res.json([]) })"
    assert scan_js(js) == []


def test_express_401_in_body_not_flagged():
    js = "router.get('/api/items', (req, res) => { res.status(401).json({error:'Unauthorized'}) })"
    assert scan_js(js) == []


def test_express_app_post_flagged():
    js = "app.post('/api/orders', async (req, res) => { res.json({}) })"
    assert len(scan_js(js)) == 1


def test_express_finding_severity_is_high():
    js = "router.get('/api/data', (req, res) => { res.json([]) })"
    assert scan_js(js)[0].severity == "HIGH"


def test_express_fix_contains_authenticate():
    js = "router.get('/api/data', (req, res) => { res.json([]) })"
    assert "authenticate" in scan_js(js)[0].fix


# ---------------------------------------------------------------------------
# Express.js — public path skipping
# ---------------------------------------------------------------------------


def test_express_login_path_skipped():
    assert scan_js("router.post('/login', (req, res) => { res.json({}) })") == []


def test_express_register_path_skipped():
    assert scan_js("router.post('/api/register', (req, res) => {})") == []


def test_express_health_path_skipped():
    assert scan_js("app.get('/health', (req, res) => { res.json({ok:true}) })") == []


def test_express_webhook_path_skipped():
    assert scan_js("router.post('/webhook/stripe', (req, res) => {})") == []


def test_express_auth_callback_skipped():
    assert scan_js("router.get('/auth/callback', (req, res) => {})") == []


def test_express_non_express_file_skipped():
    # No express/router keywords — pre-filter should exit early
    js = "const x = obj.get('/api/data', handler)"
    assert scan_js(js) == []


# ---------------------------------------------------------------------------
# FastAPI / Flask — route detection
# ---------------------------------------------------------------------------


def test_fastapi_unprotected_get_flagged():
    py = "@app.get('/items')\nasync def get_items():\n    return []\n"
    assert len(scan_py(py)) == 1


def test_fastapi_with_depends_not_flagged():
    py = "@app.get('/items')\nasync def get_items(user = Depends(get_current_user)):\n    return []\n"
    assert scan_py(py) == []


def test_fastapi_current_user_param_not_flagged():
    py = "@app.get('/items')\nasync def get_items(current_user: User):\n    return []\n"
    assert scan_py(py) == []


def test_flask_login_required_not_flagged():
    py = "@app.route('/items')\n@login_required\ndef get_items():\n    return jsonify([])\n"
    assert scan_py(py) == []


def test_fastapi_public_login_skipped():
    py = "@app.post('/login')\nasync def login(creds: LoginRequest):\n    return authenticate(creds)\n"
    assert scan_py(py) == []


def test_fastapi_health_skipped():
    py = "@app.get('/health')\nasync def health():\n    return {'ok': True}\n"
    assert scan_py(py) == []


def test_fastapi_finding_fix_contains_depends():
    py = "@app.get('/orders')\nasync def get_orders():\n    return []\n"
    assert "Depends" in scan_py(py)[0].fix


def test_fastapi_finding_severity_is_high():
    py = "@app.get('/orders')\nasync def get_orders():\n    return []\n"
    assert scan_py(py)[0].severity == "HIGH"


def test_fastapi_router_decorator_flagged():
    py = "@router.get('/orders')\nasync def get_orders():\n    return []\n"
    assert len(scan_py(py)) == 1


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_tree_none_returns_empty():
    assert rule.visit(None, b"router.get('/x', h)", "/fake/r.js") == []


def test_empty_js_file_no_findings():
    assert scan_js("") == []


def test_empty_py_file_no_findings():
    assert scan_py("") == []
