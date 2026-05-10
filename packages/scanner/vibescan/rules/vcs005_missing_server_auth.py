from __future__ import annotations

from vibescan.models import Finding
from vibescan.rules.base import BaseRule

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "head", "all"})

_PY_ROUTE_METHODS = frozenset({"get", "post", "put", "patch", "delete", "route", "api_route"})

# Path segments that indicate a public endpoint — never flag these
_PUBLIC_PATH_SEGMENTS = frozenset({
    "login", "logout", "register", "signup",
    "auth", "oauth", "callback", "webhook",
    "health", "healthz", "ping", "status",
    "verify", "confirm", "reset", "forgot",
    "public", "static", "favicon", "robots",
    "docs", "swagger", "openapi", "redoc",
})

# Text patterns that indicate auth is handled inside the handler body
_JS_AUTH_SIGNALS = (
    "req.user", "req.auth", "req.session",
    "req.isAuthenticated", "authorization", "Bearer",
    "401", "403", "Unauthorized", "Forbidden",
    "jwt.verify", "verifyToken", "checkAuth",
    "passport",
)

_PY_AUTH_SIGNALS = (
    "current_user", "get_current_user",
    "HTTPException", "401", "403",
    "Unauthorized", "login_required",
    "current_user_or_error",
)


def _is_public_path(path: str) -> bool:
    path_lower = path.lower()
    return any(seg in path_lower for seg in _PUBLIC_PATH_SEGMENTS)


def _iter_nodes(node):
    yield node
    for child in node.children:
        yield from _iter_nodes(child)


# ---------------------------------------------------------------------------
# Express.js helpers
# ---------------------------------------------------------------------------


_NON_ROUTER_OBJECTS = frozenset({
    "schema", "model", "db", "mongoose", "sequelize",
    "prisma", "client", "knex", "typeorm",
})


def _is_route_call(node) -> bool:
    func = node.child_by_field_name("function")
    if func is None or func.type != "member_expression":
        return False
    prop = func.child_by_field_name("property")
    if prop is None or prop.text.decode() not in _HTTP_METHODS:
        return False
    # Exclude ORM/ODM objects whose .post()/.get() are hooks, not HTTP routes
    obj = func.child_by_field_name("object")
    if obj is not None and obj.text.decode().lower() in _NON_ROUTER_OBJECTS:
        return False
    return True


def _extract_js_path(string_node) -> str:
    for child in string_node.named_children:
        if child.type == "string_fragment":
            return child.text.decode(errors="replace")
    return ""


def _js_handler_is_protected(handler_node) -> bool:
    body_text = handler_node.text.decode(errors="replace")
    return any(sig in body_text for sig in _JS_AUTH_SIGNALS)


# ---------------------------------------------------------------------------
# FastAPI / Flask helpers
# ---------------------------------------------------------------------------


def _extract_py_route_path(decorator_node) -> str | None:
    """Return the path string from a route decorator, or None if not a route decorator."""
    call_node = next(
        (c for c in decorator_node.named_children if c.type == "call"),
        None,
    )
    if call_node is None:
        return None

    func = call_node.child_by_field_name("function")
    if func is None or func.type != "attribute":
        return None

    attr = func.child_by_field_name("attribute")
    if attr is None or attr.text.decode(errors="replace") not in _PY_ROUTE_METHODS:
        return None

    arg_list = call_node.child_by_field_name("arguments")
    if arg_list is None:
        return None

    for arg in arg_list.named_children:
        if arg.type == "string":
            for child in arg.named_children:
                if child.type == "string_content":
                    return child.text.decode(errors="replace")
            return ""

    return None  # Path is a variable — can't inspect statically


def _py_func_is_protected(func_def_node, all_decorators: list) -> bool:
    # @login_required or similar on any decorator
    for dec in all_decorators:
        dec_text = dec.text.decode(errors="replace")
        if "login_required" in dec_text or "require_auth" in dec_text:
            return True

    # Depends() or current_user in function parameters
    params = func_def_node.child_by_field_name("parameters")
    if params is not None:
        params_text = params.text.decode(errors="replace")
        if "Depends(" in params_text or "current_user" in params_text:
            return True

    # Auth signals in function body
    body = func_def_node.child_by_field_name("body")
    if body is not None:
        body_text = body.text.decode(errors="replace")
        if any(sig in body_text for sig in _PY_AUTH_SIGNALS):
            return True

    return False


# ---------------------------------------------------------------------------
# Fix templates
# ---------------------------------------------------------------------------

_EXPRESS_FIX = """\
Add an auth middleware before the route handler:

  const authenticate = (req, res, next) => {{
    const token = req.headers.authorization?.split(' ')[1]
    if (!token) return res.status(401).json({{ error: 'Unauthorized' }})
    try {{
      req.user = jwt.verify(token, process.env.JWT_SECRET)
      next()
    }} catch {{ res.status(401).json({{ error: 'Invalid token' }}) }}
  }}

  app.{method}('{path}', authenticate, async (req, res) => {{ ... }})\
"""

_FASTAPI_FIX = """\
Add a Depends() auth parameter:

  from fastapi import Depends
  from app.auth import get_current_user

  @app.{method}("{path}")
  async def {name}(current_user: User = Depends(get_current_user)):
      ...\
"""


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------


class MissingServerAuthRule(BaseRule):
    """Detect route handlers with no server-side authentication.

    Checks Express.js (JS/TS) and FastAPI/Flask (Python) routes.
    A route is flagged when:
    - It has no auth middleware argument (Express), or
    - Its function signature has no Depends() / current_user (FastAPI), or
    - No @login_required decorator (Flask),
    AND the handler body contains no auth signals.

    Known public paths (login, health, webhook, etc.) are always skipped.
    This is a heuristic — review flagged routes before suppressing.
    """

    id = "VCS-005"
    name = "Route handler missing server-side auth"
    severity = "HIGH"
    languages = ["javascript", "typescript", "tsx", "python"]

    def visit(self, tree, source, filepath):  # noqa: ANN001
        if tree is None:
            return []

        # Skip test/spec files — mock routes in tests are not real auth gaps
        fp_lower = filepath.lower()
        if any(
            part in fp_lower
            for part in (".test.", ".spec.", "_test.", "_spec.", "/tests/", "/test/", "/__tests__/")
        ):
            return []

        text = source.decode(errors="replace")
        lines = text.splitlines()

        if filepath.endswith(".py"):
            return self._check_python(tree, text, lines, filepath)
        return self._check_express(tree, text, lines, filepath)

    # ------------------------------------------------------------------
    # Express.js
    # ------------------------------------------------------------------

    def _check_express(self, tree, text: str, lines: list[str], filepath: str) -> list[Finding]:
        # Pre-filter: skip files that don't look like Express route files
        if not any(kw in text for kw in ("express", "Router", "router", ".get(", ".post(")):
            return []

        findings: list[Finding] = []

        for node in _iter_nodes(tree.root_node):
            if node.type != "call_expression" or not _is_route_call(node):
                continue

            args = node.child_by_field_name("arguments")
            if args is None:
                continue

            named_args = list(args.named_children)
            if len(named_args) < 2:
                continue

            path_node = named_args[0]
            if path_node.type != "string":
                continue

            route_path = _extract_js_path(path_node)
            if _is_public_path(route_path):
                continue

            # 3+ args → middleware present → protected
            if len(named_args) >= 3:
                continue

            handler = named_args[-1]
            if handler.type not in ("arrow_function", "function_expression", "function"):
                continue

            if _js_handler_is_protected(handler):
                continue

            func = node.child_by_field_name("function")
            method = func.child_by_field_name("property").text.decode()
            line_no = node.start_point[0] + 1

            findings.append(
                Finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    filepath=filepath,
                    line=line_no,
                    col=node.start_point[1],
                    snippet=lines[line_no - 1].strip() if line_no <= len(lines) else "",
                    fix=_EXPRESS_FIX.format(method=method, path=route_path),
                )
            )

        return findings

    # ------------------------------------------------------------------
    # FastAPI / Flask
    # ------------------------------------------------------------------

    def _check_python(self, tree, text: str, lines: list[str], filepath: str) -> list[Finding]:
        if not any(kw in text for kw in ("@app.", "@router.", "@bp.", "FastAPI", "Flask")):
            return []

        findings: list[Finding] = []

        for node in _iter_nodes(tree.root_node):
            if node.type != "decorated_definition":
                continue

            decorators = [c for c in node.children if c.type == "decorator"]
            func_defs = [c for c in node.children if c.type == "function_definition"]

            if not func_defs:
                continue

            func_def = func_defs[0]

            # Find the route decorator
            route_path: str | None = None
            route_method: str = "get"
            for dec in decorators:
                path = _extract_py_route_path(dec)
                if path is not None:
                    route_path = path
                    # Extract method from decorator for fix text
                    call_node = next(
                        (c for c in dec.named_children if c.type == "call"), None
                    )
                    if call_node:
                        func = call_node.child_by_field_name("function")
                        if func and func.type == "attribute":
                            attr = func.child_by_field_name("attribute")
                            if attr:
                                route_method = attr.text.decode(errors="replace")
                    break

            if route_path is None or _is_public_path(route_path):
                continue

            if _py_func_is_protected(func_def, decorators):
                continue

            line_no = func_def.start_point[0] + 1
            func_name_node = func_def.child_by_field_name("name")
            func_name = func_name_node.text.decode(errors="replace") if func_name_node else "handler"

            findings.append(
                Finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    filepath=filepath,
                    line=line_no,
                    col=func_def.start_point[1],
                    snippet=lines[line_no - 1].strip() if line_no <= len(lines) else "",
                    fix=_FASTAPI_FIX.format(
                        method=route_method, path=route_path, name=func_name
                    ),
                )
            )

        return findings
