from __future__ import annotations

import re
from typing import ClassVar

from vibescan.models import Finding
from vibescan.rules._helpers import is_test_path, matches_outside_strings
from vibescan.rules.base import BaseRule

# ---------------------------------------------------------------------------
# Python — requests/httpx/urllib3/aiohttp/ssl
# ---------------------------------------------------------------------------

_PY_VERIFY_FALSE = re.compile(
    r"\b(?:requests|httpx|aiohttp|session|client)\.(?:get|post|put|patch|delete|request|head|"
    r"options)\s*\([^)]*\bverify\s*=\s*False\b",
    re.IGNORECASE | re.DOTALL,
)
_PY_VERIFY_FALSE_GENERIC = re.compile(
    r"\bverify\s*=\s*False\b",
)
_PY_DISABLE_WARNINGS = re.compile(
    r"urllib3\.disable_warnings\s*\(\s*(?:urllib3\.exceptions\.)?InsecureRequestWarning\s*\)",
)
_PY_UNVERIFIED_CONTEXT = re.compile(
    r"ssl\._create_unverified_context\s*\(\)",
)
_PY_CHECK_HOSTNAME_FALSE = re.compile(
    r"\.check_hostname\s*=\s*False\b",
)

# ---------------------------------------------------------------------------
# JS/TS — Node.js https/axios/fetch
# ---------------------------------------------------------------------------

_JS_REJECT_UNAUTH = re.compile(
    r"rejectUnauthorized\s*:\s*false\b",
)
_JS_NODE_TLS_ENV = re.compile(
    r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0['\"]?",
)
_JS_AGENT_INSECURE = re.compile(
    r"new\s+https\.Agent\s*\(\s*\{\s*rejectUnauthorized\s*:\s*false",
)


class TLSVerificationDisabledRule(BaseRule):
    """Detect disabled TLS certificate verification.

    Flags HTTP clients configured to skip cert validation, which exposes the
    request to MITM attacks. Common patterns:
    - Python: `requests.get(url, verify=False)`, `ssl._create_unverified_context()`
    - Node.js: `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`
    """

    id = "VCS-013"
    name = "TLS certificate verification disabled"
    severity = "HIGH"
    languages: ClassVar[list[str]] = ["python", "javascript", "typescript", "tsx"]

    def visit(self, tree, source: bytes, filepath: str) -> list[Finding]:
        if is_test_path(filepath):
            return []

        text = source.decode(errors="replace")
        lines = text.splitlines()
        findings: list[Finding] = []
        is_python = filepath.endswith(".py")

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//")):
                continue

            if is_python:
                has_http_lib = any(
                    t in text
                    for t in ("requests.", "httpx.", "aiohttp.", "import requests", "import httpx")
                )
                if matches_outside_strings(_PY_VERIFY_FALSE, line) or (
                    has_http_lib and matches_outside_strings(_PY_VERIFY_FALSE_GENERIC, line)
                ):
                    findings.append(self._finding(filepath, i, stripped, "verify=False"))
                elif matches_outside_strings(_PY_DISABLE_WARNINGS, line):
                    findings.append(self._finding(filepath, i, stripped, "urllib3.disable_warnings"))
                elif matches_outside_strings(_PY_UNVERIFIED_CONTEXT, line):
                    findings.append(self._finding(filepath, i, stripped, "ssl._create_unverified_context"))
                elif matches_outside_strings(_PY_CHECK_HOSTNAME_FALSE, line):
                    findings.append(self._finding(filepath, i, stripped, "check_hostname=False"))
            elif matches_outside_strings(_JS_REJECT_UNAUTH, line) or matches_outside_strings(_JS_AGENT_INSECURE, line):
                findings.append(self._finding(filepath, i, stripped, "rejectUnauthorized: false"))
            elif matches_outside_strings(_JS_NODE_TLS_ENV, line):
                findings.append(self._finding(filepath, i, stripped, "NODE_TLS_REJECT_UNAUTHORIZED=0"))

        return findings

    def _finding(self, filepath: str, line: int, snippet: str, pattern: str) -> Finding:
        fix = (
            f"`{pattern}` disables TLS certificate verification. The connection is open to "
            "MITM attacks. If you need to test against self-signed certs, use a CA bundle "
            "or a per-environment trust store. Never disable verification in production."
        )
        return Finding(
            rule_id=self.id,
            rule_name=self.name,
            severity=self.severity,
            filepath=filepath,
            line=line,
            col=0,
            snippet=snippet,
            fix=fix,
        )
