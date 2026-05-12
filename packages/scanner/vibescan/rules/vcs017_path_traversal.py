from __future__ import annotations

import re
from typing import ClassVar

from vibescan.models import Finding
from vibescan.rules._helpers import is_test_path
from vibescan.rules.base import BaseRule

# We can't do full taint tracking, so we look for the loudest pattern:
# a file API receives an expression that explicitly references a request
# input. False negatives are acceptable here; false positives are not.

# Python — common request-source expressions
_PY_REQUEST_SOURCES = (
    r"request\.(?:args|form|json|files|values|cookies|get_json\(\)|data)"
    r"|request\.(?:args|form)\.get\([^)]*\)"
    r"|flask\.request\.(?:args|form|json|files)"
    r"|req\.(?:args|body|query|params|files)"
    r"|self\.request\.(?:args|GET|POST|FILES)"
)
_PY_FILE_API_WITH_REQUEST = re.compile(
    rf"\b(?:open|Path|os\.path\.join|send_file|send_from_directory|FileResponse|"
    rf"shutil\.copyfile|shutil\.move|os\.remove|os\.unlink)\s*\("
    rf"[^)]*(?:{_PY_REQUEST_SOURCES})",
)

# JS/TS — Express/Fastify request inputs flowing into fs/path APIs
_JS_REQUEST_SOURCES = (
    r"req\.(?:body|params|query|files|headers)"
    r"|request\.(?:body|params|query|files|headers)"
    r"|ctx\.request\.(?:body|params|query)"
)
_JS_FILE_API_WITH_REQUEST = re.compile(
    rf"\b(?:fs\.(?:readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync|"
    rf"createReadStream|createWriteStream)|"
    rf"res\.(?:sendFile|download)|"
    rf"path\.(?:resolve|join))\s*\("
    rf"[^)]*(?:{_JS_REQUEST_SOURCES})",
)


class PathTraversalRule(BaseRule):
    """Detect file APIs reading user-controlled paths.

    Looks for the simplest path-traversal pattern: a file open/read/write/send
    function called with an argument that directly references a request input
    (req.body.path, request.args.get('file'), etc.). Misses indirect taint;
    catches the worst-case AI scaffolding pattern.
    """

    id = "VCS-017"
    name = "Path traversal via user input"
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
                if _PY_FILE_API_WITH_REQUEST.search(line):
                    findings.append(self._finding(filepath, i, stripped))
            elif _JS_FILE_API_WITH_REQUEST.search(line):
                findings.append(self._finding(filepath, i, stripped))

        return findings

    def _finding(self, filepath: str, line: int, snippet: str) -> Finding:
        fix = (
            "User input flows directly into a file API. An attacker can pass "
            "'../etc/passwd' (or similar) and read arbitrary files.\n"
            "Mitigations:\n"
            "  1. Resolve the requested path against a fixed base directory and "
            "reject anything that escapes:\n"
            "     full = os.path.realpath(os.path.join(BASE, user_path))\n"
            "     assert full.startswith(BASE)\n"
            "  2. Or store user files by opaque ID and look up the real path server-side."
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
