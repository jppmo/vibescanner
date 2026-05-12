from __future__ import annotations

import re
from typing import ClassVar

from vibescan.models import Finding
from vibescan.rules._helpers import is_test_path
from vibescan.rules.base import BaseRule

# Python — stdlib XML parsers are unsafe by default.
# Recommended replacement: defusedxml.

_XML_IMPORTS_UNSAFE = re.compile(
    r"^\s*(?:from|import)\s+(?:"
    r"xml\.etree(?:\.\w+)?|"
    r"xml\.dom(?:\.\w+)?|"
    r"xml\.sax(?:\.\w+)?|"
    r"xml\.pulldom|"
    r"lxml(?:\.\w+)?|"
    r"xmltodict"
    r")\b",
    re.MULTILINE,
)

_PARSE_CALLS = re.compile(
    r"\b(?:ET|etree|ElementTree|minidom|pulldom|xml|lxml)\.(?:parse|fromstring|XMLParser)\s*\(",
)
_LXML_RESOLVE_ENTITIES = re.compile(
    r"\bresolve_entities\s*=\s*True\b",
)
_LXML_NO_RESOLVE_ENTITIES = re.compile(  # passing it explicitly false counts as safe
    r"\bresolve_entities\s*=\s*False\b",
)
_DEFUSEDXML_IMPORT = re.compile(r"\bdefusedxml\b")


class XXEUnsafeParserRule(BaseRule):
    """Detect unsafe XML parsers vulnerable to XXE.

    Python's stdlib xml.etree.ElementTree, xml.dom.minidom, and lxml
    parse external entities by default. Without defusedxml or explicit
    `resolve_entities=False`, an attacker can read local files, exfiltrate
    data via OOB DNS, or trigger SSRF through `<!ENTITY>` declarations.

    Strategy: file uses an unsafe XML library AND calls a parse function AND
    does not import defusedxml as the replacement.
    """

    id = "VCS-016"
    name = "Unsafe XML parser (XXE)"
    severity = "HIGH"
    languages: ClassVar[list[str]] = ["python"]

    def visit(self, tree, source: bytes, filepath: str) -> list[Finding]:
        if is_test_path(filepath):
            return []
        if not filepath.endswith(".py"):
            return []

        text = source.decode(errors="replace")

        # Bail early if no XML imports
        if not _XML_IMPORTS_UNSAFE.search(text):
            return []

        # If defusedxml is in scope, assume the developer is using the safe replacement.
        # This is a heuristic — they may use defusedxml in some places and unsafe parsers
        # in others — but it eliminates the loudest false positive.
        uses_defused = _DEFUSEDXML_IMPORT.search(text) is not None

        lines = text.splitlines()
        findings: list[Finding] = []

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if _LXML_NO_RESOLVE_ENTITIES.search(line):
                continue
            if _LXML_RESOLVE_ENTITIES.search(line):
                # Explicit unsafe — always flag, even if defusedxml is imported
                findings.append(self._finding(filepath, i, stripped, "resolve_entities=True"))
                continue
            if uses_defused:
                continue
            if _PARSE_CALLS.search(line):
                findings.append(self._finding(filepath, i, stripped, "stdlib XML parser"))

        return findings

    def _finding(self, filepath: str, line: int, snippet: str, primitive: str) -> Finding:
        fix = (
            f"`{primitive}` parses external entities by default. An attacker who "
            "controls the XML body can read local files via XXE.\n"
            "  pip install defusedxml\n"
            "  from defusedxml.ElementTree import parse, fromstring\n"
            "  # …or for lxml: etree.XMLParser(resolve_entities=False)"
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
