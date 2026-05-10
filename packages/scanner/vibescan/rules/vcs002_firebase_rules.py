from __future__ import annotations

import re
from pathlib import Path

from vibescan.models import Finding
from vibescan.rules.base import BaseRule

# Firestore: allow [read|write|...]: if true
_FIRESTORE_OPEN_RE = re.compile(
    r"allow\s+[\w\s,]+\s*:\s*if\s+true\b",
    re.IGNORECASE,
)

# Realtime Database: ".read": true / ".write": true  (boolean or string "true")
_RTDB_OPEN_RE = re.compile(
    r'"\.(read|write)"\s*:\s*(?:true|"true")',
)


class FirebaseOpenRulesRule(BaseRule):
    """Detect Firebase security rules that grant open read or write access.

    Both Firestore (`allow read, write: if true`) and Realtime Database
    (`".read": true`) patterns are flagged. Either allows any visitor —
    authenticated or not — to read or modify every record in the database.
    """

    id = "VCS-002"
    name = "Firebase open read/write rules"
    severity = "CRITICAL"
    languages = ["firebase_rules", "json"]

    def visit(self, tree, source, filepath):  # noqa: ANN001
        text = source.decode(errors="replace")
        suffix = Path(filepath).suffix

        if suffix == ".rules":
            return self._check_firestore(text, filepath)
        if suffix == ".json":
            return self._check_realtime_db(text, filepath)
        return []

    def _check_firestore(self, text: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(text.splitlines(), 1):
            m = _FIRESTORE_OPEN_RE.search(line)
            if m:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        rule_name=self.name,
                        severity=self.severity,
                        filepath=filepath,
                        line=i,
                        col=m.start(),
                        snippet=line.strip(),
                        fix="allow read, write: if request.auth != null;",
                    )
                )
        return findings

    def _check_realtime_db(self, text: str, filepath: str) -> list[Finding]:
        # Fast-exit: skip JSON files that aren't Firebase rules at all
        if '".read"' not in text and '".write"' not in text:
            return []

        findings: list[Finding] = []
        for i, line in enumerate(text.splitlines(), 1):
            m = _RTDB_OPEN_RE.search(line)
            if m:
                perm = m.group(1)
                findings.append(
                    Finding(
                        rule_id=self.id,
                        rule_name=self.name,
                        severity=self.severity,
                        filepath=filepath,
                        line=i,
                        col=m.start(),
                        snippet=line.strip(),
                        fix=f'".{perm}": "auth != null"',
                    )
                )
        return findings
