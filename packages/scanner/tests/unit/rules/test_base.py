from __future__ import annotations

import pytest

from vibescan.models import Finding
from vibescan.rules.base import BaseRule


class ConcreteRule(BaseRule):
    id = "VCS-TEST"
    name = "Test rule"
    severity = "LOW"
    languages = ["py"]

    def visit(self, tree, source, filepath):
        return []


class AlwaysFindingRule(BaseRule):
    id = "VCS-FIND"
    name = "Always finds something"
    severity = "HIGH"
    languages = ["*"]

    def visit(self, tree, source, filepath):
        return [
            Finding(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                filepath=filepath,
                line=1,
                col=0,
                snippet=source.decode()[:50],
                fix="Fix it.",
            )
        ]


def test_base_rule_cannot_be_instantiated():
    with pytest.raises(TypeError):
        BaseRule()  # type: ignore[abstract]


def test_concrete_rule_instantiates():
    rule = ConcreteRule()
    assert rule.id == "VCS-TEST"
    assert rule.severity == "LOW"
    assert rule.languages == ["py"]


def test_visit_returns_empty_list():
    rule = ConcreteRule()
    result = rule.visit(None, b"", "/fake/file.py")
    assert result == []


def test_visit_returns_findings():
    rule = AlwaysFindingRule()
    findings = rule.visit(None, b"some source code", "/fake/file.py")
    assert len(findings) == 1
    assert findings[0].rule_id == "VCS-FIND"
    assert findings[0].filepath == "/fake/file.py"


def test_visit_accepts_none_tree():
    rule = ConcreteRule()
    # Text-based rules receive tree=None — this must not raise
    result = rule.visit(None, b"SELECT 1;", "/fake/schema.sql")
    assert isinstance(result, list)
