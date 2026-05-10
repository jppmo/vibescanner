from __future__ import annotations

from pathlib import Path

import pytest

from vibescan.engine import SKIP_DIRS, ScanEngine
from vibescan.models import Finding
from vibescan.rules.base import BaseRule


# ---------------------------------------------------------------------------
# Helpers — in-test rule stubs
# ---------------------------------------------------------------------------


class _AlwaysFindsRule(BaseRule):
    """Emits one finding per file, regardless of content."""

    id = "TEST-001"
    name = "Always finds"
    severity = "LOW"
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
                snippet=source.decode(errors="replace")[:40],
                fix="No fix needed.",
            )
        ]


class _SqlOnlyRule(BaseRule):
    """Emits one finding per SQL file."""

    id = "TEST-002"
    name = "SQL only"
    severity = "HIGH"
    languages = ["sql"]

    def visit(self, tree, source, filepath):
        return [
            Finding(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                filepath=filepath,
                line=1,
                col=0,
                snippet="SELECT 1;",
                fix="No fix.",
            )
        ]


class _RaisingRule(BaseRule):
    """Simulates a rule that crashes."""

    id = "TEST-003"
    name = "Always raises"
    severity = "MEDIUM"
    languages = ["*"]

    def visit(self, tree, source, filepath):
        msg = "intentional error"
        raise RuntimeError(msg)


def _make_engine(repo_path: Path, rules: list[BaseRule]) -> ScanEngine:
    """Return a ScanEngine with a fixed rule list (bypasses auto-discovery)."""
    engine = ScanEngine(repo_path)
    engine._rules = rules  # noqa: SLF001
    return engine


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


def test_empty_repo_returns_no_findings(tmp_path: Path) -> None:
    engine = _make_engine(tmp_path, [_AlwaysFindsRule()])
    assert engine.scan() == []


def test_supported_extensions_are_scanned(tmp_path: Path) -> None:
    for i, ext in enumerate((".js", ".ts", ".py", ".sql", ".json", ".yaml", ".tf")):
        (tmp_path / f"file{ext}").write_text(f"content_{i}")

    engine = _make_engine(tmp_path, [_AlwaysFindsRule()])
    assert len(engine.scan()) == 7


def test_unknown_extensions_are_skipped(tmp_path: Path) -> None:
    (tmp_path / "image.png").write_bytes(b"\x89PNG")
    (tmp_path / "video.mp4").write_bytes(b"\x00\x00")
    (tmp_path / "archive.zip").write_bytes(b"PK")

    engine = _make_engine(tmp_path, [_AlwaysFindsRule()])
    assert engine.scan() == []


def test_skip_dirs_are_not_traversed(tmp_path: Path) -> None:
    for skip_dir in (".git", "node_modules", ".venv", "__pycache__"):
        d = tmp_path / skip_dir
        d.mkdir()
        (d / "secret.py").write_text("x = 1")

    engine = _make_engine(tmp_path, [_AlwaysFindsRule()])
    assert engine.scan() == []


def test_nested_files_are_discovered(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "deep").mkdir()
    (tmp_path / "src" / "deep" / "file.py").write_text("x = 1")

    engine = _make_engine(tmp_path, [_AlwaysFindsRule()])
    assert len(engine.scan()) == 1


def test_oversized_files_are_skipped(tmp_path: Path) -> None:
    big = tmp_path / "huge.py"
    big.write_bytes(b"x" * (1024 * 1024 + 1))

    engine = _make_engine(tmp_path, [_AlwaysFindsRule()])
    assert engine.scan() == []


# ---------------------------------------------------------------------------
# Language routing
# ---------------------------------------------------------------------------


def test_language_specific_rule_only_runs_on_matching_extension(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text("CREATE TABLE t (id int);")
    (tmp_path / "app.py").write_text("x = 1")

    engine = _make_engine(tmp_path, [_SqlOnlyRule()])
    findings = engine.scan()

    assert len(findings) == 1
    assert findings[0].filepath.endswith("schema.sql")


def test_star_language_rule_runs_on_all_supported_files(tmp_path: Path) -> None:
    (tmp_path / "a.js").write_text("console.log(1)")
    (tmp_path / "b.py").write_text("print(1)")
    (tmp_path / "c.sql").write_text("SELECT 1;")

    engine = _make_engine(tmp_path, [_AlwaysFindsRule()])
    assert len(engine.scan()) == 3


# ---------------------------------------------------------------------------
# Tree-sitter parsing
# ---------------------------------------------------------------------------


def test_python_files_are_parsed_to_ast(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("x = 1 + 2")

    received_trees = []

    class _CaptureTree(BaseRule):
        id = "TEST-CAPTURE"
        name = "Capture tree"
        severity = "LOW"
        languages = ["python"]

        def visit(self, tree, source, filepath):
            received_trees.append(tree)
            return []

    engine = _make_engine(tmp_path, [_CaptureTree()])
    engine.scan()

    assert len(received_trees) == 1
    assert received_trees[0] is not None
    assert received_trees[0].root_node.type == "module"


def test_sql_files_receive_none_tree(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text("SELECT 1;")

    received_trees = []

    class _CaptureTree(BaseRule):
        id = "TEST-CAPTURE-SQL"
        name = "Capture tree SQL"
        severity = "LOW"
        languages = ["sql"]

        def visit(self, tree, source, filepath):
            received_trees.append(tree)
            return []

    engine = _make_engine(tmp_path, [_CaptureTree()])
    engine.scan()

    assert received_trees == [None]


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def test_identical_snippets_across_files_are_deduplicated(tmp_path: Path) -> None:
    same_content = "CREATE TABLE users (id int);"
    (tmp_path / "a.sql").write_text(same_content)
    (tmp_path / "b.sql").write_text(same_content)

    engine = _make_engine(tmp_path, [_SqlOnlyRule()])
    findings = engine.scan()

    # _SqlOnlyRule always emits the same snippet regardless of file content
    assert len(findings) == 1


def test_different_snippets_are_not_deduplicated(tmp_path: Path) -> None:
    class _ContentRule(BaseRule):
        id = "TEST-CONTENT"
        name = "Content rule"
        severity = "LOW"
        languages = ["sql"]

        def visit(self, tree, source, filepath):
            return [
                Finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    filepath=filepath,
                    line=1,
                    col=0,
                    snippet=source.decode(),
                    fix="Fix it.",
                )
            ]

    (tmp_path / "a.sql").write_text("SELECT 1;")
    (tmp_path / "b.sql").write_text("SELECT 2;")

    engine = _make_engine(tmp_path, [_ContentRule()])
    assert len(engine.scan()) == 2


def test_findings_sorted_by_severity_then_filepath(tmp_path: Path) -> None:
    class _MultiSeverityRule(BaseRule):
        id = "TEST-MULTI"
        name = "Multi severity"
        severity = "LOW"
        languages = ["sql"]

        def visit(self, tree, source, filepath):
            return [
                Finding(
                    rule_id="TEST-MULTI",
                    rule_name=self.name,
                    severity="LOW",
                    filepath=filepath,
                    line=2,
                    col=0,
                    snippet=f"low:{filepath}",
                    fix="",
                ),
                Finding(
                    rule_id="TEST-MULTI",
                    rule_name=self.name,
                    severity="CRITICAL",
                    filepath=filepath,
                    line=1,
                    col=0,
                    snippet=f"critical:{filepath}",
                    fix="",
                ),
            ]

    (tmp_path / "z.sql").write_text("x")
    (tmp_path / "a.sql").write_text("y")

    engine = _make_engine(tmp_path, [_MultiSeverityRule()])
    findings = engine.scan()

    severities = [f.severity for f in findings]
    assert severities.index("CRITICAL") < severities.index("LOW")


# ---------------------------------------------------------------------------
# Error isolation
# ---------------------------------------------------------------------------


def test_crashing_rule_does_not_abort_scan(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("x = 1")

    engine = _make_engine(tmp_path, [_RaisingRule(), _AlwaysFindsRule()])
    # _RaisingRule crashes but _AlwaysFindsRule should still produce a finding
    findings = engine.scan()
    assert len(findings) == 1
    assert findings[0].rule_id == "TEST-001"


# ---------------------------------------------------------------------------
# Rule auto-discovery smoke test
# ---------------------------------------------------------------------------


def test_auto_discovery_returns_list(tmp_path: Path) -> None:
    # With no rule files in place yet, discovery should return an empty list
    # without crashing. Real rules are tested per-rule in their own test files.
    rules = ScanEngine._discover_rules()  # noqa: SLF001
    assert isinstance(rules, list)
