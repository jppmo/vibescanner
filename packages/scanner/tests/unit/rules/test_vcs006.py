from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vibescan.models import Finding
from vibescan.rules.vcs006_hallucinated_packages import HallucinatedPackageRule
from vibescan.validators.packages import RegistryResult

FIXTURES = Path(__file__).parents[2] / "fixtures" / "VCS-006"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(
    name: str,
    ecosystem: str = "npm",
    exists: bool = True,
    first_published_days_ago: int = 3000,
    version_count: int = 20,
    anomaly_score: float = 0.0,
    typosquat_of: str | None = None,
    error: str | None = None,
) -> RegistryResult:
    return RegistryResult(
        name=name,
        ecosystem=ecosystem,
        exists=exists,
        first_published=datetime.now(UTC) - timedelta(days=first_published_days_ago),
        version_count=version_count,
        anomaly_score=anomaly_score,
        typosquat_of=typosquat_of,
        error=error,
    )


def _rule_with_results(results: list[RegistryResult]) -> HallucinatedPackageRule:
    rule = HallucinatedPackageRule.__new__(HallucinatedPackageRule)
    mock_validator = MagicMock()
    mock_validator.validate_all.return_value = results
    rule._validator = mock_validator
    return rule


# ---------------------------------------------------------------------------
# Non-manifest files are skipped
# ---------------------------------------------------------------------------


def test_non_manifest_returns_empty():
    rule = _rule_with_results([])
    findings = rule.visit(None, b"import requests", "app.py")
    assert findings == []


def test_makefile_returns_empty():
    rule = _rule_with_results([])
    findings = rule.visit(None, b"install: pip install -r req.txt", "Makefile")
    assert findings == []


def test_empty_manifest_returns_empty():
    rule = _rule_with_results([])
    findings = rule.visit(None, b"{}", "package.json")
    assert findings == []


# ---------------------------------------------------------------------------
# Non-existent package → CRITICAL
# ---------------------------------------------------------------------------


def test_404_package_emits_critical():
    results = [_make_result("fake-pkg-xyz", exists=False)]
    rule = _rule_with_results(results)
    findings = rule.visit(None, b'{"dependencies": {"fake-pkg-xyz": "^1.0"}}', "package.json")
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert findings[0].rule_id == "VCS-006"


def test_404_fix_mentions_registry():
    results = [_make_result("fake-pkg-xyz", ecosystem="npm", exists=False)]
    rule = _rule_with_results(results)
    findings = rule.visit(None, b'{"dependencies": {"fake-pkg-xyz": "^1.0"}}', "package.json")
    assert "npm" in findings[0].fix


def test_404_pypi_fix_mentions_pypi():
    results = [_make_result("totallyfakepkg", ecosystem="pypi", exists=False)]
    rule = _rule_with_results(results)
    findings = rule.visit(None, b"totallyfakepkg>=1.0\n", "requirements.txt")
    assert "PyPI" in findings[0].fix


def test_404_with_typosquat_suggestion_in_fix():
    results = [_make_result("requets", ecosystem="pypi", exists=False, typosquat_of="requests")]
    rule = _rule_with_results(results)
    findings = rule.visit(None, b"requets>=2.0\n", "requirements.txt")
    assert len(findings) == 1
    assert "requests" in findings[0].fix


def test_multiple_404_packages_each_emit_critical():
    results = [
        _make_result("fake-a", exists=False),
        _make_result("fake-b", exists=False),
    ]
    rule = _rule_with_results(results)
    source = b'{"dependencies": {"fake-a": "^1.0", "fake-b": "^1.0"}}'
    findings = rule.visit(None, source, "package.json")
    assert len(findings) == 2
    assert all(f.severity == "CRITICAL" for f in findings)


# ---------------------------------------------------------------------------
# Typosquat (exists but near a popular name) → HIGH
# ---------------------------------------------------------------------------


def test_typosquat_existing_package_emits_high():
    # A real typosquat is always a newly-published, unknown package — anomaly_score > 0
    results = [_make_result("expresss", typosquat_of="express", anomaly_score=0.5)]
    rule = _rule_with_results(results)
    source = b'{"dependencies": {"expresss": "^4.0"}}'
    findings = rule.visit(None, source, "package.json")
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"


def test_typosquat_fix_names_both_packages():
    results = [_make_result("expresss", typosquat_of="express", anomaly_score=0.5)]
    rule = _rule_with_results(results)
    source = b'{"dependencies": {"expresss": "^4.0"}}'
    findings = rule.visit(None, source, "package.json")
    assert "expresss" in findings[0].fix
    assert "express" in findings[0].fix


def test_typosquat_does_not_also_emit_anomaly():
    # When typosquat_of is set AND anomaly_score is high, only typosquat fires
    results = [_make_result("expresss", typosquat_of="express", anomaly_score=0.9)]
    rule = _rule_with_results(results)
    source = b'{"dependencies": {"expresss": "^4.0"}}'
    findings = rule.visit(None, source, "package.json")
    assert len(findings) == 1  # only one finding, not two


# ---------------------------------------------------------------------------
# Anomaly score → HIGH
# ---------------------------------------------------------------------------


def test_high_anomaly_score_emits_high():
    results = [_make_result("newpkg", anomaly_score=0.9, version_count=1, first_published_days_ago=3)]
    rule = _rule_with_results(results)
    source = b'{"dependencies": {"newpkg": "^1.0"}}'
    findings = rule.visit(None, source, "package.json")
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"


def test_anomaly_below_threshold_no_finding():
    results = [_make_result("established-pkg", anomaly_score=0.3)]
    rule = _rule_with_results(results)
    source = b'{"dependencies": {"established-pkg": "^1.0"}}'
    findings = rule.visit(None, source, "package.json")
    assert findings == []


def test_anomaly_exactly_at_threshold_emits_finding():
    results = [_make_result("borderline", anomaly_score=0.7, version_count=1)]
    rule = _rule_with_results(results)
    source = b'{"dependencies": {"borderline": "^1.0"}}'
    findings = rule.visit(None, source, "package.json")
    assert len(findings) == 1


def test_anomaly_fix_mentions_suspicious():
    results = [_make_result("newpkg", anomaly_score=0.9, version_count=1, first_published_days_ago=3)]
    rule = _rule_with_results(results)
    source = b'{"dependencies": {"newpkg": "^1.0"}}'
    findings = rule.visit(None, source, "package.json")
    assert "suspicious" in findings[0].fix.lower()


# ---------------------------------------------------------------------------
# Clean packages → no findings
# ---------------------------------------------------------------------------


def test_established_package_no_finding():
    results = [_make_result("lodash", anomaly_score=0.0)]
    rule = _rule_with_results(results)
    source = b'{"dependencies": {"lodash": "^4.0"}}'
    findings = rule.visit(None, source, "package.json")
    assert findings == []


def test_clean_requirements_txt_no_findings():
    results = [
        _make_result("flask", ecosystem="pypi"),
        _make_result("requests", ecosystem="pypi"),
    ]
    rule = _rule_with_results(results)
    findings = rule.visit(None, b"flask>=2.0\nrequests>=2.28\n", "requirements.txt")
    assert findings == []


# ---------------------------------------------------------------------------
# Fetch errors are suppressed
# ---------------------------------------------------------------------------


def test_fetch_error_result_not_emitted():
    results = [_make_result("some-pkg", error="fetch_error", exists=False)]
    rule = _rule_with_results(results)
    source = b'{"dependencies": {"some-pkg": "^1.0"}}'
    # error == "fetch_error" — treated as not-exists, so CRITICAL fires
    findings = rule.visit(None, source, "package.json")
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"


def test_unexpected_error_status_suppressed():
    results = [_make_result("some-pkg", error="server_error", exists=False)]
    rule = _rule_with_results(results)
    source = b'{"dependencies": {"some-pkg": "^1.0"}}'
    # error is not "fetch_error", and exists=False — rule skips
    findings = rule.visit(None, source, "package.json")
    assert findings == []


# ---------------------------------------------------------------------------
# Fixture-based integration (mocked validator)
# ---------------------------------------------------------------------------


def test_vulnerable_package_json_fixture():
    results = [
        _make_result("react", exists=True, anomaly_score=0.0),
        _make_result("expresss", exists=True, typosquat_of="express", anomaly_score=0.5),
        _make_result("axios", exists=True, anomaly_score=0.0),
        _make_result("supabse-js", exists=False, typosquat_of="supabase-js"),
    ]
    rule = _rule_with_results(results)
    source = (FIXTURES / "vulnerable_package.json").read_bytes()
    findings = rule.visit(None, source, "package.json")
    severities = {f.severity for f in findings}
    assert "HIGH" in severities   # expresss typosquat
    assert "CRITICAL" in severities  # supabse-js 404


def test_clean_package_json_fixture():
    results = [
        _make_result("react", exists=True),
        _make_result("express", exists=True),
        _make_result("axios", exists=True),
    ]
    rule = _rule_with_results(results)
    source = (FIXTURES / "clean_package.json").read_bytes()
    findings = rule.visit(None, source, "package.json")
    assert findings == []


def test_vulnerable_requirements_txt_fixture():
    results = [
        _make_result("flask", ecosystem="pypi", exists=True),
        _make_result("requets", ecosystem="pypi", exists=False, typosquat_of="requests"),
        _make_result("numpy", ecosystem="pypi", exists=True),
        _make_result("sqlalchamy", ecosystem="pypi", exists=False, typosquat_of="sqlalchemy"),
    ]
    rule = _rule_with_results(results)
    source = (FIXTURES / "vulnerable_requirements.txt").read_bytes()
    findings = rule.visit(None, source, "requirements.txt")
    assert len(findings) == 2
    assert all(f.severity == "CRITICAL" for f in findings)


def test_clean_requirements_txt_fixture():
    results = [
        _make_result("flask", ecosystem="pypi", exists=True),
        _make_result("requests", ecosystem="pypi", exists=True),
        _make_result("numpy", ecosystem="pypi", exists=True),
        _make_result("sqlalchemy", ecosystem="pypi", exists=True),
    ]
    rule = _rule_with_results(results)
    source = (FIXTURES / "clean_requirements.txt").read_bytes()
    findings = rule.visit(None, source, "requirements.txt")
    assert findings == []


# ---------------------------------------------------------------------------
# Regression: workspace packages flagged as hallucinations (corpus FP)
# ---------------------------------------------------------------------------


def test_skips_packages_declared_in_parent_workspaces(tmp_path):
    """A monorepo subpackage depending on a sibling workspace must not be flagged."""
    # Parent package.json with workspaces
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "monorepo-root",
        "private": True,
        "workspaces": ["packages/*"],
    }))

    # Sibling workspace package
    sib = tmp_path / "packages" / "shared-utils"
    sib.mkdir(parents=True)
    (sib / "package.json").write_text(json.dumps({"name": "shared-utils", "version": "1.0.0"}))

    # The package being scanned depends on the sibling
    inner = tmp_path / "packages" / "consumer"
    inner.mkdir()
    inner_pkg = inner / "package.json"
    inner_pkg.write_text(json.dumps({
        "name": "consumer",
        "dependencies": {"shared-utils": "^1.0.0"},
    }))

    # Validator would say shared-utils is 404 — but the rule should never call it
    # because the workspace filter strips the package first.
    results = [_make_result("shared-utils", exists=False)]
    rule = _rule_with_results(results)

    findings = rule.visit(None, inner_pkg.read_bytes(), str(inner_pkg))
    assert findings == []


def test_workspace_object_form_handled(tmp_path):
    """Yarn-style workspaces: {packages: [...]} object form."""
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "monorepo-root",
        "workspaces": {"packages": ["apps/*"]},
    }))

    sib = tmp_path / "apps" / "shared-thing"
    sib.mkdir(parents=True)
    (sib / "package.json").write_text(json.dumps({"name": "shared-thing"}))

    inner = tmp_path / "apps" / "consumer"
    inner.mkdir()
    inner_pkg = inner / "package.json"
    inner_pkg.write_text(json.dumps({
        "name": "consumer",
        "dependencies": {"shared-thing": "*"},
    }))

    results = [_make_result("shared-thing", exists=False)]
    rule = _rule_with_results(results)
    assert rule.visit(None, inner_pkg.read_bytes(), str(inner_pkg)) == []


def test_real_external_dep_in_monorepo_still_fires(tmp_path):
    """A monorepo scan must still flag external hallucinated deps."""
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "root", "workspaces": ["packages/*"],
    }))
    sib = tmp_path / "packages" / "real-sibling"
    sib.mkdir(parents=True)
    (sib / "package.json").write_text(json.dumps({"name": "real-sibling"}))

    inner = tmp_path / "packages" / "consumer"
    inner.mkdir()
    inner_pkg = inner / "package.json"
    inner_pkg.write_text(json.dumps({
        "name": "consumer",
        "dependencies": {"@made-up/never-exists": "^1.0.0"},
    }))

    results = [_make_result("@made-up/never-exists", exists=False)]
    rule = _rule_with_results(results)
    findings = rule.visit(None, inner_pkg.read_bytes(), str(inner_pkg))
    assert len(findings) == 1
    assert findings[0].snippet == '"@made-up/never-exists"'
