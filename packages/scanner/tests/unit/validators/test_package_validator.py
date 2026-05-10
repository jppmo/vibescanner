from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vibescan.validators.packages import (
    Package,
    PackageManifestParser,
    RegistryResult,
    RegistryValidator,
    _compute_anomaly_score,
    _levenshtein,
    _nearest_typosquat,
)

FIXTURES = Path(__file__).parents[2] / "fixtures" / "VCS-006"


# ---------------------------------------------------------------------------
# Levenshtein distance
# ---------------------------------------------------------------------------


def test_identical_strings_distance_zero():
    assert _levenshtein("requests", "requests") == 0


def test_single_char_difference():
    assert _levenshtein("requets", "requests") == 1


def test_single_insertion():
    assert _levenshtein("expresss", "express") == 1


def test_transposition():
    assert _levenshtein("flassk", "flask") == 1


def test_very_different_strings_returns_three():
    assert _levenshtein("abc", "xyz123") == 3


# ---------------------------------------------------------------------------
# Typosquat detection
# ---------------------------------------------------------------------------


def test_exact_match_not_flagged():
    assert _nearest_typosquat("requests", "pypi") is None


def test_one_edit_away_flagged():
    assert _nearest_typosquat("requets", "pypi") == "requests"


def test_typosquat_npm():
    assert _nearest_typosquat("expresss", "npm") == "express"


def test_unrelated_name_not_flagged():
    assert _nearest_typosquat("my-totally-unique-package-xyz", "npm") is None


def test_case_insensitive():
    assert _nearest_typosquat("REQUETS", "pypi") == "requests"


# ---------------------------------------------------------------------------
# Anomaly scoring
# ---------------------------------------------------------------------------


def test_recent_package_scores_high():
    result = RegistryResult(
        name="newpkg",
        ecosystem="npm",
        exists=True,
        first_published=datetime.now(UTC) - timedelta(days=5),
        version_count=1,
    )
    score = _compute_anomaly_score(result)
    assert score >= 0.7


def test_old_established_package_scores_zero():
    result = RegistryResult(
        name="lodash",
        ecosystem="npm",
        exists=True,
        first_published=datetime.now(UTC) - timedelta(days=3000),
        version_count=50,
    )
    assert _compute_anomaly_score(result) == 0.0


def test_single_version_adds_score():
    result = RegistryResult(
        name="pkg",
        ecosystem="npm",
        exists=True,
        first_published=datetime.now(UTC) - timedelta(days=500),
        version_count=1,
    )
    assert _compute_anomaly_score(result) > 0


def test_score_capped_at_one():
    result = RegistryResult(
        name="x",
        ecosystem="npm",
        exists=True,
        first_published=datetime.now(UTC) - timedelta(days=1),
        version_count=1,
    )
    assert _compute_anomaly_score(result) <= 1.0


# ---------------------------------------------------------------------------
# Manifest parser — package.json
# ---------------------------------------------------------------------------


def test_package_json_parses_dependencies():
    source = b'{"dependencies": {"react": "^18.0.0", "lodash": "^4.0.0"}}'
    pkgs = PackageManifestParser.parse("package.json", source)
    names = {p.name for p in pkgs}
    assert "react" in names
    assert "lodash" in names


def test_package_json_includes_dev_dependencies():
    source = b'{"devDependencies": {"jest": "^29.0.0"}}'
    pkgs = PackageManifestParser.parse("package.json", source)
    assert any(p.name == "jest" for p in pkgs)


def test_package_json_all_are_npm():
    source = b'{"dependencies": {"react": "18"}}'
    pkgs = PackageManifestParser.parse("package.json", source)
    assert all(p.ecosystem == "npm" for p in pkgs)


def test_package_json_invalid_json_returns_empty():
    pkgs = PackageManifestParser.parse("package.json", b"not json")
    assert pkgs == []


def test_package_json_fixture():
    source = (FIXTURES / "vulnerable_package.json").read_bytes()
    pkgs = PackageManifestParser.parse("package.json", source)
    names = {p.name for p in pkgs}
    assert "expresss" in names
    assert "supabse-js" in names
    assert "react" in names


# ---------------------------------------------------------------------------
# Manifest parser — requirements.txt
# ---------------------------------------------------------------------------


def test_requirements_txt_parses_packages():
    source = b"requests>=2.0\nflask==2.0\nnumpy\n"
    pkgs = PackageManifestParser.parse("requirements.txt", source)
    names = {p.name for p in pkgs}
    assert {"requests", "flask", "numpy"} == names


def test_requirements_txt_skips_comments():
    source = b"# this is a comment\nrequests>=2.0\n"
    pkgs = PackageManifestParser.parse("requirements.txt", source)
    assert len(pkgs) == 1


def test_requirements_txt_skips_dash_r():
    source = b"-r base.txt\nrequests\n"
    pkgs = PackageManifestParser.parse("requirements.txt", source)
    assert len(pkgs) == 1


def test_requirements_txt_strips_extras():
    source = b"requests[security]>=2.0\n"
    pkgs = PackageManifestParser.parse("requirements.txt", source)
    assert pkgs[0].name == "requests"


def test_requirements_txt_all_are_pypi():
    source = b"flask\ndjango\n"
    pkgs = PackageManifestParser.parse("requirements.txt", source)
    assert all(p.ecosystem == "pypi" for p in pkgs)


def test_requirements_txt_fixture():
    source = (FIXTURES / "vulnerable_requirements.txt").read_bytes()
    pkgs = PackageManifestParser.parse("requirements.txt", source)
    names = {p.name for p in pkgs}
    assert "requets" in names
    assert "sqlalchamy" in names


# ---------------------------------------------------------------------------
# Manifest parser — pyproject.toml
# ---------------------------------------------------------------------------


def test_pyproject_toml_pep621_style():
    source = b'[project]\ndependencies = ["requests>=2.0", "flask"]\n'
    pkgs = PackageManifestParser.parse("pyproject.toml", source)
    names = {p.name for p in pkgs}
    assert "requests" in names and "flask" in names


def test_pyproject_toml_poetry_style():
    source = b'[tool.poetry.dependencies]\npython = "^3.12"\nflask = "^2.0"\n'
    pkgs = PackageManifestParser.parse("pyproject.toml", source)
    names = {p.name for p in pkgs}
    assert "flask" in names
    assert "python" not in names  # python itself is skipped


def test_pyproject_toml_invalid_returns_empty():
    pkgs = PackageManifestParser.parse("pyproject.toml", b"not toml !!!")
    assert pkgs == []


# ---------------------------------------------------------------------------
# Unknown filename returns empty
# ---------------------------------------------------------------------------


def test_unknown_filename_returns_empty():
    assert PackageManifestParser.parse("Makefile", b"install: pip install -r req.txt") == []


# ---------------------------------------------------------------------------
# RegistryValidator — mocked HTTP
# ---------------------------------------------------------------------------


def _make_npm_response(name: str, created: str, versions: list[str]) -> dict:
    time_data = {"created": created, "modified": created}
    for v in versions:
        time_data[v] = created
    return {"name": name, "time": time_data, "versions": {v: {} for v in versions}}


def _make_pypi_response(name: str, upload_time: str, versions: list[str]) -> dict:
    releases = {v: [{"upload_time": upload_time}] for v in versions}
    return {"info": {"name": name, "version": versions[-1]}, "releases": releases}


@pytest.fixture
def validator():
    return RegistryValidator(redis_url=None)


def test_validator_returns_not_exists_on_404(validator):
    pkg = Package(name="fake-pkg-xyz", version_spec="^1.0", ecosystem="npm")

    mock_resp = MagicMock()
    mock_resp.status_code = 404

    with patch("vibescan.validators.packages.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp
        results = validator.validate_all([pkg])

    assert len(results) == 1
    assert results[0].exists is False


def test_validator_returns_exists_on_200(validator):
    pkg = Package(name="lodash", version_spec="^4.0", ecosystem="npm")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = _make_npm_response(
        "lodash", "2012-04-23T00:00:00.000Z", ["4.0.0", "4.17.21"]
    )

    with patch("vibescan.validators.packages.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp
        results = validator.validate_all([pkg])

    assert results[0].exists is True
    assert results[0].version_count == 2


def test_validator_pypi_404(validator):
    pkg = Package(name="totally-fake-lib", version_spec="", ecosystem="pypi")

    mock_resp = MagicMock()
    mock_resp.status_code = 404

    with patch("vibescan.validators.packages.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp
        results = validator.validate_all([pkg])

    assert results[0].exists is False


def test_validator_uses_cache_on_second_call(validator):
    pkg = Package(name="cached-pkg", version_spec="", ecosystem="npm")

    mock_redis = MagicMock()
    mock_redis.get.return_value = None  # cache miss first call

    mock_resp = MagicMock()
    mock_resp.status_code = 404

    validator._redis = mock_redis

    with patch("vibescan.validators.packages.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp
        validator.validate_all([pkg])

    # Should have attempted to write to cache after fetch
    assert mock_redis.set.called


def test_validator_network_error_returns_result(validator):
    pkg = Package(name="some-pkg", version_spec="", ecosystem="npm")

    with patch("vibescan.validators.packages.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.get.side_effect = Exception("timeout")
        results = validator.validate_all([pkg])

    assert len(results) == 1
    assert results[0].error is not None
