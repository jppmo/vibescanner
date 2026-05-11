from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import ClassVar

from vibescan.models import Finding
from vibescan.rules.base import BaseRule
from vibescan.validators.packages import PackageManifestParser, RegistryValidator

logger = logging.getLogger(__name__)

_MANIFEST_FILENAMES = frozenset({
    "package.json",
    "requirements.txt",
    "pyproject.toml",
})

_ANOMALY_THRESHOLD = 0.7


def _get_validator() -> RegistryValidator:
    return RegistryValidator(redis_url=os.getenv("REDIS_URL"))


def _workspace_package_names(manifest_path: Path) -> set[str]:
    """Find package names declared in a parent monorepo's `workspaces` field.

    Walks up from manifest_path looking for the first ancestor package.json
    that declares `workspaces`. Globs the workspace patterns and collects the
    `name` field of every matching package.json. Returns the lowercased name
    set, or empty if no parent monorepo is found.
    """
    if manifest_path.name != "package.json":
        return set()

    current = manifest_path.parent.parent
    seen_roots: set[Path] = set()
    while current and current not in seen_roots and current != current.parent:
        seen_roots.add(current)
        parent_pkg = current / "package.json"
        if parent_pkg.exists() and parent_pkg.resolve() != manifest_path.resolve():
            try:
                data = json.loads(parent_pkg.read_text())
            except (OSError, json.JSONDecodeError):
                data = None
            if data is not None:
                workspaces = data.get("workspaces")
                patterns: list[str] = []
                if isinstance(workspaces, list):
                    patterns = [str(p) for p in workspaces]
                elif isinstance(workspaces, dict):
                    patterns = [str(p) for p in workspaces.get("packages", [])]
                if patterns:
                    return _collect_workspace_names(current, patterns)
        current = current.parent
    return set()


def _collect_workspace_names(root: Path, patterns: list[str]) -> set[str]:
    names: set[str] = set()
    for pattern in patterns:
        clean = pattern.rstrip("/").lstrip("./")
        if not clean:
            continue
        try:
            for match in root.glob(clean):
                pkg_json = match / "package.json"
                if not pkg_json.is_file():
                    continue
                try:
                    name = json.loads(pkg_json.read_text()).get("name")
                except (OSError, json.JSONDecodeError):
                    continue
                if isinstance(name, str) and name:
                    names.add(name.lower())
        except (OSError, ValueError):
            continue
    return names


class HallucinatedPackageRule(BaseRule):
    """Detect npm and PyPI packages that don't exist or look suspicious.

    AI code generators hallucinate package names. A hallucinated package
    imported by a real project becomes an install-time supply-chain attack
    vector — an attacker can publish the fake name and have it executed
    automatically by anyone who runs `npm install` or `pip install`.

    Three findings this rule emits:
    - CRITICAL: package returns 404 from the registry — does not exist.
    - HIGH: package exists but has an anomaly score > 0.7 (very new,
      single version, suspiciously short name).
    - HIGH: package name is 1 edit away from a popular package — likely
      a typosquat (e.g. `requets` instead of `requests`).
    """

    id = "VCS-006"
    name = "Hallucinated or suspicious package"
    severity = "CRITICAL"
    languages: ClassVar[list[str]] = ["json", "toml", "text"]

    def __init__(self) -> None:
        self._validator = _get_validator()

    def visit(self, tree, source: bytes, filepath: str) -> list[Finding]:
        filename = Path(filepath).name
        if filename not in _MANIFEST_FILENAMES:
            return []

        packages = PackageManifestParser.parse(filename, source)
        if not packages:
            return []

        # Skip names declared in a parent monorepo's `workspaces` — those are
        # local sibling packages, not external dependencies.
        workspace_names = _workspace_package_names(Path(filepath))
        if workspace_names:
            packages = [p for p in packages if p.name.lower() not in workspace_names]
            if not packages:
                return []

        if self.diff_context is not None:
            try:
                rel = Path(filepath).resolve().relative_to(self.diff_context.repo_path).as_posix()
            except ValueError:
                rel = None
            added = self.diff_context.added_packages.get(rel, set()) if rel else set()
            packages = [p for p in packages if p.name in added]
            if not packages:
                return []

        logger.info(
            "Checking packages",
            extra={"file": filepath, "count": len(packages)},
        )

        results = self._validator.validate_all(packages)
        findings: list[Finding] = []

        for result in results:
            if result.error and result.error != "fetch_error":
                # Registry returned an unexpected status — don't emit a finding
                continue

            if not result.exists:
                fix = (
                    f'"{result.name}" was not found on '
                    f'{"npm" if result.ecosystem == "npm" else "PyPI"}. '
                    "Remove it or replace it with the correct package name.\n"
                )
                if result.typosquat_of:
                    fix += f'Did you mean "{result.typosquat_of}"?'

                findings.append(
                    Finding(
                        rule_id=self.id,
                        rule_name=self.name,
                        severity="CRITICAL",
                        filepath=filepath,
                        line=1,
                        col=0,
                        snippet=f'"{result.name}"',
                        fix=fix,
                    )
                )
                continue

            # Typosquat check: package exists but name is dangerously close to a popular one.
            # Only flag if the package also looks suspicious (elevated anomaly score) —
            # established packages that happen to be 1 edit from another popular package
            # (e.g. jsdoc vs jsdom) are not typosquats.
            if result.typosquat_of and result.anomaly_score >= 0.3:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        rule_name=self.name,
                        severity="HIGH",
                        filepath=filepath,
                        line=1,
                        col=0,
                        snippet=f'"{result.name}"',
                        fix=(
                            f'"{result.name}" is 1 edit away from the popular package '
                            f'"{result.typosquat_of}". Verify this is intentional — '
                            f'typosquatting attacks register near-identical names.'
                        ),
                    )
                )

            # Anomaly check (package exists but looks suspicious)
            if result.anomaly_score >= _ANOMALY_THRESHOLD and not result.typosquat_of:
                details: list[str] = []
                if result.first_published:
                    from datetime import UTC, datetime, timedelta
                    age = datetime.now(UTC) - (
                        result.first_published.replace(tzinfo=UTC)
                        if result.first_published.tzinfo is None
                        else result.first_published
                    )
                    if age < timedelta(days=30):
                        details.append(f"published {age.days} days ago")
                if result.version_count <= 1:
                    details.append(f"only {result.version_count} release(s)")

                findings.append(
                    Finding(
                        rule_id=self.id,
                        rule_name=self.name,
                        severity="HIGH",
                        filepath=filepath,
                        line=1,
                        col=0,
                        snippet=f'"{result.name}"',
                        fix=(
                            f'"{result.name}" looks suspicious ({", ".join(details)}). '
                            "Verify this package is legitimate before installing it."
                        ),
                    )
                )

        return findings
