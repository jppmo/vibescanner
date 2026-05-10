from __future__ import annotations

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
