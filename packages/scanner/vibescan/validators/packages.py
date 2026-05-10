from __future__ import annotations

import json
import logging
import tomllib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

import httpx
import redis as redis_lib

logger = logging.getLogger(__name__)

_TOP_PACKAGES_PATH = Path(__file__).parent.parent / "data" / "top_packages.json"
_TOP_PACKAGES: dict[str, list[str]] = json.loads(_TOP_PACKAGES_PATH.read_text())

_REGISTRY_TIMEOUT = 8.0
_CACHE_TTL = 86_400  # 24 hours
_MAX_WORKERS = 10

Ecosystem = Literal["npm", "pypi"]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class Package:
    """A dependency extracted from a manifest file."""

    name: str
    version_spec: str
    ecosystem: Ecosystem


@dataclass
class RegistryResult:
    """What we learned about a package from the registry."""

    name: str
    ecosystem: Ecosystem
    exists: bool
    first_published: datetime | None = None
    version_count: int = 0
    anomaly_score: float = 0.0
    typosquat_of: str | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Manifest parser
# ---------------------------------------------------------------------------


class PackageManifestParser:
    """Extracts dependencies from common manifest file formats."""

    @staticmethod
    def parse(filename: str, source: bytes) -> list[Package]:
        """Dispatch to the right parser based on filename."""
        name = Path(filename).name
        if name == "package.json":
            return PackageManifestParser._parse_package_json(source)
        if name == "requirements.txt":
            return PackageManifestParser._parse_requirements_txt(source)
        if name == "pyproject.toml":
            return PackageManifestParser._parse_pyproject_toml(source)
        return []

    @staticmethod
    def _parse_package_json(source: bytes) -> list[Package]:
        try:
            data = json.loads(source)
        except json.JSONDecodeError:
            return []

        # Version spec prefixes that indicate a local/workspace package — skip registry lookup
        # "*" as a version in a monorepo always resolves to the local workspace package
        _LOCAL_PREFIXES = ("workspace:", "file:", "link:", "portal:", "/", ".")
        _LOCAL_EXACT = {"*"}

        packages: list[Package] = []
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for name, version_spec in data.get(section, {}).items():
                spec = str(version_spec)
                if spec in _LOCAL_EXACT or any(spec.startswith(p) for p in _LOCAL_PREFIXES):
                    continue  # local/workspace package — never on the public registry
                packages.append(Package(name=name, version_spec=spec, ecosystem="npm"))
        return packages

    @staticmethod
    def _parse_requirements_txt(source: bytes) -> list[Package]:
        packages: list[Package] = []
        for raw_line in source.decode(errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Strip inline comments
            line = line.split("#")[0].strip()
            # Split off version specifier: requests>=2.0, flask==1.1.2, numpy
            import re
            m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)", line)
            if m:
                name = m.group(1).split("[")[0]  # strip extras like requests[security]
                version_spec = line[m.end():]
                packages.append(Package(name=name.lower(), version_spec=version_spec.strip(), ecosystem="pypi"))
        return packages

    @staticmethod
    def _parse_pyproject_toml(source: bytes) -> list[Package]:
        try:
            data = tomllib.loads(source.decode(errors="replace"))
        except Exception:
            return []

        # Collect workspace/local package names declared in [tool.uv.sources]
        # or [tool.poetry.source] so we don't flag our own packages.
        workspace_names: set[str] = set()
        for pkg_name, src in data.get("tool", {}).get("uv", {}).get("sources", {}).items():
            if isinstance(src, dict) and src.get("workspace"):
                workspace_names.add(pkg_name.lower().replace("_", "-"))

        packages: list[Package] = []

        import re

        # PEP 621 style: [project] dependencies
        for dep in data.get("project", {}).get("dependencies", []):
            m = re.match(r"^([A-Za-z0-9_.\-]+)", dep)
            if m:
                name = m.group(1).lower().replace("_", "-")
                if name not in workspace_names:
                    packages.append(Package(name=name, version_spec="", ecosystem="pypi"))

        # Poetry style: [tool.poetry.dependencies]
        for name, spec in data.get("tool", {}).get("poetry", {}).get("dependencies", {}).items():
            if name.lower() == "python":
                continue
            norm = name.lower().replace("_", "-")
            if norm not in workspace_names:
                packages.append(Package(name=norm, version_spec=str(spec), ecosystem="pypi"))

        return packages


# ---------------------------------------------------------------------------
# Registry validator
# ---------------------------------------------------------------------------


class RegistryValidator:
    """Checks packages against npm and PyPI registries.

    Results are cached in Redis for 24 hours. Falls back to uncached
    operation if Redis is unavailable.
    """

    def __init__(self, redis_url: str | None = None) -> None:
        self._redis: redis_lib.Redis | None = None
        if redis_url:
            try:
                client = redis_lib.from_url(redis_url, socket_connect_timeout=2)
                client.ping()
                self._redis = client
                logger.debug("Redis cache connected for package validator")
            except Exception:
                logger.warning("Redis unavailable for package validator — caching disabled")

    def validate_all(self, packages: list[Package]) -> list[RegistryResult]:
        """Check all packages, using cache where available.

        Uncached packages are fetched concurrently (max 10 workers).
        """
        results: list[RegistryResult] = []
        to_fetch: list[Package] = []

        for pkg in packages:
            cached = self._get_cached(pkg)
            if cached is not None:
                results.append(cached)
            else:
                to_fetch.append(pkg)

        if to_fetch:
            fetched = self._fetch_concurrent(to_fetch)
            for result in fetched:
                self._set_cached(result)
            results.extend(fetched)

        return results

    # ------------------------------------------------------------------
    # Fetching
    # ------------------------------------------------------------------

    def _fetch_concurrent(self, packages: list[Package]) -> list[RegistryResult]:
        results: list[RegistryResult] = []
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
            futures = {executor.submit(self._fetch_one, pkg): pkg for pkg in packages}
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception:
                    pkg = futures[future]
                    logger.exception("Unexpected error fetching registry data", extra={"package": pkg.name})
                    results.append(RegistryResult(name=pkg.name, ecosystem=pkg.ecosystem, exists=False, error="fetch_error"))
        return results

    def _fetch_one(self, pkg: Package) -> RegistryResult:
        if pkg.ecosystem == "npm":
            return self._fetch_npm(pkg)
        return self._fetch_pypi(pkg)

    def _fetch_npm(self, pkg: Package) -> RegistryResult:
        url = f"https://registry.npmjs.org/{pkg.name}"
        try:
            with httpx.Client(timeout=_REGISTRY_TIMEOUT) as client:
                resp = client.get(url)
        except httpx.RequestError as exc:
            return RegistryResult(name=pkg.name, ecosystem="npm", exists=False, error=str(exc))

        if resp.status_code == 404:
            result = RegistryResult(name=pkg.name, ecosystem="npm", exists=False)
            result.typosquat_of = _nearest_typosquat(pkg.name, "npm")
            return result

        if resp.status_code != 200:
            return RegistryResult(name=pkg.name, ecosystem="npm", exists=True, error=f"http_{resp.status_code}")

        try:
            data = resp.json()
        except Exception:
            return RegistryResult(name=pkg.name, ecosystem="npm", exists=True, error="parse_error")

        time_data = data.get("time", {})
        created_str = time_data.get("created")
        first_published = _parse_iso(created_str)
        version_count = max(0, len(time_data) - 2)  # subtract "created" and "modified" keys

        result = RegistryResult(
            name=pkg.name,
            ecosystem="npm",
            exists=True,
            first_published=first_published,
            version_count=version_count,
        )
        result.anomaly_score = _compute_anomaly_score(result)
        result.typosquat_of = _nearest_typosquat(pkg.name, "npm")
        return result

    def _fetch_pypi(self, pkg: Package) -> RegistryResult:
        url = f"https://pypi.org/pypi/{pkg.name}/json"
        try:
            with httpx.Client(timeout=_REGISTRY_TIMEOUT) as client:
                resp = client.get(url)
        except httpx.RequestError as exc:
            return RegistryResult(name=pkg.name, ecosystem="pypi", exists=False, error=str(exc))

        if resp.status_code == 404:
            result = RegistryResult(name=pkg.name, ecosystem="pypi", exists=False)
            result.typosquat_of = _nearest_typosquat(pkg.name, "pypi")
            return result

        if resp.status_code != 200:
            return RegistryResult(name=pkg.name, ecosystem="pypi", exists=True, error=f"http_{resp.status_code}")

        try:
            data = resp.json()
        except Exception:
            return RegistryResult(name=pkg.name, ecosystem="pypi", exists=True, error="parse_error")

        releases = data.get("releases", {})
        version_count = len(releases)

        # Find earliest upload time across all releases
        first_published: datetime | None = None
        for release_files in releases.values():
            for f in release_files:
                t = _parse_iso(f.get("upload_time"))
                if t and (first_published is None or t < first_published):
                    first_published = t

        result = RegistryResult(
            name=pkg.name,
            ecosystem="pypi",
            exists=True,
            first_published=first_published,
            version_count=version_count,
        )
        result.anomaly_score = _compute_anomaly_score(result)
        result.typosquat_of = _nearest_typosquat(pkg.name, "pypi")
        return result

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------

    def _cache_key(self, pkg: Package) -> str:
        return f"vibescan:registry:{pkg.ecosystem}:{pkg.name}"

    def _get_cached(self, pkg: Package) -> RegistryResult | None:
        if self._redis is None:
            return None
        try:
            raw = self._redis.get(self._cache_key(pkg))
            if raw:
                return _result_from_dict(json.loads(raw))
        except Exception:
            logger.debug("Cache read failed", extra={"package": pkg.name})
        return None

    def _set_cached(self, result: RegistryResult) -> None:
        if self._redis is None:
            return
        try:
            pkg = Package(name=result.name, version_spec="", ecosystem=result.ecosystem)
            self._redis.set(self._cache_key(pkg), json.dumps(_result_to_dict(result)), ex=_CACHE_TTL)
        except Exception:
            logger.debug("Cache write failed", extra={"package": result.name})


# ---------------------------------------------------------------------------
# Anomaly scoring
# ---------------------------------------------------------------------------


def _compute_anomaly_score(result: RegistryResult) -> float:
    """Score 0.0–1.0. Higher = more suspicious."""
    score = 0.0

    if result.first_published:
        age = datetime.now(UTC) - result.first_published.replace(tzinfo=UTC) if result.first_published.tzinfo is None else datetime.now(UTC) - result.first_published
        if age < timedelta(days=30):
            score += 0.4

    if result.version_count == 1:
        score += 0.3
    elif result.version_count == 0:
        score += 0.2

    if len(result.name) <= 2:
        score += 0.2

    return min(score, 1.0)


# ---------------------------------------------------------------------------
# Typosquat detection
# ---------------------------------------------------------------------------


def _levenshtein(a: str, b: str) -> int:
    """Standard dynamic-programming Levenshtein distance."""
    if abs(len(a) - len(b)) > 2:
        return 3  # early exit — we only care about distance ≤ 2
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[:]
        dp[0] = i
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[j] = prev[j - 1]
            else:
                dp[j] = 1 + min(prev[j], dp[j - 1], prev[j - 1])
    return dp[n]


def _nearest_typosquat(name: str, ecosystem: Ecosystem) -> str | None:
    """Return the popular package this name is suspiciously close to, or None."""
    name_lower = name.lower()
    # PyPI normalises hyphens and underscores as equivalent
    name_norm = name_lower.replace("_", "-") if ecosystem == "pypi" else name_lower
    popular_list = _TOP_PACKAGES.get(ecosystem, [])
    popular_set = set(popular_list)
    # If the package itself IS popular, it cannot be a typosquat — check before
    # iterating to avoid early-return on a differently-ordered near-neighbour.
    if name_norm in popular_set or name_lower in popular_set:
        return None
    for popular in popular_list:
        if _levenshtein(name_norm, popular) <= 1:
            return popular
    return None


# ---------------------------------------------------------------------------
# Cache serialisation helpers
# ---------------------------------------------------------------------------


def _result_to_dict(r: RegistryResult) -> dict:
    return {
        "name": r.name,
        "ecosystem": r.ecosystem,
        "exists": r.exists,
        "first_published": r.first_published.isoformat() if r.first_published else None,
        "version_count": r.version_count,
        "anomaly_score": r.anomaly_score,
        "typosquat_of": r.typosquat_of,
        "error": r.error,
    }


def _result_from_dict(d: dict) -> RegistryResult:
    return RegistryResult(
        name=d["name"],
        ecosystem=d["ecosystem"],
        exists=d["exists"],
        first_published=_parse_iso(d.get("first_published")),
        version_count=d.get("version_count", 0),
        anomaly_score=d.get("anomaly_score", 0.0),
        typosquat_of=d.get("typosquat_of"),
        error=d.get("error"),
    )


def _parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.rstrip("Z"))
    except ValueError:
        return None
