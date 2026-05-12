from __future__ import annotations

import importlib
import inspect
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

import tree_sitter_javascript as ts_js
import tree_sitter_python as ts_py
import tree_sitter_typescript as ts_ts
from tree_sitter import Language, Parser

from vibescan.origin.detector import AIOriginDetector
from vibescan.rules.base import BaseRule

if TYPE_CHECKING:
    from collections.abc import Iterator

    from tree_sitter import Tree

    from vibescan.diff.context import DiffContext
    from vibescan.models import Finding

logger = logging.getLogger(__name__)

# Extensions we handle and the language name each maps to
EXTENSION_TO_LANGUAGE: dict[str, str] = {
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".py": "python",
    ".sql": "sql",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".tf": "terraform",
    ".toml": "toml",
    ".txt": "text",
    ".rules": "firebase_rules",
    ".pem": "pem",
    ".key": "pem",
    ".env": "env",  # catches app.env style files and test fixtures
}

# Extensionless filenames that are always private keys
_BARE_KEY_NAMES: frozenset[str] = frozenset({"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"})


def _language_for(filepath: Path) -> str | None:
    """Return language tag for a file, applying name-based rules before extension lookup."""
    name = filepath.name.lower()
    # Dotenv files: .env, .env.local, .env.production, .env.test, etc.
    if name == ".env" or name.startswith(".env."):
        return "env"
    # Extensionless SSH/OpenSSH private key files
    if name in _BARE_KEY_NAMES:
        return "pem"
    return EXTENSION_TO_LANGUAGE.get(filepath.suffix.lower())

# Languages that have a tree-sitter grammar — all others get tree=None
AST_LANGUAGES: frozenset[str] = frozenset({"javascript", "typescript", "tsx", "python"})

# Directories that are never worth scanning
SKIP_DIRS: frozenset[str] = frozenset({
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".ruff_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "coverage",
    "htmlcov",
})

# Skip files larger than 1 MB — they're almost certainly generated or binary
MAX_FILE_BYTES = 1024 * 1024


def _load_ignore_patterns(repo_path: Path) -> list[str]:
    """Read .vibescanignore and return path prefixes/patterns to skip."""
    ignore_file = repo_path / ".vibescanignore"
    if not ignore_file.exists():
        return []
    patterns = []
    for raw in ignore_file.read_text().splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            patterns.append(line.rstrip("/"))
    return patterns


def _is_ignored(path: Path, repo_path: Path, patterns: list[str]) -> bool:
    try:
        rel = path.relative_to(repo_path).as_posix()
    except ValueError:
        return False
    return any(rel == p or rel.startswith(p + "/") for p in patterns)


class ScanEngine:
    """Orchestrates file discovery, parsing, and rule execution for a repo."""

    def __init__(self, repo_path: str | Path, diff_context: DiffContext | None = None) -> None:
        self.repo_path = Path(repo_path).resolve()
        self.diff_context = diff_context
        self._ignore_patterns = _load_ignore_patterns(self.repo_path)
        self._parsers = self._build_parsers()
        self._rules = self._discover_rules()
        self._origin = AIOriginDetector()
        self._origin.warmup(self.repo_path, diff_context=diff_context)
        logger.info(
            "ScanEngine ready",
            extra={
                "repo": str(self.repo_path),
                "rules": len(self._rules),
                "diff_mode": diff_context is not None,
            },
        )

    @property
    def repo_ai_score(self) -> float:
        """Repo-level AI origin score (0.0–1.0). 1.0 = hard git signal."""
        return self._origin._repo_score

    @property
    def repo_ai_tool(self) -> str | None:
        """Name of the AI tool detected in git history, or None."""
        return self._origin.git_tool

    @property
    def velocity_label(self) -> str | None:
        """Velocity description if velocity signal fired, else None."""
        return self._origin.velocity_label

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self) -> list[Finding]:
        """Run all rules against every file in the repo.

        Returns:
            Deduplicated list of findings sorted by severity then filepath.
        """
        findings: list[Finding] = []

        for rule in self._rules:
            rule.diff_context = self.diff_context

        for filepath in self._discover_files():
            language = _language_for(filepath)
            if language is None:
                continue

            try:
                source = filepath.read_bytes()
            except OSError:
                logger.warning("Could not read file, skipping", extra={"file": str(filepath)})
                continue

            tree = self._parse(source, language)
            applicable = self._rules_for(language)
            origin_score = self._origin.score_file(source, language)

            for rule in applicable:
                try:
                    found = rule.visit(tree, source, str(filepath))
                    for f in found:
                        f.ai_origin_score = origin_score
                    findings.extend(found)
                except Exception:
                    logger.exception(
                        "Rule raised an unexpected error",
                        extra={"rule": rule.id, "file": str(filepath)},
                    )

        if self.diff_context is not None:
            findings = self._filter_to_diff(findings)

        return self._deduplicate(findings)

    def _filter_to_diff(self, findings: list[Finding]) -> list[Finding]:
        """Drop findings whose line is not within a changed line range."""
        ctx = self.diff_context
        if ctx is None:
            return findings
        kept: list[Finding] = []
        for f in findings:
            try:
                fp = Path(f.filepath)
                if ctx.line_in_diff(fp, f.line):
                    kept.append(f)
            except (ValueError, OSError):
                continue
        return kept

    # ------------------------------------------------------------------
    # File discovery
    # ------------------------------------------------------------------

    def _discover_files(self) -> Iterator[Path]:
        if self.diff_context is not None:
            for rel in sorted(self.diff_context.changed_files):
                path = self.repo_path / rel
                if not path.is_file():
                    continue
                try:
                    size = path.stat().st_size
                except OSError:
                    continue
                if size > MAX_FILE_BYTES:
                    continue
                yield path
            return

        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            for name in sorted(files):
                path = Path(root) / name
                if _is_ignored(path, self.repo_path, self._ignore_patterns):
                    continue
                try:
                    size = path.stat().st_size
                except OSError:
                    continue
                if size > MAX_FILE_BYTES:
                    logger.debug("Skipping oversized file", extra={"file": str(path)})
                    continue
                yield path

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse(self, source: bytes, language: str) -> Tree | None:
        parser = self._parsers.get(language)
        if parser is None:
            return None
        return parser.parse(source)

    @staticmethod
    def _build_parsers() -> dict[str, Parser]:
        return {
            "python": Parser(Language(ts_py.language())),
            "javascript": Parser(Language(ts_js.language())),
            "typescript": Parser(Language(ts_ts.language_typescript())),
            "tsx": Parser(Language(ts_ts.language_tsx())),
        }

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------

    def _rules_for(self, language: str) -> list[BaseRule]:
        return [r for r in self._rules if language in r.languages or "*" in r.languages]

    @staticmethod
    def _discover_rules() -> list[BaseRule]:
        """Import every module in vibescan/rules/ and collect BaseRule subclasses."""
        rules_dir = Path(__file__).parent / "rules"
        rules: list[BaseRule] = []
        seen_ids: set[str] = set()

        for path in sorted(rules_dir.glob("*.py")):
            if path.stem.startswith("_") or path.stem == "base":
                continue

            module_name = f"vibescan.rules.{path.stem}"
            try:
                module = importlib.import_module(module_name)
            except Exception:
                logger.exception("Failed to import rule module", extra={"rule_module": module_name})
                continue

            for _, obj in inspect.getmembers(module, inspect.isclass):
                if not issubclass(obj, BaseRule) or obj is BaseRule:
                    continue
                if not hasattr(obj, "id"):
                    logger.warning("Rule class missing 'id', skipping", extra={"class": obj.__name__})
                    continue
                if obj.id in seen_ids:
                    logger.warning("Duplicate rule id, skipping", extra={"id": obj.id})
                    continue
                seen_ids.add(obj.id)
                rules.append(obj())
                logger.debug("Registered rule", extra={"id": obj.id})

        return rules

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        seen: set[str] = set()
        unique: list[Finding] = []
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

        for finding in sorted(findings, key=lambda f: (severity_order[f.severity], f.filepath, f.line)):
            key = finding.dedup_key()
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique
