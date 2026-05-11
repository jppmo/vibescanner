from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


class DiffError(Exception):
    """Raised when a diff cannot be resolved (not a git repo, bad ref, etc.)."""


_LOCK_FILES: frozenset[str] = frozenset({
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "go.sum",
    "Cargo.lock",
    "composer.lock",
    "Gemfile.lock",
})

_GENERATED_PREFIXES: tuple[str, ...] = (
    "dist/",
    "build/",
    "node_modules/",
    "vendor/",
    "__pycache__/",
    ".next/",
    ".nuxt/",
    "coverage/",
)

_GENERATED_SUFFIXES: tuple[str, ...] = (".min.js", ".min.css", ".map")

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)


def _is_noise(rel_path: str) -> bool:
    """True if the path is a lock file, generated artefact, or vendored code."""
    name = Path(rel_path).name
    if name in _LOCK_FILES:
        return True
    if any(rel_path.startswith(p) for p in _GENERATED_PREFIXES):
        return True
    return any(rel_path.endswith(s) for s in _GENERATED_SUFFIXES)


def _run_git(args: list[str], cwd: Path) -> str:
    try:
        result = subprocess.run(  # noqa: S603
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (FileNotFoundError, OSError) as exc:
        msg = f"git not available: {exc}"
        raise DiffError(msg) from exc

    if result.returncode != 0:
        stderr = result.stderr.strip()
        msg = f"git {' '.join(args)} failed: {stderr}"
        raise DiffError(msg)

    return result.stdout


def _resolve_range(spec: str) -> tuple[str, str]:
    """Turn a user-supplied range spec into (base, head).

    Accepts:
      - "origin/main"           -> base=origin/main, head=HEAD
      - "origin/main..HEAD"     -> base=origin/main, head=HEAD
      - "abc123..def456"        -> base=abc123, head=def456
      - "HEAD~5"                -> base=HEAD~5, head=HEAD
    """
    if ".." in spec:
        base, head = spec.split("..", 1)
        return (base.strip() or "HEAD", head.strip() or "HEAD")
    return (spec.strip(), "HEAD")


@dataclass
class DiffContext:
    """Snapshot of a git diff: which files/lines changed and when.

    All paths are stored relative to the repo root.
    """

    base: str
    head: str
    repo_path: Path
    changed_files: set[str] = field(default_factory=set)
    changed_lines: dict[str, set[int]] = field(default_factory=dict)
    added_packages: dict[str, set[str]] = field(default_factory=dict)
    elapsed_seconds: int = 0
    commit_count: int = 0
    net_loc_added: int = 0

    def file_in_diff(self, abs_path: Path) -> bool:
        """True if abs_path is among the changed files."""
        try:
            rel = abs_path.relative_to(self.repo_path).as_posix()
        except ValueError:
            return False
        return rel in self.changed_files

    def line_in_diff(self, abs_path: Path, line: int) -> bool:
        """True if (abs_path, line) is in the diff. Used to filter findings."""
        try:
            rel = abs_path.relative_to(self.repo_path).as_posix()
        except ValueError:
            return False
        return line in self.changed_lines.get(rel, set())

    @property
    def loc_per_minute(self) -> float:
        if self.elapsed_seconds <= 0:
            return 0.0
        return round(self.net_loc_added / (self.elapsed_seconds / 60), 1)

    @classmethod
    def from_git(cls, repo_path: Path, range_spec: str) -> DiffContext:
        """Build a DiffContext by shelling out to git.

        Raises DiffError if the repo or the range can't be resolved.
        """
        repo_path = repo_path.resolve()
        if not (repo_path / ".git").exists():
            msg = f"{repo_path} is not a git repository"
            raise DiffError(msg)

        base, head = _resolve_range(range_spec)
        ctx = cls(base=base, head=head, repo_path=repo_path)

        ctx._populate_changed_files(base, head)
        ctx._populate_changed_lines(base, head)
        ctx._populate_added_packages(base, head)
        ctx._populate_velocity(base, head)

        logger.info(
            "DiffContext built",
            extra={
                "base": base,
                "head": head,
                "files": len(ctx.changed_files),
                "lines": sum(len(v) for v in ctx.changed_lines.values()),
                "loc_per_min": ctx.loc_per_minute,
            },
        )
        return ctx

    def _populate_changed_files(self, base: str, head: str) -> None:
        out = _run_git(
            ["diff", "--name-only", "--diff-filter=ACMR", f"{base}..{head}"],
            cwd=self.repo_path,
        )
        for line in out.splitlines():
            rel = line.strip()
            if not rel or _is_noise(rel):
                continue
            self.changed_files.add(rel)

    def _populate_changed_lines(self, base: str, head: str) -> None:
        out = _run_git(
            ["diff", "--unified=0", "--no-color", f"{base}..{head}"],
            cwd=self.repo_path,
        )
        current_file: str | None = None
        for raw in out.splitlines():
            if raw.startswith("+++ b/"):
                rel = raw[6:]
                current_file = rel if rel in self.changed_files else None
                continue
            if raw.startswith("+++ "):
                current_file = None
                continue
            if not raw.startswith("@@") or current_file is None:
                continue
            m = _HUNK_RE.match(raw)
            if not m:
                continue
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) else 1
            if count == 0:
                continue
            line_set = self.changed_lines.setdefault(current_file, set())
            for i in range(start, start + count):
                line_set.add(i)

    def _populate_added_packages(self, base: str, head: str) -> None:
        """For each changed manifest, record the package names added in the diff."""
        manifest_names = ("package.json", "requirements.txt", "pyproject.toml")
        manifests = [f for f in self.changed_files if Path(f).name in manifest_names]
        for rel in manifests:
            try:
                out = _run_git(
                    ["diff", "--unified=0", "--no-color", f"{base}..{head}", "--", rel],
                    cwd=self.repo_path,
                )
            except DiffError:
                continue
            added: set[str] = set()
            for raw in out.splitlines():
                if not raw.startswith("+") or raw.startswith("+++"):
                    continue
                added.update(_extract_package_names(raw[1:]))
            if added:
                self.added_packages[rel] = added

    def _populate_velocity(self, base: str, head: str) -> None:
        """Compute commit count, elapsed wall time, and net LOC added (excl. noise)."""
        log_out = _run_git(
            ["log", "--format=%ct", f"{base}..{head}"],
            cwd=self.repo_path,
        )
        timestamps = [int(t) for t in log_out.splitlines() if t.strip().isdigit()]
        self.commit_count = len(timestamps)
        if len(timestamps) >= 2:
            self.elapsed_seconds = max(timestamps) - min(timestamps)

        numstat_out = _run_git(
            ["diff", "--numstat", f"{base}..{head}"],
            cwd=self.repo_path,
        )
        net = 0
        for raw in numstat_out.splitlines():
            parts = raw.split("\t")
            if len(parts) < 3:
                continue
            added_s, removed_s, path = parts[0], parts[1], parts[2]
            if added_s == "-" or removed_s == "-":
                continue
            if _is_noise(path):
                continue
            try:
                net += int(added_s) - int(removed_s)
            except ValueError:
                continue
        self.net_loc_added = max(net, 0)


_PKG_JSON_RE = re.compile(r'"([^"@\s/][^"]*?)"\s*:\s*"[^"]*"')
_REQ_TXT_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_PYPROJECT_RE = re.compile(r'"([A-Za-z0-9][A-Za-z0-9._-]*)\s*[<>=!~^]')


def _extract_package_names(line: str) -> set[str]:
    """Best-effort extraction of package names from a single added line.

    Used only to scope VCS-006 in --diff mode; full validation still happens
    against the parsed manifest.
    """
    names: set[str] = set()
    stripped = line.strip()
    if not stripped:
        return names

    for m in _PKG_JSON_RE.finditer(line):
        candidate = m.group(1)
        if not candidate:
            continue
        is_unscoped = not candidate.startswith(("@", "/")) and "/" not in candidate
        is_scoped = candidate.startswith("@") and "/" in candidate
        if is_unscoped or is_scoped:
            names.add(candidate)

    req_match = _REQ_TXT_RE.match(stripped)
    if req_match:
        candidate = req_match.group(1)
        if candidate.lower() not in ("from", "import"):
            names.add(candidate)

    for m in _PYPROJECT_RE.finditer(line):
        names.add(m.group(1))

    return names
