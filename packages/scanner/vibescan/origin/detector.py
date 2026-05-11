from __future__ import annotations

import logging
import re
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from vibescan.diff.context import DiffContext

from vibescan.classifier.pattern import PatternClassifier
from vibescan.diff.velocity import PRVelocityDetector

logger = logging.getLogger(__name__)

_AI_COAUTHOR_RE = re.compile(
    r"co-authored-by:.*?(copilot|cursor|claude|chatgpt|gpt-4|devin)",
    re.IGNORECASE,
)

_AI_PLATFORM_RE = re.compile(
    r"generated with (lovable|bolt|replit|v0)\b",
    re.IGNORECASE,
)


class GitMetadataDetector:
    """Detect AI authorship from git commit history.

    Parses the full commit log and returns (score, tool_name).
    score is 1.0 if any commit contains an AI tool Co-authored-by trailer
    or a known platform generation marker; 0.0 otherwise.
    tool_name is the matched tool (e.g. "cursor", "copilot") or None.
    """

    def detect(self, repo_path: Path) -> tuple[float, str | None]:
        try:
            result = subprocess.run(
                ["git", "log", "--format=%B"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return 0.0, None

        if result.returncode != 0:
            return 0.0, None

        log = result.stdout
        m = _AI_COAUTHOR_RE.search(log)
        if m:
            tool = m.group(1).lower()
            logger.info("AI tool signature in git history", extra={"repo": str(repo_path), "tool": tool})
            return 1.0, tool

        m = _AI_PLATFORM_RE.search(log)
        if m:
            tool = m.group(1).lower()
            logger.info("AI platform signature in git history", extra={"repo": str(repo_path), "tool": tool})
            return 1.0, tool

        return 0.0, None


class AIOriginDetector:
    """Combine git-history, velocity, and per-file pattern signals into one score.

    Usage:
        detector = AIOriginDetector()
        detector.warmup(repo_path, diff_context=...)   # once per repo
        score = detector.score_file(source, language)  # per file
    """

    def __init__(self) -> None:
        self._git = GitMetadataDetector()
        self._velocity = PRVelocityDetector()
        self._classifier = PatternClassifier()
        self._repo_score: float = 0.0
        self.git_tool: str | None = None
        self.velocity_label: str | None = None

    def warmup(self, repo_path: Path, diff_context: DiffContext | None = None) -> None:
        """Run repo-level detectors once. Must be called before score_file."""
        score, tool = self._git.detect(repo_path)
        self._repo_score = score
        self.git_tool = tool

        if diff_context is not None:
            v_score, v_label = self._velocity.detect(diff_context)
            self._repo_score = max(self._repo_score, v_score)
            if v_label:
                self.velocity_label = v_label
                if self.git_tool is None:
                    self.git_tool = "velocity"

        if self._repo_score > 0:
            logger.info(
                "Repo-level AI origin score",
                extra={
                    "score": self._repo_score,
                    "tool": self.git_tool,
                    "velocity": self.velocity_label,
                    "repo": str(repo_path),
                },
            )

    def score_file(self, source: bytes, language: str) -> float:
        """Return the combined AI origin score for one file (0.0–1.0)."""
        if self._repo_score >= 1.0:
            return 1.0
        file_score = self._classifier.classify(source, language)
        return round(max(self._repo_score, file_score), 3)
