from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from vibescan.origin.detector import GitMetadataDetector

_REPO = Path("/fake/repo")


def _run(stdout: str, returncode: int = 0) -> CompletedProcess:
    return CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


# ---------------------------------------------------------------------------
# Positive detections
# ---------------------------------------------------------------------------


def test_copilot_coauthor_returns_one():
    log = "feat: add login\n\nCo-authored-by: GitHub Copilot <copilot@github.com>\n"
    with patch("vibescan.origin.detector.subprocess.run", return_value=_run(log)):
        score, tool = GitMetadataDetector().detect(_REPO)
    assert score == 1.0
    assert tool == "copilot"


def test_cursor_coauthor_returns_one():
    log = "fix: bug\n\nCo-authored-by: Cursor <cursor@anysphere.io>\n"
    with patch("vibescan.origin.detector.subprocess.run", return_value=_run(log)):
        score, tool = GitMetadataDetector().detect(_REPO)
    assert score == 1.0
    assert tool == "cursor"


def test_claude_coauthor_returns_one():
    log = "chore: refactor\n\nCo-authored-by: Claude <claude@anthropic.com>\n"
    with patch("vibescan.origin.detector.subprocess.run", return_value=_run(log)):
        score, tool = GitMetadataDetector().detect(_REPO)
    assert score == 1.0
    assert tool == "claude"


def test_chatgpt_coauthor_returns_one():
    log = "Co-authored-by: ChatGPT <chatgpt@openai.com>\n"
    with patch("vibescan.origin.detector.subprocess.run", return_value=_run(log)):
        score, tool = GitMetadataDetector().detect(_REPO)
    assert score == 1.0
    assert tool == "chatgpt"


def test_lovable_platform_marker_returns_one():
    log = "Initial commit\n\nGenerated with Lovable v2\n"
    with patch("vibescan.origin.detector.subprocess.run", return_value=_run(log)):
        score, tool = GitMetadataDetector().detect(_REPO)
    assert score == 1.0
    assert tool == "lovable"


def test_bolt_platform_marker_returns_one():
    log = "Generated with Bolt.new\n"
    with patch("vibescan.origin.detector.subprocess.run", return_value=_run(log)):
        score, tool = GitMetadataDetector().detect(_REPO)
    assert score == 1.0
    assert tool == "bolt"


def test_case_insensitive_match():
    log = "co-authored-by: CURSOR <x@y.com>\n"
    with patch("vibescan.origin.detector.subprocess.run", return_value=_run(log)):
        score, tool = GitMetadataDetector().detect(_REPO)
    assert score == 1.0
    assert tool == "cursor"


# ---------------------------------------------------------------------------
# Negative / error cases
# ---------------------------------------------------------------------------


def test_human_only_commits_returns_zero():
    log = "feat: add login\n\nCo-authored-by: Alice <alice@example.com>\n"
    with patch("vibescan.origin.detector.subprocess.run", return_value=_run(log)):
        score, tool = GitMetadataDetector().detect(_REPO)
    assert score == 0.0
    assert tool is None


def test_non_zero_returncode_returns_zero():
    with patch("vibescan.origin.detector.subprocess.run", return_value=_run("", returncode=128)):
        score, tool = GitMetadataDetector().detect(_REPO)
    assert score == 0.0
    assert tool is None


def test_git_not_found_returns_zero():
    with patch("vibescan.origin.detector.subprocess.run", side_effect=FileNotFoundError):
        score, tool = GitMetadataDetector().detect(_REPO)
    assert score == 0.0
    assert tool is None


def test_timeout_returns_zero():
    import subprocess
    with patch("vibescan.origin.detector.subprocess.run", side_effect=subprocess.TimeoutExpired("git", 10)):
        score, tool = GitMetadataDetector().detect(_REPO)
    assert score == 0.0
    assert tool is None


def test_empty_log_returns_zero():
    with patch("vibescan.origin.detector.subprocess.run", return_value=_run("")):
        score, tool = GitMetadataDetector().detect(_REPO)
    assert score == 0.0
    assert tool is None
