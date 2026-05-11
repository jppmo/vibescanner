from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from vibescan.diff.context import DiffContext, DiffError
from vibescan.engine import ScanEngine


def _run(args: list[str], cwd: Path) -> None:
    subprocess.run(args, cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _run(["git", "init", "-q", "-b", "main"], repo)
    _run(["git", "config", "user.email", "test@test.com"], repo)
    _run(["git", "config", "user.name", "Test"], repo)
    _run(["git", "config", "commit.gpgsign", "false"], repo)
    return repo


def _commit(repo: Path, message: str) -> None:
    _run(["git", "add", "-A"], repo)
    _run(["git", "commit", "-q", "-m", message], repo)


class TestDiffContextFromGit:
    def test_not_a_git_repo(self, tmp_path: Path):
        with pytest.raises(DiffError, match="not a git repository"):
            DiffContext.from_git(tmp_path, "HEAD")

    def test_picks_up_changed_files_only(self, git_repo: Path):
        (git_repo / "untouched.py").write_text("x = 1\n")
        _commit(git_repo, "initial")

        (git_repo / "added.py").write_text("y = 2\n")
        _commit(git_repo, "add")

        ctx = DiffContext.from_git(git_repo, "HEAD~1..HEAD")
        assert "added.py" in ctx.changed_files
        assert "untouched.py" not in ctx.changed_files

    def test_skips_lock_files(self, git_repo: Path):
        (git_repo / "real.py").write_text("a = 1\n")
        _commit(git_repo, "initial")

        (git_repo / "real.py").write_text("a = 2\n")
        (git_repo / "package-lock.json").write_text('{"name":"x"}\n')
        _commit(git_repo, "change")

        ctx = DiffContext.from_git(git_repo, "HEAD~1..HEAD")
        assert "real.py" in ctx.changed_files
        assert "package-lock.json" not in ctx.changed_files

    def test_changed_lines_populated(self, git_repo: Path):
        (git_repo / "f.py").write_text("a = 1\nb = 2\nc = 3\n")
        _commit(git_repo, "initial")

        (git_repo / "f.py").write_text("a = 1\nb = 99\nc = 3\nd = 4\n")
        _commit(git_repo, "edit")

        ctx = DiffContext.from_git(git_repo, "HEAD~1..HEAD")
        # Line 2 was modified; line 4 was added
        assert 2 in ctx.changed_lines["f.py"]
        assert 4 in ctx.changed_lines["f.py"]
        # Line 1 and 3 unchanged
        assert 1 not in ctx.changed_lines["f.py"]

    def test_added_packages_extracted(self, git_repo: Path):
        (git_repo / "package.json").write_text('{"dependencies":{"react":"18.0.0"}}\n')
        _commit(git_repo, "initial")

        (git_repo / "package.json").write_text(
            '{"dependencies":{"react":"18.0.0","fakelib-totally-hallucinated":"1.0.0"}}\n',
        )
        _commit(git_repo, "add fake dep")

        ctx = DiffContext.from_git(git_repo, "HEAD~1..HEAD")
        added = ctx.added_packages.get("package.json", set())
        assert "fakelib-totally-hallucinated" in added
        # react was already there in the previous version, but appears again on the new line
        # because the whole line was rewritten — accept either presence/absence
        # The point is the new package is detected.

    def test_velocity_metadata_populated(self, git_repo: Path):
        (git_repo / "a.py").write_text("\n".join(f"x_{i} = {i}" for i in range(50)) + "\n")
        _commit(git_repo, "initial")

        (git_repo / "a.py").write_text(
            "\n".join(f"x_{i} = {i}" for i in range(50)) + "\n"
            + "\n".join(f"y_{i} = {i}" for i in range(700)) + "\n",
        )
        _commit(git_repo, "big add")

        ctx = DiffContext.from_git(git_repo, "HEAD~1..HEAD")
        assert ctx.commit_count == 1
        assert ctx.net_loc_added >= 700


class TestScanEngineDiffMode:
    def test_findings_filtered_to_changed_lines(self, git_repo: Path):
        # Initial commit with two committed-secret findings
        old_token = "fake_token_value_" + "a" * 40
        new_password = "rotated_password_" + "b" * 40
        (git_repo / ".env").write_text(
            f"API_TOKEN={old_token}\n"
            f"DATABASE_PASSWORD=oldpassword_{'x' * 40}\n",
        )
        _commit(git_repo, "initial")

        # Second commit only modifies line 2; line 1 should NOT be flagged in diff mode
        (git_repo / ".env").write_text(
            f"API_TOKEN={old_token}\n"
            f"DATABASE_PASSWORD={new_password}\n",
        )
        _commit(git_repo, "rotate db creds")

        ctx = DiffContext.from_git(git_repo, "HEAD~1..HEAD")
        engine = ScanEngine(git_repo, diff_context=ctx)
        findings = engine.scan()

        # Stripe key is on line 1 (unchanged in this diff); should not be reported
        for f in findings:
            assert f.line != 1, f"Line 1 (Stripe key, unchanged) should be filtered out: {f}"

    def test_velocity_signal_propagates(self, git_repo: Path):
        (git_repo / "tiny.py").write_text("x = 1\n")
        _commit(git_repo, "initial")

        (git_repo / "huge.py").write_text("\n".join(f"v_{i} = {i}" for i in range(800)) + "\n")
        _commit(git_repo, "huge add")

        ctx = DiffContext.from_git(git_repo, "HEAD~1..HEAD")
        engine = ScanEngine(git_repo, diff_context=ctx)
        engine.scan()

        assert engine.repo_ai_score == 1.0
        assert engine.velocity_label is not None
        assert engine.repo_ai_tool == "velocity"
