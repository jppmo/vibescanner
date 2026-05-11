from __future__ import annotations

from pathlib import Path

from vibescan.diff.context import DiffContext
from vibescan.diff.velocity import PRVelocityDetector


def _ctx(*, loc: int, elapsed: int, commits: int) -> DiffContext:
    return DiffContext(
        base="origin/main",
        head="HEAD",
        repo_path=Path("/tmp/fake"),
        net_loc_added=loc,
        elapsed_seconds=elapsed,
        commit_count=commits,
    )


class TestPRVelocityDetector:
    def test_zero_loc_returns_zero(self):
        det = PRVelocityDetector()
        score, label = det.detect(_ctx(loc=0, elapsed=120, commits=2))
        assert score == 0.0
        assert label is None

    def test_single_big_commit_fires(self):
        det = PRVelocityDetector()
        score, label = det.detect(_ctx(loc=800, elapsed=0, commits=1))
        assert score == 1.0
        assert "single commit" in label

    def test_single_small_commit_does_not_fire(self):
        det = PRVelocityDetector()
        score, label = det.detect(_ctx(loc=200, elapsed=0, commits=1))
        assert score == 0.0
        assert label is None

    def test_burst_fires(self):
        det = PRVelocityDetector()
        score, label = det.detect(_ctx(loc=1500, elapsed=300, commits=3))
        assert score == 1.0
        assert "1500" in label
        assert "5m" in label

    def test_sustained_high_rate_fires(self):
        det = PRVelocityDetector()
        # 600 LOC in 60s = 600 LOC/min, well above 300 threshold
        score, label = det.detect(_ctx(loc=600, elapsed=60, commits=4))
        assert score == 1.0
        assert "LOC/min" in label

    def test_human_pace_does_not_fire(self):
        det = PRVelocityDetector()
        # 200 LOC over 2 hours = ~1.7 LOC/min
        score, label = det.detect(_ctx(loc=200, elapsed=7200, commits=5))
        assert score == 0.0
        assert label is None

    def test_below_min_loc_does_not_fire_even_at_high_rate(self):
        det = PRVelocityDetector()
        # 50 LOC in 5s — high rate but tiny diff, should not flag
        score, label = det.detect(_ctx(loc=50, elapsed=5, commits=1))
        assert score == 0.0
        assert label is None
