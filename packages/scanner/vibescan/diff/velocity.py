from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vibescan.diff.context import DiffContext

logger = logging.getLogger(__name__)

_LOC_PER_MIN_THRESHOLD = 300.0
_MIN_LOC_FOR_RATE_SIGNAL = 100
_BIG_SINGLE_COMMIT_LOC = 500
_BURST_LOC = 1000
_BURST_SECONDS = 600  # 10 minutes


class PRVelocityDetector:
    """Infer AI authorship from PR velocity.

    Returns (score, label) where score is 0.0 or 1.0 and label is a short
    human-readable string describing why velocity fired (or None).
    """

    def detect(self, context: DiffContext) -> tuple[float, str | None]:
        loc = context.net_loc_added
        elapsed = context.elapsed_seconds
        commits = context.commit_count

        if loc <= 0:
            return 0.0, None

        # Single commit, lots of code — no elapsed time to compute a rate.
        if commits == 1 and loc >= _BIG_SINGLE_COMMIT_LOC:
            label = f"{loc} net LOC in a single commit"
            logger.info("Velocity signal fired", extra={"reason": "single_big_commit", "loc": loc})
            return 1.0, label

        # Burst: lots of code in a short window
        if loc >= _BURST_LOC and 0 < elapsed <= _BURST_SECONDS:
            mins = elapsed / 60
            label = f"{loc} net LOC in {_format_duration(elapsed)} ({loc / mins:.0f} LOC/min)"
            logger.info("Velocity signal fired", extra={"reason": "burst", "loc": loc, "elapsed": elapsed})
            return 1.0, label

        # Sustained high rate
        if loc >= _MIN_LOC_FOR_RATE_SIGNAL and elapsed > 0:
            rate = loc / (elapsed / 60)
            if rate >= _LOC_PER_MIN_THRESHOLD:
                label = f"{loc} net LOC in {_format_duration(elapsed)} ({rate:.0f} LOC/min)"
                logger.info("Velocity signal fired", extra={"reason": "rate", "rate": rate, "loc": loc})
                return 1.0, label

        return 0.0, None


def _format_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    mins, secs = divmod(seconds, 60)
    if mins < 60:
        return f"{mins}m{secs:02d}s" if secs else f"{mins}m"
    hours, mins = divmod(mins, 60)
    return f"{hours}h{mins:02d}m"
