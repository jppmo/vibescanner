from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal


@dataclass
class Finding:
    """A single vulnerability finding produced by a rule."""

    rule_id: str
    rule_name: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    filepath: str
    line: int
    col: int
    snippet: str
    fix: str
    ai_origin_score: float = 0.0

    def dedup_key(self) -> str:
        """Stable key for deduplicating findings across files.

        Keyed on rule + snippet content so the same vulnerable pattern found
        in multiple files is counted once per unique occurrence, not once per file.
        """
        content_hash = hashlib.sha256(self.snippet.encode()).hexdigest()[:16]
        return f"{self.rule_id}:{content_hash}"
