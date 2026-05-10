from __future__ import annotations

import re

# Phrases that appear disproportionately in AI-generated comments
_AI_PHRASE_RE = re.compile(
    r"this (function|method|class|module|code|implementation|snippet|approach)\b"
    r"|# TODO: (add|implement|handle|check|verify)\b"
    r"|# (Note|NOTE|IMPORTANT|WARNING): ",
    re.IGNORECASE,
)

# Lines that start with a comment marker (byte-level)
_COMMENT_LINE_RE = re.compile(rb"^\s*(#|//|/\*|\*)", re.MULTILINE)


class PatternClassifier:
    """Heuristic classifier for AI-generated source code.

    Scores a single file 0.0–1.0. Higher means more likely AI-generated.
    Signals used: comment density, AI-characteristic phrase density,
    and (for Python) docstring density.
    """

    def classify(self, source: bytes, language: str) -> float:
        if not source:
            return 0.0

        lines = source.splitlines()
        total = len(lines)
        if total == 0:
            return 0.0

        score = 0.0

        # Signal 1: comment-line density
        comment_count = len(_COMMENT_LINE_RE.findall(source))
        comment_ratio = comment_count / total
        if comment_ratio > 0.40:
            score += 0.40
        elif comment_ratio > 0.25:
            score += 0.20

        # Signal 2: AI-characteristic phrase density
        try:
            decoded = source.decode("utf-8", errors="replace")
        except Exception:
            return 0.0

        phrase_hits = len(_AI_PHRASE_RE.findall(decoded))
        phrase_density = phrase_hits / total
        if phrase_density > 0.05:
            score += 0.30
        elif phrase_density > 0.02:
            score += 0.15

        # Signal 3: Python docstring density
        if language == "python":
            triple_quotes = decoded.count('"""')
            docstrings = triple_quotes // 2
            if total > 0 and docstrings / total > 0.05:
                score += 0.20

        return min(score, 1.0)
