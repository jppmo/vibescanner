from __future__ import annotations

from vibescan.classifier.pattern import PatternClassifier


def _clf() -> PatternClassifier:
    return PatternClassifier()


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_empty_bytes_returns_zero():
    assert _clf().classify(b"", "python") == 0.0


def test_blank_lines_only_returns_zero():
    assert _clf().classify(b"\n\n\n", "python") == 0.0


# ---------------------------------------------------------------------------
# Comment density signal
# ---------------------------------------------------------------------------


def test_heavy_comment_file_scores_high():
    # >40% comment lines
    lines = [b"# This is a comment"] * 50 + [b"x = 1"] * 40
    source = b"\n".join(lines)
    score = _clf().classify(source, "python")
    assert score >= 0.40


def test_light_comment_file_scores_low():
    lines = [b"# comment"] * 5 + [b"x = 1"] * 95
    source = b"\n".join(lines)
    score = _clf().classify(source, "python")
    assert score < 0.40


def test_no_comments_returns_zero_from_comment_signal():
    source = b"x = 1\ny = 2\nz = x + y\n"
    score = _clf().classify(source, "python")
    assert score == 0.0


def test_js_slash_comments_counted():
    lines = [b"// comment"] * 50 + [b"const x = 1;"] * 40
    source = b"\n".join(lines)
    assert _clf().classify(source, "javascript") >= 0.40


# ---------------------------------------------------------------------------
# AI phrase signal
# ---------------------------------------------------------------------------


def test_ai_phrases_increase_score():
    source = (
        b"# This function handles user authentication\n"
        b"# This method validates the input\n"
        b"# TODO: implement error handling\n"
        b"x = 1\n" * 20
    )
    score = _clf().classify(source, "python")
    assert score > 0.0


def test_clean_code_no_ai_phrases_scores_zero():
    source = b"def add(a, b):\n    return a + b\n"
    assert _clf().classify(source, "python") == 0.0


# ---------------------------------------------------------------------------
# Python docstring signal
# ---------------------------------------------------------------------------


def test_python_high_docstring_density_increases_score():
    # Many triple-quoted docstrings relative to file length
    block = b'def f():\n    """Do something."""\n    pass\n'
    source = block * 10  # 10 functions, each ~3 lines = 30 lines, 10 docstrings
    score = _clf().classify(source, "python")
    # docstring density = 10/30 ≈ 0.33 > 0.05 → +0.20
    assert score >= 0.20


def test_docstring_signal_only_for_python():
    # Same source but classified as JavaScript shouldn't get the docstring bonus
    block = b'def f():\n    """Do something."""\n    pass\n'
    source = block * 10
    py_score = _clf().classify(source, "python")
    js_score = _clf().classify(source, "javascript")
    assert py_score >= js_score


# ---------------------------------------------------------------------------
# Score is capped at 1.0
# ---------------------------------------------------------------------------


def test_score_never_exceeds_one():
    # Artificially trigger all three signals at once
    comments = [b"# This function does magic"] * 60
    code = [b"x = 1"] * 40
    source = b"\n".join(comments + code)
    assert _clf().classify(source, "python") <= 1.0


# ---------------------------------------------------------------------------
# AIOriginDetector integration
# ---------------------------------------------------------------------------


def test_origin_detector_warmup_and_score():
    from pathlib import Path
    from subprocess import CompletedProcess
    from unittest.mock import patch

    from vibescan.origin.detector import AIOriginDetector

    clean_log = CompletedProcess(args=[], returncode=0, stdout="feat: normal commit\n", stderr="")

    with patch("vibescan.origin.detector.subprocess.run", return_value=clean_log):
        det = AIOriginDetector()
        det.warmup(Path("/fake/repo"))

    score = det.score_file(b"x = 1\n", "python")
    assert 0.0 <= score <= 1.0


def test_origin_detector_git_score_wins():
    from pathlib import Path
    from subprocess import CompletedProcess
    from unittest.mock import patch

    from vibescan.origin.detector import AIOriginDetector

    ai_log = CompletedProcess(
        args=[],
        returncode=0,
        stdout="Co-authored-by: Cursor <x@anysphere.io>\n",
        stderr="",
    )

    with patch("vibescan.origin.detector.subprocess.run", return_value=ai_log):
        det = AIOriginDetector()
        det.warmup(Path("/fake/repo"))

    # Even a totally clean file gets 1.0 because git said so
    assert det.score_file(b"x = 1\n", "python") == 1.0


def test_origin_detector_no_warmup_uses_file_score():
    from vibescan.origin.detector import AIOriginDetector

    det = AIOriginDetector()
    # No warmup → repo_score stays 0.0 → falls back to pattern classifier
    score = det.score_file(b"x = 1\n", "python")
    assert score == 0.0  # clean code → zero from classifier too
