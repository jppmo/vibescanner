#!/usr/bin/env python3
"""Scan a corpus of public GitHub repos with vibescan and aggregate results.

Input: a JSONL file. One repo per line:
    {"url": "https://github.com/foo/bar", "source": "commit_search", "tool_label": "claude"}

Output (under --out):
    scans/<owner>__<repo>/findings.json     raw vibescan JSON output
    scans/<owner>__<repo>/meta.json         repo metadata (stars, language, etc.)
    scans/<owner>__<repo>/scan.log          scan stderr / errors
    summary.csv                             one row per repo (rebuilt from scratch on each run)
    findings.jsonl                          one row per finding (rebuilt from scratch on each run)

Usage:
    python scripts/scan_corpus.py --input scripts/seed.example.jsonl
    python scripts/scan_corpus.py --input seed.jsonl --concurrency 8 --max-mb 50
    python scripts/scan_corpus.py --input seed.jsonl --aggregate-only

Already-scanned repos (with a findings.json on disk) are skipped unless --force is set.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("scan_corpus")


@dataclass
class RepoSpec:
    url: str
    source: str = "unknown"
    tool_label: str = "unknown"

    @property
    def slug(self) -> str:
        owner, repo = _parse_repo(self.url)
        return f"{owner}__{repo}"

    @property
    def owner_repo(self) -> tuple[str, str]:
        return _parse_repo(self.url)


def _parse_repo(url: str) -> tuple[str, str]:
    """Extract (owner, repo) from a GitHub URL."""
    cleaned = url.rstrip("/").removesuffix(".git")
    parts = cleaned.split("/")
    if len(parts) < 2:
        raise ValueError(f"Cannot parse repo from {url}")
    return parts[-2], parts[-1]


def _read_input(path: Path) -> list[RepoSpec]:
    specs: list[RepoSpec] = []
    with path.open() as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                # Allow plain-URL lines as a convenience
                obj = {"url": line}
            specs.append(RepoSpec(
                url=obj["url"],
                source=obj.get("source", "unknown"),
                tool_label=obj.get("tool_label", "unknown"),
            ))
    return specs


def _gh_metadata(owner: str, repo: str) -> dict:
    """Fetch repo metadata via gh CLI. Returns {} on failure."""
    fields = "stargazerCount,primaryLanguage,pushedAt,isFork,isArchived,diskUsage,defaultBranchRef"
    try:
        result = subprocess.run(
            ["gh", "repo", "view", f"{owner}/{repo}", "--json", fields],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {}
    if result.returncode != 0:
        logger.warning("gh metadata fetch failed for %s/%s: %s", owner, repo, result.stderr.strip())
        return {}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}


def _clone(url: str, dest: Path) -> bool:
    """Shallow-clone url into dest. Returns True on success."""
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--filter=blob:none", "--quiet", url, str(dest)],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("clone timed out: %s", url)
        return False
    if result.returncode != 0:
        logger.warning("clone failed for %s: %s", url, result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "")
        return False
    return True


def _run_scan(repo_path: Path, output_path: Path, log_path: Path) -> tuple[int, float]:
    """Run vibescan and write JSON findings + log. Returns (exit_code, duration_seconds)."""
    started = time.monotonic()
    with log_path.open("w") as log_fh:
        try:
            result = subprocess.run(
                [
                    "vibescan", "scan", str(repo_path),
                    "--format", "json",
                    "--output", str(output_path),
                    "--fail-on", "NONE",  # we want exit 0 even when findings exist
                ],
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                timeout=600,
                check=False,
            )
            exit_code = result.returncode
        except FileNotFoundError:
            log_fh.write("vibescan binary not found on PATH\n")
            exit_code = 127
        except subprocess.TimeoutExpired:
            log_fh.write("scan timed out after 600s\n")
            exit_code = 124
    duration = time.monotonic() - started
    return exit_code, duration


def _scan_one(spec: RepoSpec, out_dir: Path, max_mb: int, *, force: bool) -> dict:
    """Process one repo. Returns a dict suitable for writing to summary.csv."""
    owner, repo = spec.owner_repo
    scan_dir = out_dir / "scans" / spec.slug
    findings_path = scan_dir / "findings.json"
    meta_path = scan_dir / "meta.json"
    log_path = scan_dir / "scan.log"

    if findings_path.exists() and not force:
        logger.info("skipping (already scanned): %s", spec.slug)
        return _row_from_disk(spec, scan_dir)

    scan_dir.mkdir(parents=True, exist_ok=True)

    meta = _gh_metadata(owner, repo)
    meta_path.write_text(json.dumps(meta, indent=2))

    if meta.get("isFork"):
        log_path.write_text("skipped: fork\n")
        return _row(spec, meta, error="skipped_fork")
    if meta.get("isArchived"):
        log_path.write_text("skipped: archived\n")
        return _row(spec, meta, error="skipped_archived")
    disk_kb = meta.get("diskUsage") or 0
    if disk_kb and disk_kb > max_mb * 1024:
        log_path.write_text(f"skipped: too large ({disk_kb} KB > {max_mb} MB)\n")
        return _row(spec, meta, error="skipped_too_large")

    with tempfile.TemporaryDirectory(prefix="vibescan-corpus-") as tmp:
        clone_dest = Path(tmp) / "repo"
        if not _clone(spec.url, clone_dest):
            log_path.write_text("clone failed\n")
            return _row(spec, meta, error="clone_failed")

        exit_code, duration = _run_scan(clone_dest, findings_path, log_path)

    if exit_code != 0 and not findings_path.exists():
        return _row(spec, meta, error=f"scan_exit_{exit_code}", scan_duration=duration)

    return _row_from_disk(spec, scan_dir, scan_duration=duration)


def _row_from_disk(spec: RepoSpec, scan_dir: Path, *, scan_duration: float | None = None) -> dict:
    findings_path = scan_dir / "findings.json"
    meta_path = scan_dir / "meta.json"
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    if not findings_path.exists():
        return _row(spec, meta, error="no_findings_file", scan_duration=scan_duration)

    try:
        payload = json.loads(findings_path.read_text())
    except json.JSONDecodeError:
        return _row(spec, meta, error="invalid_findings_json", scan_duration=scan_duration)

    findings = payload.get("findings", [])
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "").upper()
        if sev in sev_counts:
            sev_counts[sev] += 1

    return _row(
        spec,
        meta,
        total=len(findings),
        sev_counts=sev_counts,
        repo_ai_score=payload.get("repo_ai_score", 0.0),
        repo_ai_tool=payload.get("repo_ai_tool"),
        scan_duration=scan_duration,
    )


def _row(
    spec: RepoSpec,
    meta: dict,
    *,
    total: int = 0,
    sev_counts: dict | None = None,
    repo_ai_score: float = 0.0,
    repo_ai_tool: str | None = None,
    scan_duration: float | None = None,
    error: str = "",
) -> dict:
    sev_counts = sev_counts or {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    primary_lang = (meta.get("primaryLanguage") or {}).get("name") if meta else None
    return {
        "url": spec.url,
        "owner": spec.owner_repo[0],
        "repo": spec.owner_repo[1],
        "source": spec.source,
        "tool_label": spec.tool_label,
        "stars": meta.get("stargazerCount") if meta else None,
        "language": primary_lang,
        "pushed_at": meta.get("pushedAt") if meta else None,
        "disk_kb": meta.get("diskUsage") if meta else None,
        "scan_duration_s": round(scan_duration, 2) if scan_duration else None,
        "total_findings": total,
        "critical": sev_counts["CRITICAL"],
        "high": sev_counts["HIGH"],
        "medium": sev_counts["MEDIUM"],
        "low": sev_counts["LOW"],
        "repo_ai_score": repo_ai_score,
        "repo_ai_tool": repo_ai_tool or "",
        "error": error,
    }


def _aggregate(out_dir: Path, specs: list[RepoSpec]) -> tuple[int, int]:
    """Rebuild summary.csv and findings.jsonl from on-disk scans/. Returns (repos, findings)."""
    summary_path = out_dir / "summary.csv"
    findings_path = out_dir / "findings.jsonl"

    rows: list[dict] = []
    finding_count = 0
    findings_fh = findings_path.open("w")

    try:
        for spec in specs:
            scan_dir = out_dir / "scans" / spec.slug
            if not scan_dir.exists():
                continue
            row = _row_from_disk(spec, scan_dir)
            rows.append(row)

            f_path = scan_dir / "findings.json"
            if not f_path.exists():
                continue
            try:
                payload = json.loads(f_path.read_text())
            except json.JSONDecodeError:
                continue
            for f in payload.get("findings", []):
                out_record = {
                    "repo_url": spec.url,
                    "owner": spec.owner_repo[0],
                    "repo": spec.owner_repo[1],
                    "source": spec.source,
                    "tool_label": spec.tool_label,
                    **f,
                }
                findings_fh.write(json.dumps(out_record) + "\n")
                finding_count += 1
    finally:
        findings_fh.close()

    if rows:
        with summary_path.open("w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    return len(rows), finding_count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, required=True, help="JSONL list of repos to scan")
    parser.add_argument("--out", type=Path, default=Path("corpus"), help="Output directory (default: ./corpus)")
    parser.add_argument("--concurrency", type=int, default=4, help="Parallel scans (default: 4)")
    parser.add_argument("--limit", type=int, default=None, help="Process at most N repos")
    parser.add_argument("--max-mb", type=int, default=200, help="Skip repos larger than N MB (default: 200)")
    parser.add_argument("--force", action="store_true", help="Re-scan repos even if findings.json exists")
    parser.add_argument("--aggregate-only", action="store_true", help="Skip scanning, only rebuild summary.csv + findings.jsonl")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    if not args.input.exists():
        logger.error("input file not found: %s", args.input)
        return 2

    if shutil.which("vibescan") is None:
        logger.error("vibescan binary not on PATH. Install with: pip install vibescan-scanner")
        return 2

    specs = _read_input(args.input)
    if args.limit:
        specs = specs[: args.limit]
    logger.info("loaded %d repos from %s", len(specs), args.input)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "scans").mkdir(parents=True, exist_ok=True)

    if args.aggregate_only:
        repos, findings = _aggregate(args.out, specs)
        logger.info("aggregated %d repos / %d findings", repos, findings)
        return 0

    started = time.monotonic()
    completed = 0
    failed = 0

    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(_scan_one, spec, args.out, args.max_mb, force=args.force): spec for spec in specs}
        for fut in as_completed(futures):
            spec = futures[fut]
            try:
                row = fut.result()
                if row.get("error"):
                    failed += 1
                    logger.warning("[%d/%d] %s -> %s", completed + failed, len(specs), spec.slug, row["error"])
                else:
                    completed += 1
                    logger.info(
                        "[%d/%d] %s -> %d findings (C:%d H:%d)",
                        completed + failed, len(specs), spec.slug,
                        row["total_findings"], row["critical"], row["high"],
                    )
            except Exception:
                failed += 1
                logger.exception("scan crashed for %s", spec.slug)

    elapsed = time.monotonic() - started
    logger.info("scan loop done in %.1fs (%d ok, %d failed)", elapsed, completed, failed)

    repos, findings = _aggregate(args.out, specs)
    logger.info("wrote summary.csv (%d repos), findings.jsonl (%d findings)", repos, findings)

    return 0


if __name__ == "__main__":
    sys.exit(main())
