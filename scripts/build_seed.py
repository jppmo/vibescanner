#!/usr/bin/env python3
"""Assemble a seed corpus of AI-generated repos for scan_corpus.py to scan.

Runs three classes of GitHub search via `gh`:

1. Hard-labeled (commit search) — repos with `Co-authored-by: <tool>` trailers.
   Highest-confidence label.
2. Topic search — GitHub repos tagged with AI-tool topics (lovable, bolt-new, etc.).
   Medium confidence.
3. Heuristic — repo searches that combine common vibe-coded patterns
   (e.g. supabase + vite, firebase + react, claude in commits).
   Unlabeled but interesting.

Dedupes across all queries and writes one JSON object per line to the output
file. Run this BEFORE scripts/scan_corpus.py.

Usage:
    python scripts/build_seed.py --out corpus/seed.jsonl
    python scripts/build_seed.py --hard-limit 80 --topic-limit 40 --heuristic-limit 30
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

logger = logging.getLogger("build_seed")


@dataclass
class Repo:
    url: str
    source: str
    tool_label: str


HARD_LABEL_QUERIES: list[tuple[str, str]] = [
    ("co-authored-by:claude",  "claude"),
    ("co-authored-by:cursor",  "cursor"),
    ("co-authored-by:copilot", "copilot"),
    ("co-authored-by:devin",   "devin"),
    ("generated with lovable", "lovable"),
    ("generated with bolt",    "bolt"),
    ("generated with v0",      "v0"),
]

TOPIC_QUERIES: list[tuple[str, str]] = [
    ("lovable",          "lovable"),
    ("lovable-app",      "lovable"),
    ("bolt-new",         "bolt"),
    ("v0-app",           "v0"),
    ("v0-dev",           "v0"),
    ("built-with-cursor","cursor"),
    ("claude-code",      "claude"),
    ("replit-agent",     "replit"),
]

HEURISTIC_QUERIES: list[tuple[str, str]] = [
    ('"supabase" "vite" in:readme stars:1..50',          "unknown"),
    ('"firebase" "react" in:readme stars:1..30',          "unknown"),
    ('"@supabase/supabase-js" "next" stars:1..30',        "unknown"),
    ('"supabase" "react" stars:1..20 created:>2024-06-01', "unknown"),
]


def _run_gh(args: list[str]) -> str:
    result = subprocess.run(
        ["gh", *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        logger.warning("gh %s failed: %s", " ".join(args), result.stderr.strip())
        return ""
    return result.stdout


def _commit_search(query: str, limit: int) -> list[str]:
    out = _run_gh([
        "search", "commits", query,
        "--limit", str(limit),
        "--json", "repository",
    ])
    if not out:
        return []
    try:
        rows = json.loads(out)
    except json.JSONDecodeError:
        return []
    urls: list[str] = []
    seen: set[str] = set()
    for row in rows:
        repo = row.get("repository") or {}
        url = repo.get("url")
        if not url or url in seen:
            continue
        if repo.get("isFork") or repo.get("isPrivate"):
            continue
        seen.add(url)
        urls.append(url)
    return urls


def _topic_search(topic: str, limit: int) -> list[str]:
    out = _run_gh([
        "search", "repos",
        "--topic", topic,
        "--limit", str(limit),
        "--json", "url,isFork,isArchived",
    ])
    if not out:
        return []
    try:
        rows = json.loads(out)
    except json.JSONDecodeError:
        return []
    return [
        r["url"] for r in rows
        if r.get("url") and not r.get("isFork") and not r.get("isArchived")
    ]


def _repo_query(query: str, limit: int) -> list[str]:
    out = _run_gh([
        "search", "repos", query,
        "--limit", str(limit),
        "--json", "url,isFork,isArchived",
    ])
    if not out:
        return []
    try:
        rows = json.loads(out)
    except json.JSONDecodeError:
        return []
    return [
        r["url"] for r in rows
        if r.get("url") and not r.get("isFork") and not r.get("isArchived")
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=Path("corpus/seed.jsonl"))
    parser.add_argument("--hard-limit", type=int, default=20, help="per-query commit-search limit")
    parser.add_argument("--topic-limit", type=int, default=20, help="per-topic repo-search limit")
    parser.add_argument("--heuristic-limit", type=int, default=20, help="per-query heuristic limit")
    parser.add_argument("--commit-search-delay", type=float, default=8.0,
                        help="seconds to wait between commit-search queries (rate-limit dodge)")
    parser.add_argument("--dry-run", action="store_true", help="print summary, do not write file")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    seen: dict[str, Repo] = {}
    counts = {"hard": 0, "topic": 0, "heuristic": 0}

    logger.info("== hard-labeled commit search ==")
    for i, (query, tool) in enumerate(HARD_LABEL_QUERIES):
        if i > 0:
            # GitHub commit search has a tight secondary rate limit; pace ourselves
            time.sleep(args.commit_search_delay)
        urls = _commit_search(query, args.hard_limit)
        new = 0
        for url in urls:
            if url not in seen:
                seen[url] = Repo(url=url, source=f"commit:{query}", tool_label=tool)
                counts["hard"] += 1
                new += 1
        logger.info("  %-30s %3d urls (%d new)", query, len(urls), new)

    logger.info("== topic search ==")
    for topic, tool in TOPIC_QUERIES:
        urls = _topic_search(topic, args.topic_limit)
        new = 0
        for url in urls:
            if url not in seen:
                seen[url] = Repo(url=url, source=f"topic:{topic}", tool_label=tool)
                counts["topic"] += 1
                new += 1
        logger.info("  topic:%-20s %3d urls (%d new)", topic, len(urls), new)

    logger.info("== heuristic search ==")
    for query, tool in HEURISTIC_QUERIES:
        urls = _repo_query(query, args.heuristic_limit)
        new = 0
        for url in urls:
            if url not in seen:
                seen[url] = Repo(url=url, source=f"heuristic:{query[:30]}", tool_label=tool)
                counts["heuristic"] += 1
                new += 1
        logger.info("  heuristic:%-40s %3d urls (%d new)", query[:40], len(urls), new)

    logger.info("== summary ==")
    logger.info("  hard:      %d", counts["hard"])
    logger.info("  topic:     %d", counts["topic"])
    logger.info("  heuristic: %d", counts["heuristic"])
    logger.info("  total:     %d unique repos", len(seen))

    if args.dry_run:
        return 0

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as fh:
        for repo in seen.values():
            fh.write(json.dumps(asdict(repo)) + "\n")
    logger.info("wrote %s (%d repos)", args.out, len(seen))
    return 0


if __name__ == "__main__":
    sys.exit(main())
