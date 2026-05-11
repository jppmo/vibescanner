from __future__ import annotations

import logging
import sys
from pathlib import Path

import click
from rich.console import Console

from vibescan.cli.formatters import HumanFormatter, JSONFormatter

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

_FAIL_ON_CHOICES = click.Choice(
    ["CRITICAL", "HIGH", "MEDIUM", "ALL", "NONE"],
    case_sensitive=False,
)


def _compute_exit_code(findings: list, fail_on: str) -> int:
    if not findings:
        return 0

    if fail_on == "NONE":
        return 0

    threshold = 99 if fail_on == "ALL" else _SEVERITY_RANK[fail_on]

    for f in findings:
        if _SEVERITY_RANK[f.severity] <= threshold:
            return 2

    return 1


@click.group()
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging.")
def cli(*, debug: bool) -> None:
    """Vibescan — security scanner for AI-generated code."""
    level = logging.DEBUG if debug else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


@cli.command("scan")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["human", "json"], case_sensitive=False),
    default="human",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--fail-on",
    type=_FAIL_ON_CHOICES,
    default="CRITICAL",
    show_default=True,
    help="Minimum severity that causes a non-zero exit code.",
)
@click.option(
    "--ignore-rule",
    "ignore_rules",
    multiple=True,
    metavar="RULE_ID",
    help="Skip a rule by ID (repeatable: --ignore-rule VCS-004 --ignore-rule VCS-005).",
)
@click.option(
    "--output",
    "output_path",
    default=None,
    type=click.Path(dir_okay=False, writable=True),
    help="Write findings to a file instead of stdout.",
)
@click.option(
    "--diff",
    "diff_range",
    default=None,
    metavar="REF",
    help=(
        "Scan only changes vs a git ref (e.g. 'origin/main' or 'origin/main..HEAD'). "
        "Findings are restricted to changed lines. Adds PR-velocity AI signal."
    ),
)
def scan(
    path: str,
    output_format: str,
    fail_on: str,
    ignore_rules: tuple[str, ...],
    output_path: str | None,
    diff_range: str | None,
) -> None:
    """Scan a repository for security vulnerabilities.

    PATH defaults to the current directory.
    """
    from vibescan.diff.context import DiffContext, DiffError
    from vibescan.engine import ScanEngine

    console = Console()

    diff_context = None
    if diff_range:
        try:
            diff_context = DiffContext.from_git(Path(path), diff_range)
        except DiffError as exc:
            Console(stderr=True).print(f"[bold red]Error:[/] {exc}")
            sys.exit(3)
        if not diff_context.changed_files:
            console.print("[dim]No changed files in diff range — nothing to scan.[/]")
            sys.exit(0)

    try:
        engine = ScanEngine(path, diff_context=diff_context)
        findings = engine.scan()
    except Exception as exc:
        Console(stderr=True).print(f"[bold red]Error:[/] {exc}")
        sys.exit(3)

    ignore_upper = {r.upper() for r in ignore_rules}
    if ignore_upper:
        findings = [f for f in findings if f.rule_id not in ignore_upper]

    repo_ai_score = engine.repo_ai_score
    repo_ai_tool = engine.repo_ai_tool
    velocity_label = engine.velocity_label

    fmt_kwargs = {
        "repo_ai_score": repo_ai_score,
        "repo_ai_tool": repo_ai_tool,
        "velocity_label": velocity_label,
        "diff_context": diff_context,
    }

    if output_format.lower() == "json":
        formatter = JSONFormatter()
        output = formatter.write(findings, path, **fmt_kwargs)
        if output_path:
            Path(output_path).write_text(output)
        else:
            click.echo(output)
    else:
        human = HumanFormatter(console=console)
        if output_path:
            with Path(output_path).open("w") as fh:
                HumanFormatter(console=Console(file=fh, highlight=False)).write(
                    findings, path, **fmt_kwargs,
                )
        else:
            human.write(findings, path, **fmt_kwargs)

    sys.exit(_compute_exit_code(findings, fail_on.upper()))
