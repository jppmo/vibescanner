from __future__ import annotations

import dataclasses
import json
from typing import TYPE_CHECKING

from rich.console import Console
from rich.padding import Padding
from rich.text import Text

if TYPE_CHECKING:
    from vibescan.models import Finding

_SEVERITY_STYLE: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
}

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


class HumanFormatter:
    """Rich terminal output, grouped by severity."""

    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console(stderr=False)

    def write(
        self,
        findings: list[Finding],
        repo_path: str,
        *,
        repo_ai_score: float = 0.0,
        repo_ai_tool: str | None = None,
    ) -> None:
        c = self._console

        ai_banner = self._ai_banner(repo_ai_score, repo_ai_tool)

        if not findings:
            c.print("[bold green]✓[/] No findings — repo looks clean.")
            if ai_banner:
                c.print(ai_banner)
            return

        total = len(findings)
        c.print(f"\n[bold]Vibescan[/] found [bold]{total}[/] finding{'s' if total != 1 else ''} in [dim]{repo_path}[/]")
        if ai_banner:
            c.print(ai_banner)
        c.print()

        by_severity: dict[str, list[Finding]] = {}
        for f in findings:
            by_severity.setdefault(f.severity, []).append(f)

        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            group = by_severity.get(severity, [])
            if not group:
                continue

            style = _SEVERITY_STYLE[severity]
            c.print(f"[{style}]{'─' * 60}[/]")
            c.print(f"[{style}] {severity} ({len(group)})[/]\n")

            for finding in group:
                self._print_finding(finding, style)

    def _ai_banner(self, score: float, tool: str | None) -> str | None:
        if score >= 1.0 and tool:
            return f"[bold cyan]⚡ AI origin confirmed[/] [dim]— Co-authored-by: {tool.capitalize()} detected in git history[/]"
        if score >= 1.0:
            return "[bold cyan]⚡ AI origin confirmed[/] [dim]— AI generation marker detected in git history[/]"
        if score >= 0.5:
            return f"[cyan]~ AI-generated patterns detected[/] [dim](confidence {score:.0%})[/]"
        return None

    def _print_finding(self, f: Finding, style: str) -> None:
        c = self._console

        rule_label = Text()
        rule_label.append(f" {f.rule_id} ", style=style)
        rule_label.append(f" {f.rule_name}", style="bold")
        c.print(rule_label)

        ai_tag = ""
        if f.ai_origin_score >= 0.7:
            ai_tag = "  [dim italic]ai-origin: likely[/]"
        elif f.ai_origin_score >= 0.3:
            ai_tag = "  [dim italic]ai-origin: possible[/]"
        c.print(f"  [dim]File:[/] {f.filepath}:{f.line}{ai_tag}")

        snippet_text = Text(f"  {f.snippet}", style="dim white on grey15")
        c.print(Padding(snippet_text, (0, 0, 0, 0)))

        for line in f.fix.strip().splitlines():
            c.print(f"  [green]→[/] {line}")

        c.print()


class JSONFormatter:
    """Machine-readable JSON output for CI integration."""

    def write(
        self,
        findings: list[Finding],
        repo_path: str,
        *,
        repo_ai_score: float = 0.0,
        repo_ai_tool: str | None = None,
    ) -> str:
        payload = {
            "repo": repo_path,
            "total": len(findings),
            "repo_ai_score": repo_ai_score,
            "repo_ai_tool": repo_ai_tool,
            "findings": [dataclasses.asdict(f) for f in findings],
        }
        return json.dumps(payload, indent=2)
