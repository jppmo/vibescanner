from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from tree_sitter import Tree

from vibescan.models import Finding


class BaseRule(ABC):
    """Base class for all Vibescan vulnerability detectors.

    Subclass this and implement `visit()`. Drop the file into
    `vibescan/rules/` and the engine picks it up automatically.

    Class attributes:
        id: Rule identifier, e.g. "VCS-001".
        name: Human-readable name shown in findings output.
        severity: Default severity level for findings from this rule.
        languages: File extensions this rule applies to, e.g. ["js", "ts"].
                   Use ["*"] to run on every file regardless of extension.
    """

    id: str
    name: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    languages: list[str]

    @abstractmethod
    def visit(self, tree: Tree | None, source: bytes, filepath: str) -> list[Finding]:
        """Inspect a file and return any findings.

        Args:
            tree: Parsed tree-sitter AST, or None for file types without
                  grammar support (SQL, YAML, JSON, Terraform).
            source: Raw file contents as bytes.
            filepath: Absolute path to the file being scanned.

        Returns:
            List of findings. Return an empty list if nothing is detected.
        """
        ...
