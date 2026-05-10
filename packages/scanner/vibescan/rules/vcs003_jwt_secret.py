from __future__ import annotations

import math
from collections import Counter

from vibescan.models import Finding
from vibescan.rules.base import BaseRule

# Secrets that appear verbatim in tutorials and AI-generated code
_KNOWN_BAD: frozenset[str] = frozenset({
    "secret",
    "password",
    "your-secret",
    "your-secret-key",
    "your_secret_key",
    "jwt-secret",
    "jwt_secret",
    "mysecret",
    "my-secret",
    "my_secret",
    "supersecret",
    "super-secret",
    "changeme",
    "change-me",
    "1234567890",
    "qwerty",
    "abc123",
    "token",
    "secretkey",
    "secret-key",
    "secret_key",
    "privatekey",
    "private-key",
})

_MIN_ENTROPY = 4.0


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _iter_nodes(node):
    yield node
    for child in node.children:
        yield from _iter_nodes(child)


def _call_args(call_node) -> list:
    """Named children of the arguments node — the actual expression arguments."""
    args = call_node.child_by_field_name("arguments")
    return list(args.named_children) if args else []


def _string_value(node) -> str | None:
    """Return the literal string content, or None if the node isn't a plain string.

    Returns None for template literals that contain interpolations, since those
    aren't a simple hardcoded value.
    """
    if node.type == "string":
        for child in node.named_children:
            if child.type == "string_fragment":
                return child.text.decode(errors="replace")
        return ""

    if node.type == "template_string":
        # template_substitution nodes are the ${...} interpolations.
        # If there are none, the template is a plain string.
        if not any(c.type == "template_substitution" for c in node.named_children):
            fragments = [c for c in node.named_children if c.type == "string_fragment"]
            return "".join(f.text.decode(errors="replace") for f in fragments)

    return None


def _has_expires_in(options_node) -> bool:
    """Return True if an object literal contains an expiresIn key."""
    for child in options_node.named_children:
        if child.type != "pair":
            continue
        key = child.child_by_field_name("key")
        if key is None:
            continue
        key_text = key.text.decode(errors="replace").strip("\"'")
        if key_text == "expiresIn":
            return True
    return False


def _snippet(lines: list[str], line_no: int) -> str:
    return lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""


class JWTHardcodedSecretRule(BaseRule):
    """Detect hardcoded or weak JWT secrets and missing token expiry.

    Covers the `jsonwebtoken` library (`jwt.sign()`). Flags two distinct
    issues:
    - CRITICAL: the secret argument is a string literal — hardcoded secrets
      are committed to version control and trivially brute-forced.
    - HIGH: the options object is missing `expiresIn` — tokens that never
      expire can be used indefinitely after a breach.
    """

    id = "VCS-003"
    name = "JWT secret hardcoded or weak"
    severity = "CRITICAL"
    languages = ["javascript", "typescript", "tsx"]

    def visit(self, tree, source, filepath):  # noqa: ANN001
        if tree is None:
            return []

        # Skip test/spec files — JWT mocks without expiry are not real vulnerabilities
        fp_lower = filepath.lower()
        if any(
            part in fp_lower
            for part in (".test.", ".spec.", "_test.", "_spec.", "/tests/", "/test/", "/__tests__/")
        ):
            return []

        text = source.decode(errors="replace")
        # Only check files that use jwt.sign() — avoids false positives from
        # crypto.createSign().sign() and other non-JWT .sign() usages.
        if "jsonwebtoken" not in text and "jwt.sign(" not in text and "jwt.verify(" not in text:
            return []

        lines = text.splitlines()
        findings: list[Finding] = []

        for node in _iter_nodes(tree.root_node):
            if node.type != "call_expression":
                continue

            func = node.child_by_field_name("function")
            if func is None or func.type != "member_expression":
                continue

            prop = func.child_by_field_name("property")
            if prop is None or prop.text.decode() != "sign":
                continue

            findings.extend(self._check_call(node, lines, filepath))

        return findings

    def _check_call(self, node, lines: list[str], filepath: str) -> list[Finding]:
        args = _call_args(node)
        if len(args) < 1:
            return []

        call_line = node.start_point[0] + 1
        call_snippet = _snippet(lines, call_line)
        findings: list[Finding] = []

        # ------------------------------------------------------------------
        # Issue 1 — hardcoded secret (2nd argument is a string literal)
        # ------------------------------------------------------------------
        if len(args) >= 2:
            secret_node = args[1]
            secret_val = _string_value(secret_node)

            if secret_val is not None:
                entropy = _shannon_entropy(secret_val)
                is_known_bad = secret_val.lower() in _KNOWN_BAD

                detail = ""
                if is_known_bad:
                    detail = f' ("{secret_val}" is a known-bad value)'
                elif entropy < _MIN_ENTROPY:
                    detail = f" (entropy {entropy:.1f} < {_MIN_ENTROPY})"

                findings.append(
                    Finding(
                        rule_id=self.id,
                        rule_name=self.name,
                        severity="CRITICAL",
                        filepath=filepath,
                        line=secret_node.start_point[0] + 1,
                        col=secret_node.start_point[1],
                        snippet=call_snippet,
                        fix=(
                            f"Hardcoded JWT secret{detail}. "
                            "Move to an environment variable and add an expiry:\n"
                            "  jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' })\n"
                            "  # Generate with: node -e \"console.log(require('crypto')"
                            ".randomBytes(64).toString('hex'))\""
                        ),
                    )
                )
                # Fix text already covers the missing-expiry advice — no second finding
                return findings

        # ------------------------------------------------------------------
        # Issue 2 — missing expiresIn (only checked when secret is not hardcoded)
        # ------------------------------------------------------------------
        if len(args) >= 3:
            options_node = args[2]
            if options_node.type == "object" and not _has_expires_in(options_node):
                findings.append(
                    Finding(
                        rule_id=self.id,
                        rule_name=self.name,
                        severity="HIGH",
                        filepath=filepath,
                        line=options_node.start_point[0] + 1,
                        col=options_node.start_point[1],
                        snippet=call_snippet,
                        fix="Add expiresIn: jwt.sign(payload, secret, { expiresIn: '1h' })",
                    )
                )
        elif len(args) == 2:
            # No options argument at all
            findings.append(
                Finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity="HIGH",
                    filepath=filepath,
                    line=call_line,
                    col=node.start_point[1],
                    snippet=call_snippet,
                    fix="Add expiresIn: jwt.sign(payload, secret, { expiresIn: '1h' })",
                )
            )

        return findings
