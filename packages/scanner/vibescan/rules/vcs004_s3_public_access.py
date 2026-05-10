from __future__ import annotations

import re
from typing import ClassVar

from vibescan.models import Finding
from vibescan.rules.base import BaseRule

# ---------------------------------------------------------------------------
# Terraform helpers
# ---------------------------------------------------------------------------

_TF_RESOURCE_RE = re.compile(
    r'^\s*resource\s+"([\w]+)"\s+"(\w+)"\s*\{',
    re.IGNORECASE,
)

# Extracts the referenced S3 bucket resource name from an access block body
# e.g. bucket = aws_s3_bucket.my_bucket.id  →  "my_bucket"
_TF_BUCKET_REF_RE = re.compile(
    r"bucket\s*=\s*aws_s3_bucket\.(\w+)\b",
)

_REQUIRED_SETTINGS = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)

_SETTING_TRUE_RE = {
    s: re.compile(rf"{s}\s*=\s*true", re.IGNORECASE) for s in _REQUIRED_SETTINGS
}


def _parse_tf_resources(lines: list[str]) -> list[dict]:
    """Extract resource blocks from Terraform, tracking brace depth."""
    resources: list[dict] = []
    i = 0
    while i < len(lines):
        m = _TF_RESOURCE_RE.match(lines[i])
        if m:
            resource_type, resource_name = m.group(1), m.group(2)
            start_line = i + 1
            body_lines: list[str] = []
            depth = lines[i].count("{") - lines[i].count("}")
            i += 1
            while i < len(lines) and depth > 0:
                body_lines.append(lines[i])
                depth += lines[i].count("{") - lines[i].count("}")
                i += 1
            resources.append({
                "type": resource_type,
                "name": resource_name,
                "line": start_line,
                "snippet": lines[start_line - 1].strip(),
                "body": "\n".join(body_lines),
            })
        else:
            i += 1
    return resources


def _tf_fix(bucket_name: str, missing: list[str] | None = None) -> str:
    settings = "\n  ".join(f"{s:<25} = true" for s in _REQUIRED_SETTINGS)
    fix = (
        f'resource "aws_s3_bucket_public_access_block" "{bucket_name}" {{\n'
        f"  bucket = aws_s3_bucket.{bucket_name}.id\n\n"
        f"  {settings}\n}}"
    )
    if missing:
        fix = f"Set these to true in the access block: {', '.join(missing)}\n\n" + fix
    return fix


# ---------------------------------------------------------------------------
# CDK helpers
# ---------------------------------------------------------------------------


def _iter_nodes(node):
    yield node
    for child in node.children:
        yield from _iter_nodes(child)


def _cdk_props_object(new_node):
    """Return the last object literal argument of a new_expression, if any."""
    args = new_node.child_by_field_name("arguments")
    if args is None:
        return None
    for child in reversed(args.named_children):
        if child.type == "object":
            return child
    return None


def _has_block_all(props_node) -> bool:
    """Return True if the props object has blockPublicAccess set to BLOCK_ALL."""
    for pair in props_node.named_children:
        if pair.type != "pair":
            continue
        key = pair.child_by_field_name("key")
        if key is None or key.text.decode() != "blockPublicAccess":
            continue
        val = pair.child_by_field_name("value")
        if val is not None and b"BLOCK_ALL" in val.text:
            return True
    return False


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------


class S3PublicAccessBlockRule(BaseRule):
    """Detect S3 buckets created without public access block settings.

    Covers two IaC formats:
    - Terraform: `aws_s3_bucket` without a matching
      `aws_s3_bucket_public_access_block` that sets all four settings to true.
    - AWS CDK (TypeScript): `new s3.Bucket(...)` without
      `blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL`.
    """

    id = "VCS-004"
    name = "S3 bucket without public access block"
    severity = "CRITICAL"
    languages: ClassVar[list[str]] = ["terraform", "typescript", "tsx"]

    def visit(self, tree, source: bytes, filepath: str) -> list[Finding]:
        text = source.decode(errors="replace")

        if filepath.endswith(".tf"):
            return self._check_terraform(text, filepath)
        return self._check_cdk(tree, text, filepath)

    # ------------------------------------------------------------------
    # Terraform
    # ------------------------------------------------------------------

    def _check_terraform(self, text: str, filepath: str) -> list[Finding]:
        lines = text.splitlines()
        resources = _parse_tf_resources(lines)

        buckets = {r["name"]: r for r in resources if r["type"] == "aws_s3_bucket"}
        access_blocks = [r for r in resources if r["type"] == "aws_s3_bucket_public_access_block"]

        # Map bucket resource name → its access block
        bucket_to_block: dict[str, dict] = {}
        for ab in access_blocks:
            m = _TF_BUCKET_REF_RE.search(ab["body"])
            if m:
                bucket_to_block[m.group(1)] = ab

        findings: list[Finding] = []
        for name, bucket in buckets.items():
            if name not in bucket_to_block:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        rule_name=self.name,
                        severity=self.severity,
                        filepath=filepath,
                        line=bucket["line"],
                        col=0,
                        snippet=bucket["snippet"],
                        fix=_tf_fix(name),
                    )
                )
                continue

            ab = bucket_to_block[name]
            missing = [s for s in _REQUIRED_SETTINGS if not _SETTING_TRUE_RE[s].search(ab["body"])]
            if missing:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        rule_name=self.name,
                        severity=self.severity,
                        filepath=filepath,
                        line=ab["line"],
                        col=0,
                        snippet=ab["snippet"],
                        fix=_tf_fix(name, missing),
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # CDK TypeScript
    # ------------------------------------------------------------------

    def _check_cdk(self, tree, text: str, filepath: str) -> list[Finding]:
        if tree is None or "Bucket" not in text:
            return []

        lines = text.splitlines()
        findings: list[Finding] = []

        for node in _iter_nodes(tree.root_node):
            if node.type != "new_expression":
                continue

            constructor = node.child_by_field_name("constructor")
            if constructor is None:
                continue

            # Accept s3.Bucket, S3.Bucket, aws_s3.Bucket, or bare Bucket
            prop = constructor.child_by_field_name("property") if constructor.type == "member_expression" else constructor
            if prop is None or prop.text.decode() != "Bucket":
                continue

            props_obj = _cdk_props_object(node)
            if props_obj is None or _has_block_all(props_obj):
                continue

            line_no = node.start_point[0] + 1
            findings.append(
                Finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    filepath=filepath,
                    line=line_no,
                    col=node.start_point[1],
                    snippet=lines[line_no - 1].strip() if line_no <= len(lines) else "",
                    fix=(
                        "Add blockPublicAccess to the Bucket props:\n"
                        "  new s3.Bucket(this, 'MyBucket', {\n"
                        "    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,\n"
                        "  })"
                    ),
                )
            )

        return findings
