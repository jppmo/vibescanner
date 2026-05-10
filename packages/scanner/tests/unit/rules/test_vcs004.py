from __future__ import annotations

from pathlib import Path

import tree_sitter_typescript as ts_ts
from tree_sitter import Language, Parser

from vibescan.rules.vcs004_s3_public_access import S3PublicAccessBlockRule

FIXTURES = Path(__file__).parents[2] / "fixtures" / "VCS-004"

rule = S3PublicAccessBlockRule()
_ts_parser = Parser(Language(ts_ts.language_typescript()))


def scan_tf(content: str) -> list:
    return rule.visit(None, content.encode(), "/fake/main.tf")


def scan_ts(content: str) -> list:
    src = content.encode()
    tree = _ts_parser.parse(src)
    return rule.visit(tree, src, "/fake/stack.ts")


# ---------------------------------------------------------------------------
# Fixture files
# ---------------------------------------------------------------------------


def test_vulnerable_tf_fixture_one_finding():
    source = (FIXTURES / "vulnerable.tf").read_bytes()
    findings = rule.visit(None, source, "/repo/main.tf")
    assert len(findings) == 1
    assert findings[0].rule_id == "VCS-004"
    assert "uploads" in findings[0].fix


def test_clean_tf_fixture_no_findings():
    source = (FIXTURES / "clean.tf").read_bytes()
    assert rule.visit(None, source, "/repo/main.tf") == []


def test_vulnerable_cdk_fixture_two_findings():
    source = (FIXTURES / "vulnerable_cdk.ts").read_bytes()
    tree = _ts_parser.parse(source)
    findings = rule.visit(tree, source, "/repo/stack.ts")
    assert len(findings) == 2


def test_clean_cdk_fixture_no_findings():
    source = (FIXTURES / "clean_cdk.ts").read_bytes()
    tree = _ts_parser.parse(source)
    assert rule.visit(tree, source, "/repo/stack.ts") == []


# ---------------------------------------------------------------------------
# Terraform — block detection
# ---------------------------------------------------------------------------


def test_bucket_without_access_block_flagged():
    tf = 'resource "aws_s3_bucket" "data" {\n  bucket = "my-data"\n}\n'
    findings = scan_tf(tf)
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"


def test_bucket_with_full_access_block_clean():
    tf = """
resource "aws_s3_bucket" "data" {
  bucket = "my-data"
}
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
""".strip()
    assert scan_tf(tf) == []


def test_access_block_missing_one_setting_flagged():
    tf = """
resource "aws_s3_bucket" "data" {
  bucket = "my-data"
}
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = true
}
""".strip()
    findings = scan_tf(tf)
    assert len(findings) == 1
    assert "block_public_policy" in findings[0].fix


def test_multiple_buckets_each_checked_independently():
    tf = """
resource "aws_s3_bucket" "a" { bucket = "a" }
resource "aws_s3_bucket" "b" { bucket = "b" }
resource "aws_s3_bucket_public_access_block" "a" {
  bucket                  = aws_s3_bucket.a.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
""".strip()
    findings = scan_tf(tf)
    assert len(findings) == 1
    assert "b" in findings[0].fix


def test_fix_contains_all_four_settings():
    tf = 'resource "aws_s3_bucket" "logs" {\n  bucket = "logs"\n}\n'
    fix = scan_tf(tf)[0].fix
    for setting in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"):
        assert setting in fix


def test_empty_tf_no_findings():
    assert scan_tf("") == []


def test_non_s3_resource_not_flagged():
    tf = 'resource "aws_dynamodb_table" "users" {\n  name = "users"\n}\n'
    assert scan_tf(tf) == []


# ---------------------------------------------------------------------------
# CDK TypeScript
# ---------------------------------------------------------------------------


def test_cdk_bucket_without_block_flagged():
    ts = "const b = new s3.Bucket(this, 'X', { versioned: true })"
    findings = scan_ts(ts)
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"


def test_cdk_bucket_with_block_all_clean():
    ts = "const b = new s3.Bucket(this, 'X', { blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL })"
    assert scan_ts(ts) == []


def test_cdk_bucket_partial_block_flagged():
    ts = "const b = new s3.Bucket(this, 'X', { blockPublicAccess: new s3.BlockPublicAccess({ blockPublicAcls: false }) })"
    findings = scan_ts(ts)
    assert len(findings) == 1


def test_cdk_fix_mentions_block_all():
    ts = "const b = new s3.Bucket(this, 'X', {})"
    assert "BLOCK_ALL" in scan_ts(ts)[0].fix


def test_cdk_non_bucket_new_expression_not_flagged():
    ts = "const q = new sqs.Queue(this, 'Q', { fifo: true })"
    assert scan_ts(ts) == []


def test_cdk_no_bucket_keyword_skipped():
    ts = "const x = 1 + 2"
    assert scan_ts(ts) == []


def test_tree_none_returns_empty_for_ts():
    assert rule.visit(None, b"new s3.Bucket(this, 'X', {})", "/fake/s.ts") == []
