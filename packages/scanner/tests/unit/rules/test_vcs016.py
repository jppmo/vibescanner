from __future__ import annotations

from pathlib import Path

from vibescan.rules.vcs016_xxe import XXEUnsafeParserRule

FIXTURES = Path(__file__).parents[2] / "fixtures" / "VCS-016"
rule = XXEUnsafeParserRule()


def scan(src: str) -> list:
    return rule.visit(None, src.encode(), "/repo/app.py")


def test_vulnerable_fixture():
    findings = rule.visit(None, (FIXTURES / "vulnerable.py").read_bytes(), "/repo/vuln.py")
    # ET.fromstring, minidom.parse, lxml resolve_entities=True
    assert len(findings) >= 3, [f.snippet for f in findings]


def test_clean_fixture():
    findings = rule.visit(None, (FIXTURES / "clean.py").read_bytes(), "/repo/clean.py")
    assert findings == []


def test_etree_fromstring_unsafe():
    src = "import xml.etree.ElementTree as ET\nroot = ET.fromstring(data)"
    assert len(scan(src)) == 1


def test_minidom_parse_unsafe():
    src = "from xml.dom import minidom\ndoc = minidom.parse(path)"
    assert len(scan(src)) == 1


def test_lxml_with_resolve_entities_true():
    src = (
        "from lxml import etree\n"
        "p = etree.XMLParser(resolve_entities=True)\n"
        "etree.fromstring(data, p)"
    )
    findings = scan(src)
    # Should fire on the explicit resolve_entities=True
    assert len(findings) >= 1
    assert any("resolve_entities" in f.snippet for f in findings)


def test_lxml_with_resolve_entities_false_clean():
    src = (
        "from lxml import etree\n"
        "p = etree.XMLParser(resolve_entities=False)\n"
        "etree.fromstring(data, p)"
    )
    # The fromstring line still imports lxml but the parser line is safe; rule
    # should not flag the resolve_entities=False line.
    findings = scan(src)
    for f in findings:
        assert "resolve_entities=True" not in f.snippet


def test_defusedxml_imported_makes_clean():
    src = (
        "from defusedxml.ElementTree import fromstring\n"
        "import xml.etree.ElementTree as ET\n"  # still imports unsafe but…
        "root = fromstring(data)"
    )
    # Defusedxml is imported — heuristic says trust the developer
    assert scan(src) == []


def test_no_xml_import_returns_empty():
    src = "x = ET.parse('foo.xml')"  # no import → not flagged
    assert scan(src) == []


def test_test_dir_skipped():
    src = "import xml.etree.ElementTree as ET\nET.fromstring(d)"
    assert rule.visit(None, src.encode(), "/repo/tests/test_x.py") == []


def test_non_python_file_returns_empty():
    src = "import xml.etree.ElementTree as ET\nET.fromstring(d)"
    assert rule.visit(None, src.encode(), "/repo/app.js") == []
