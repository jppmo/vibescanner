from __future__ import annotations

from pathlib import Path

from vibescan.rules.vcs015_shell_injection import ShellInjectionRule

FIXTURES = Path(__file__).parents[2] / "fixtures" / "VCS-015"
rule = ShellInjectionRule()


def scan_py(src: str) -> list:
    return rule.visit(None, src.encode(), "/repo/app.py")


def scan_js(src: str) -> list:
    return rule.visit(None, src.encode(), "/repo/app.js")


def test_vulnerable_python_fixture():
    findings = rule.visit(None, (FIXTURES / "vulnerable.py").read_bytes(), "/repo/app.py")
    # subprocess shell=True, os.system, os.popen, eval, exec
    assert len(findings) >= 5, [f.snippet for f in findings]


def test_clean_python_fixture():
    assert rule.visit(None, (FIXTURES / "clean.py").read_bytes(), "/repo/clean.py") == []


def test_vulnerable_js_fixture():
    findings = rule.visit(None, (FIXTURES / "vulnerable.js").read_bytes(), "/repo/app.js")
    # exec, execSync, eval, vm.runInNewContext, new Function
    assert len(findings) >= 5, [f.snippet for f in findings]


def test_clean_js_fixture():
    assert rule.visit(None, (FIXTURES / "clean.js").read_bytes(), "/repo/clean.js") == []


def test_subprocess_shell_true():
    src = 'subprocess.run(f"git pull {b}", shell=True)'
    assert len(scan_py(src)) == 1


def test_os_system():
    assert len(scan_py('os.system("ls " + path)')) == 1


def test_python_eval():
    assert len(scan_py("result = eval(user_input)")) == 1


def test_subprocess_args_list_clean():
    assert scan_py('subprocess.run(["ls", "-la", path])') == []


def test_js_child_process_exec():
    assert len(scan_js("child_process.exec(`ls ${dir}`)")) == 1


def test_js_eval():
    assert len(scan_js("const r = eval(input);")) == 1


def test_js_new_function():
    assert len(scan_js("const fn = new Function(body);")) == 1


def test_js_spawn_clean():
    assert scan_js('spawn("ls", ["-la", dir]);') == []


def test_test_dir_skipped():
    assert rule.visit(None, b"os.system(x)", "/repo/tests/test_x.py") == []
