from __future__ import annotations

import re
from typing import ClassVar

from vibescan.models import Finding
from vibescan.rules._helpers import is_test_path, matches_outside_strings
from vibescan.rules.base import BaseRule

# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

# subprocess.{run,Popen,call,check_output,check_call} with shell=True
_PY_SUBPROCESS_SHELL = re.compile(
    r"subprocess\.(?:run|Popen|call|check_output|check_call)\s*\([^)]*\bshell\s*=\s*True\b",
    re.DOTALL,
)
# os.system / os.popen — taking any input is dangerous
_PY_OS_SYSTEM = re.compile(r"\bos\.(system|popen)\s*\(")
# eval / exec — flag any usage. Almost never appropriate in production code.
_PY_EVAL_EXEC = re.compile(r"(?<![\w.])(eval|exec)\s*\(")
# commands.getoutput is the legacy 2.x API but still appears in vibe-coded snippets
_PY_COMMANDS_GETOUTPUT = re.compile(r"\bcommands\.getoutput\s*\(")

# ---------------------------------------------------------------------------
# JS/TS
# ---------------------------------------------------------------------------

_JS_CHILD_PROCESS_EXEC = re.compile(
    r"(?:child_process\.|require\(['\"]child_process['\"]\)\.|\b)"
    r"(execSync|exec)\s*\(",
)
_JS_EVAL = re.compile(r"(?<![\w.])(eval)\s*\(")
_JS_VM_RUN = re.compile(r"\bvm\.(runInThisContext|runInNewContext|runInContext)\s*\(")
_JS_FUNCTION_CTOR = re.compile(r"new\s+Function\s*\(")


class ShellInjectionRule(BaseRule):
    """Detect shell injection / unsafe-eval primitives.

    Catches:
    - Python: subprocess(..., shell=True), os.system, os.popen, eval, exec
    - JS/TS: child_process.exec/execSync, eval, vm.runIn*Context, new Function()
    """

    id = "VCS-015"
    name = "Shell injection or unsafe eval"
    severity = "CRITICAL"
    languages: ClassVar[list[str]] = ["python", "javascript", "typescript", "tsx"]

    def visit(self, tree, source: bytes, filepath: str) -> list[Finding]:
        if is_test_path(filepath):
            return []

        text = source.decode(errors="replace")
        lines = text.splitlines()
        findings: list[Finding] = []
        is_python = filepath.endswith(".py")

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//")):
                continue

            if is_python:
                if matches_outside_strings(_PY_SUBPROCESS_SHELL, line):
                    findings.append(self._finding(filepath, i, stripped, "subprocess shell=True"))
                elif matches := matches_outside_strings(_PY_OS_SYSTEM, line):
                    findings.append(self._finding(filepath, i, stripped, f"os.{matches[0].group(1)}"))
                elif matches := matches_outside_strings(_PY_EVAL_EXEC, line):
                    findings.append(self._finding(filepath, i, stripped, matches[0].group(1)))
                elif matches_outside_strings(_PY_COMMANDS_GETOUTPUT, line):
                    findings.append(self._finding(filepath, i, stripped, "commands.getoutput"))
            elif matches := matches_outside_strings(_JS_CHILD_PROCESS_EXEC, line):
                findings.append(self._finding(filepath, i, stripped, f"child_process.{matches[0].group(1)}"))
            elif matches_outside_strings(_JS_EVAL, line):
                findings.append(self._finding(filepath, i, stripped, "eval"))
            elif matches := matches_outside_strings(_JS_VM_RUN, line):
                findings.append(self._finding(filepath, i, stripped, f"vm.{matches[0].group(1)}"))
            elif matches_outside_strings(_JS_FUNCTION_CTOR, line):
                findings.append(self._finding(filepath, i, stripped, "new Function()"))

        return findings

    def _finding(self, filepath: str, line: int, snippet: str, primitive: str) -> Finding:
        fix = _FIXES.get(primitive.split(maxsplit=1)[0].lower(), _DEFAULT_FIX).format(primitive=primitive)
        return Finding(
            rule_id=self.id,
            rule_name=self.name,
            severity=self.severity,
            filepath=filepath,
            line=line,
            col=0,
            snippet=snippet,
            fix=fix,
        )


_DEFAULT_FIX = (
    "`{primitive}` executes arbitrary code if any input flows into it. "
    "Use a safer alternative or strict input allow-listing."
)

_FIXES = {
    "subprocess": (
        "shell=True passes the entire command string to /bin/sh — any user-influenced "
        "input becomes shell injection. Use a list of args:\n"
        "  subprocess.run(['ls', '-la', user_path], check=True)"
    ),
    "os.system": (
        "os.system() invokes the shell. Use subprocess.run([...], check=True) with an "
        "argument list — never with shell=True."
    ),
    "os.popen": (
        "os.popen() invokes the shell. Use subprocess.run with capture_output=True and "
        "an argument list."
    ),
    "eval": (
        "eval() executes arbitrary code. Replace with json.loads / ast.literal_eval / a "
        "purpose-built parser. There is almost never a legitimate use of eval in app code."
    ),
    "exec": (
        "exec() executes arbitrary code. Refactor to call the actual function/method "
        "directly. There is almost never a legitimate use of exec in app code."
    ),
    "child_process.exec": (
        "child_process.exec runs the command via /bin/sh. Use child_process.execFile or "
        "spawn with an argument array:\n"
        "  spawn('git', ['log', '--format=%B'])"
    ),
    "child_process.execSync": (
        "child_process.execSync runs the command via /bin/sh. Use execFileSync or "
        "spawnSync with an argument array."
    ),
    "vm": (
        "vm.runIn*Context executes arbitrary JS. There is no sandbox guarantee for "
        "untrusted input. Avoid passing user input to vm.* APIs."
    ),
    "new": (
        "new Function() compiles a string into executable JS. Treat any user input "
        "passed to it as an XSS/RCE source. Refactor to call known functions directly."
    ),
}
