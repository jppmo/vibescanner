from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

from vibescan.models import Finding
from vibescan.rules.base import BaseRule

# ---------------------------------------------------------------------------
# Frontend-accessible env var prefixes
# These prefixes cause the value to be embedded in the compiled JS bundle.
# ---------------------------------------------------------------------------

_FRONTEND_PREFIXES: tuple[str, ...] = (
    "VITE_",
    "NEXT_PUBLIC_",
    "REACT_APP_",
    "NUXT_PUBLIC_",
    "EXPO_PUBLIC_",
    "GATSBY_",
)

# After stripping the frontend prefix, if the remaining name matches any of
# these it likely contains sensitive material.
# Use (?:^|_)...($ |_) instead of \b: underscores are word characters, so
# \b doesn't fire between segments like STRIPE_SECRET_KEY.
_SECRET_SUFFIX_RE = re.compile(
    r"(?:^|_)(SECRET|SERVICE_ROLE|SERVICE_KEY|PRIVATE_KEY|PRIVATE|PASSWORD|PASSWD"
    r"|PWD|TOKEN|SIGNING_KEY|MASTER_KEY|KEY)(?:_|$)",
    re.IGNORECASE,
)

# Names that are intentionally public — never flag these even if they match above
_SAFE_SUFFIX_RE = re.compile(
    r"(?:^|_)(ANON_KEY|ANON|PUBLIC_KEY|PUBLISHABLE_KEY|PUBLISHABLE|PUBLIC"
    r"|APP_NAME|APP_URL|API_URL|BASE_URL|URL|HOST|PORT|ENV|MODE|DEBUG)(?:_|$)",
    re.IGNORECASE,
)

_ENV_LINE_RE = re.compile(r"^([A-Z_][A-Z0-9_]*)=(.*)$", re.IGNORECASE)

_PLACEHOLDER_RE = re.compile(
    r"^(your[-_]|example|placeholder|changeme|todo|x{3,}|<[^>]*>"
    r"|insert|dummy|fake|replace|none|null|undefined|true|false|\d{1,4}).*$|^$",
    re.IGNORECASE,
)


class FrontendExposedSecretsRule(BaseRule):
    """Detect secrets embedded in frontend-accessible environment variables.

    Flags variables prefixed with VITE_, NEXT_PUBLIC_, REACT_APP_, NUXT_PUBLIC_,
    EXPO_PUBLIC_, or GATSBY_ whose name suggests sensitive content (service keys,
    private keys, tokens, passwords).

    These prefixes cause values to be inlined into the compiled JavaScript bundle,
    making them readable by any visitor in browser DevTools.
    """

    id = "VCS-011"
    name = "Secret exposed via frontend environment variable prefix"
    severity = "HIGH"
    languages: ClassVar[list[str]] = ["env"]

    def visit(self, tree, source: bytes, filepath: str) -> list[Finding]:
        name = Path(filepath).name.lower()
        if any(name.endswith(s) for s in (".example", ".template", ".sample", ".dist")):
            return []
        if ".env." in name:
            suffix = name.split(".env.", 1)[1]
            if suffix in {"example", "template", "sample", "dist"}:
                return []

        lines = source.decode(errors="replace").splitlines()
        findings: list[Finding] = []

        for i, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            m = _ENV_LINE_RE.match(line)
            if not m:
                continue

            var_name = m.group(1)
            value = m.group(2).strip().strip('"').strip("'")

            matched_prefix = next(
                (p for p in _FRONTEND_PREFIXES if var_name.upper().startswith(p)),
                None,
            )
            if matched_prefix is None:
                continue

            suffix = var_name[len(matched_prefix):]

            if _SAFE_SUFFIX_RE.search(suffix):
                continue
            if not _SECRET_SUFFIX_RE.search(suffix):
                continue
            if _PLACEHOLDER_RE.match(value):
                continue

            findings.append(
                Finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    filepath=filepath,
                    line=i,
                    col=0,
                    snippet=raw_line.rstrip(),
                    fix=(
                        f"Move {var_name} to a server-only variable:\n\n"
                        f"  1. Rename to {suffix} (remove the '{matched_prefix}' prefix)\n"
                        f"  2. Access it only in server-side code: API routes, Edge Functions, server components\n"
                        f"  3. Never read secret values in client-side JS — they end up in the JS bundle\n"
                        f"  4. If this was ever deployed with a real value, rotate the secret immediately"
                    ),
                )
            )

        return findings
