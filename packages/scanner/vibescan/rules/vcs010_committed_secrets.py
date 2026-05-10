from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

from vibescan.models import Finding
from vibescan.rules.base import BaseRule

# ---------------------------------------------------------------------------
# PEM detection
# ---------------------------------------------------------------------------

_PEM_PRIVATE_HEADERS: tuple[bytes, ...] = (
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN PGP PRIVATE KEY BLOCK-----",
)

# ---------------------------------------------------------------------------
# .env secret detection
# ---------------------------------------------------------------------------

_ENV_LINE_RE = re.compile(r"^([A-Z_][A-Z0-9_]*)=(.*)$", re.IGNORECASE)

_SECRET_NAME_RE = re.compile(
    # Match keywords that appear as underscore-separated segments.
    # \b doesn't work here because _ is a word character; use (?:^|_) instead.
    r"(?:^|_)(SECRET|PASSWORD|PASSWD|PWD|PRIVATE|TOKEN|CREDENTIAL|KEY)(?:_|$)",
    re.IGNORECASE,
)

# Variable names that match _SECRET_NAME_RE but are known-public — skip them.
_SAFE_NAME_RE = re.compile(
    r"(?:^|_)(PUBLISHABLE_KEY|PUBLISHABLE|ANON_KEY|ANON|PUBLIC_KEY)(?:_|$)",
    re.IGNORECASE,
)

# Frontend-bundled prefixes — VCS-011 owns these; skip here to avoid duplicate findings.
_FRONTEND_PREFIXES: tuple[str, ...] = (
    "VITE_",
    "NEXT_PUBLIC_",
    "REACT_APP_",
    "NUXT_PUBLIC_",
    "EXPO_PUBLIC_",
    "GATSBY_",
)

# Values that are obviously placeholders — do not flag these
_PLACEHOLDER_RE = re.compile(
    r"^(your[-_]|example|placeholder|changeme|changethis|todo|x{3,}|<[^>]*>"
    r"|insert|dummy|fake|replace|none|null|undefined|true|false|\d{1,4}"
    r"|some[-_]|local[-_]|local$"          # some-secret, local_dev, local
    r"|dev$|development$|test$|testing$"   # bare environment names
    r"|secret$|password$"                  # the literal words used as values
    r"|postgres$|localhost|admin$).*$|^$",
    re.IGNORECASE,
)

# These file names are intentionally committed templates — always skip
_EXAMPLE_SUFFIXES: tuple[str, ...] = (".example", ".template", ".sample", ".dist")


class CommittedSecretsRule(BaseRule):
    """Detect private keys and real secrets committed to the repository.

    Checks:
    - PEM/key files containing private key material (RSA, EC, OpenSSH, PKCS#8, PGP)
    - .env files (not .env.example/.env.template) containing real-looking secret values
    """

    id = "VCS-010"
    name = "Private key or secret committed to repository"
    severity = "CRITICAL"
    languages: ClassVar[list[str]] = ["pem", "env"]

    def visit(self, tree, source: bytes, filepath: str) -> list[Finding]:
        name = Path(filepath).name.lower()
        is_pem = (
            filepath.endswith((".pem", ".key", ".p12", ".pfx"))
            or name in {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"}
        )
        return self._check_pem(source, filepath) if is_pem else self._check_env(source, filepath)

    # ------------------------------------------------------------------
    # PEM
    # ------------------------------------------------------------------

    def _check_pem(self, source: bytes, filepath: str) -> list[Finding]:
        for header in _PEM_PRIVATE_HEADERS:
            if header not in source:
                continue
            line_no = next(
                (i + 1 for i, line in enumerate(source.splitlines()) if header in line),
                1,
            )
            return [
                Finding(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    filepath=filepath,
                    line=line_no,
                    col=0,
                    snippet=header.decode(),
                    fix=(
                        f"Remove this file from the repository immediately:\n\n"
                        f"  git rm --cached {filepath}\n"
                        f"  echo '*.pem' >> .gitignore\n\n"
                        f"Then rotate the key — assume it is compromised if it was ever pushed to a remote."
                    ),
                )
            ]
        return []

    # ------------------------------------------------------------------
    # .env
    # ------------------------------------------------------------------

    def _check_env(self, source: bytes, filepath: str) -> list[Finding]:
        name = Path(filepath).name.lower()
        # Skip template/example files — they are intentionally committed
        if any(name.endswith(s) for s in _EXAMPLE_SUFFIXES):
            return []
        # Handle .env.example, .env.template, .env.sample, .env.dist naming
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

            key = m.group(1)
            value = m.group(2).strip().strip('"').strip("'")

            if not _SECRET_NAME_RE.search(key):
                continue
            if _SAFE_NAME_RE.search(key):
                continue
            # Skip frontend-prefixed vars — VCS-011 handles those with better advice
            if any(key.upper().startswith(p) for p in _FRONTEND_PREFIXES):
                continue
            if not value or _PLACEHOLDER_RE.match(value):
                continue
            # Skip values that are file paths — the variable points to a file
            # containing a secret, but the committed value itself is not the secret
            if any(value.endswith(ext) for ext in (".json", ".pem", ".p12", ".yaml", ".yml", ".txt", ".key", ".crt", ".pfx")):
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
                        f"Remove the value of {key} from this file:\n\n"
                        f"  1. Replace the real value with a placeholder: {key}=your-value-here\n"
                        f"  2. Ensure this file is in .gitignore (or use .env.example for templates)\n"
                        f"  3. If this was ever committed to git, rotate the secret immediately\n"
                        f"  4. Inject real values at deploy time via Railway / Vercel / GitHub Secrets"
                    ),
                )
            )

        return findings
