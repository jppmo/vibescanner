from __future__ import annotations

import re
from typing import ClassVar

from vibescan.models import Finding
from vibescan.rules._helpers import is_test_path, matches_outside_strings
from vibescan.rules.base import BaseRule

# ---------------------------------------------------------------------------
# Python patterns
# ---------------------------------------------------------------------------

_PY_HASHLIB_WEAK = re.compile(
    r"\bhashlib\.(md5|sha1|new\s*\(\s*['\"](md5|sha1)['\"])\s*\(",
    re.IGNORECASE,
)
_PY_PYCRYPTO_DES = re.compile(
    r"\b(?:(?:Crypto|Cryptodome)\.Cipher\.)?(DES|DES3|ARC2|ARC4|Blowfish)\."
    r"new\s*\(",
)
_PY_AES_ECB = re.compile(
    r"\bAES\.MODE_ECB\b|\bMODE_ECB\b",
    re.IGNORECASE,
)
_PY_HMAC_WEAK = re.compile(
    r"hmac\.new\s*\([^)]+digestmod\s*=\s*(?:hashlib\.)?(md5|sha1)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# JS/TS patterns
# ---------------------------------------------------------------------------

_JS_CREATE_HASH_WEAK = re.compile(
    r"createHash\s*\(\s*['\"`](md5|sha1)['\"`]\s*\)",
    re.IGNORECASE,
)
_JS_CIPHER_WEAK = re.compile(
    r"createCipheriv?\s*\(\s*['\"`]"
    r"(des(?:-(?:ecb|cbc|cfb|ofb))?|3des|rc4|rc2|bf(?:-(?:ecb|cbc))?|aes-\d+-ecb)"
    r"['\"`]",
    re.IGNORECASE,
)


class WeakCryptoRule(BaseRule):
    """Detect weak/broken cryptographic primitives.

    Catches:
    - MD5, SHA1 hashing (collision attacks demonstrated)
    - DES, 3DES, RC4, RC2, Blowfish ciphers (broken or deprecated)
    - AES in ECB mode (does not hide patterns; never appropriate)
    - HMAC built on MD5/SHA1
    """

    id = "VCS-012"
    name = "Weak or broken cryptographic primitive"
    severity = "HIGH"
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
                for m in matches_outside_strings(_PY_HASHLIB_WEAK, line):
                    algo = (m.group(1) or m.group(2) or "").lower().split("(")[0]
                    findings.append(self._finding(filepath, i, stripped, algo, "hashlib"))
                for m in matches_outside_strings(_PY_PYCRYPTO_DES, line):
                    findings.append(
                        self._finding(filepath, i, stripped, m.group(1).lower(), "Crypto.Cipher"),
                    )
                for _ in matches_outside_strings(_PY_AES_ECB, line):
                    findings.append(self._finding(filepath, i, stripped, "AES-ECB", "Crypto"))
                for m in matches_outside_strings(_PY_HMAC_WEAK, line):
                    findings.append(
                        self._finding(filepath, i, stripped, f"HMAC-{m.group(1).lower()}", "hmac"),
                    )
            else:
                for m in matches_outside_strings(_JS_CREATE_HASH_WEAK, line):
                    findings.append(
                        self._finding(filepath, i, stripped, m.group(1).lower(), "node:crypto"),
                    )
                for m in matches_outside_strings(_JS_CIPHER_WEAK, line):
                    findings.append(
                        self._finding(filepath, i, stripped, m.group(1).lower(), "node:crypto"),
                    )

        return findings

    def _finding(self, filepath: str, line: int, snippet: str, algo: str, library: str) -> Finding:
        fix = _FIX_BY_ALGO.get(algo.split("-", maxsplit=1)[0], _DEFAULT_FIX).format(algo=algo, library=library)
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
    "{algo} ({library}) is broken or deprecated. Use SHA-256 / SHA-3 for hashing "
    "and AES-GCM for symmetric encryption."
)

_FIX_BY_ALGO = {
    "md5": "MD5 is broken (collisions trivial). Use hashlib.sha256() instead. "
           "For password hashing use bcrypt/argon2id, not a raw hash.",
    "sha1": "SHA-1 is deprecated (Shattered, 2017). Use hashlib.sha256() or sha3_256().",
    "des": "DES is broken (56-bit key). Use AES-256 in GCM mode: "
           "Crypto.Cipher.AES.new(key, AES.MODE_GCM, nonce).",
    "3des": "3DES (TripleDES) is deprecated by NIST. Use AES-256-GCM.",
    "rc4": "RC4 is cryptographically broken. Use AES-256-GCM.",
    "rc2": "RC2 is broken. Use AES-256-GCM.",
    "bf": "Blowfish has weak keys; the 64-bit block size is also vulnerable to "
          "birthday attacks (Sweet32). Use AES-256-GCM.",
    "blowfish": "Blowfish is deprecated. Use AES-256-GCM.",
    "aes": "AES in ECB mode does not hide plaintext patterns. Use AES-GCM "
           "(authenticated) or AES-CBC with a random IV.",
    "hmac": "HMAC built on MD5/SHA-1 inherits their weaknesses. Use HMAC-SHA-256.",
}
