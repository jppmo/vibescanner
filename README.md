# Vibescan

**Security scanner for AI-generated code.**

Vibescan finds the vulnerabilities that AI coding tools produce repeatedly — missing Supabase RLS, hardcoded secrets, hallucinated packages, open Firebase rules, broken auth, and insecure cloud config.

We scanned 20 public repos built with Lovable, Cursor, Claude Code, and ChatGPT. 45% had real security findings on the first run.

---

## Install

```bash
pip install vibescan-cli
```

Requires Python 3.10+.

---

## Usage

```bash
# Scan the current directory
vibescan scan .

# Scan a specific repo
vibescan scan /path/to/project

# Output JSON (for CI integration)
vibescan scan . --format json

# Only fail CI on CRITICAL findings (default)
vibescan scan . --fail-on CRITICAL

# Ignore a rule
vibescan scan . --ignore-rule VCS-005

# Save findings to a file
vibescan scan . --output findings.json
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings |
| `1` | Findings exist but below `--fail-on` threshold |
| `2` | Findings at or above `--fail-on` threshold |
| `3` | Scanner error |

---

## What it catches

| Rule | Severity | What | Languages |
|------|----------|------|-----------|
| VCS-001 | CRITICAL | Supabase table without Row Level Security | SQL |
| VCS-002 | CRITICAL | Firebase open read/write rules | `.rules`, JSON |
| VCS-003 | HIGH | Weak or hardcoded JWT secret | JS, TS |
| VCS-004 | HIGH | S3 bucket without public access block | Terraform, TS |
| VCS-005 | HIGH | Route handler with no server-side auth | JS, TS, Python |
| VCS-006 | CRITICAL/HIGH | Hallucinated or anomalous npm/PyPI package | JSON, TOML, TXT |
| VCS-010 | CRITICAL | Private key or secret committed to repo | `.pem`, `.env` |
| VCS-011 | HIGH | Secret in frontend env variable (`VITE_*`, `NEXT_PUBLIC_*`) | `.env` |

### VCS-001 — Supabase RLS

Supabase exposes your database directly to the client via the anon key. Without Row Level Security, any authenticated user can read or modify every row.

```
CRITICAL  VCS-001  supabase/migrations/20240101_init.sql:3
  CREATE TABLE payments (
  Fix: ALTER TABLE payments ENABLE ROW LEVEL SECURITY;
       CREATE POLICY "authenticated_only" ON payments
         FOR ALL TO authenticated USING (auth.uid() IS NOT NULL);
```

### VCS-005 — Missing server-side auth

AI tools generate the happy path. Auth comes last — often never.

```
HIGH  VCS-005  src/routes/users.ts:12
  router.get('/users', async (req, res) => {
  Fix: Add authenticate middleware before the handler
```

### VCS-006 — Hallucinated packages

AI models suggest packages that don't exist on npm or PyPI. An attacker can register the invented name and have it executed by anyone who runs `npm install`.

```
CRITICAL  VCS-006  package.json:1
  "@myapp/internal-utils"
  Fix: "@myapp/internal-utils" was not found on npm. Remove it or replace with the correct package name.
```

### VCS-010 — Committed secrets

Private keys and real secret values committed to the repository.

```
CRITICAL  VCS-010  .env:4
  STRIPE_SECRET_KEY=sk_live_51Hxyz...
  Fix: Remove the value, add .env to .gitignore, rotate the secret.
```

### VCS-011 — Frontend-exposed secrets

Variables prefixed with `VITE_`, `NEXT_PUBLIC_`, `REACT_APP_`, etc. are embedded in the compiled JavaScript bundle and readable by any visitor.

```
HIGH  VCS-011  .env:7
  VITE_SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
  Fix: Remove VITE_ prefix. Access this only in server-side code.
```

---

## CI integration

Add to `.github/workflows/security.yml`:

```yaml
name: Security scan
on: [push, pull_request]

jobs:
  vibescan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install vibescan-cli
      - run: vibescan scan . --fail-on CRITICAL --format json --output findings.json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: vibescan-findings
          path: findings.json
```

---

## AI origin detection

Vibescan scores every finding by how likely the code was AI-generated:

- **Hard signal (score 1.0):** `Co-authored-by` in git history matching Copilot, Cursor, Claude, ChatGPT, Lovable, Bolt, or Replit
- **Soft signal (score 0.0–1.0):** Comment density, AI-phrase patterns, docstring structure

Findings from high-confidence AI-generated code are surfaced first.

---

## Known limitations

- **VCS-001** only fires on SQL files inside a Supabase project context (`supabase/` directory, or containing `auth.uid()`). Plain PostgreSQL/Prisma migrations are not flagged.
- **VCS-005** cannot detect auth enforced at the framework middleware level (`app.add_middleware(...)`). It checks per-route patterns only.
- **VCS-006** requires network access to npm/PyPI registries. Redis cache is used when `REDIS_URL` is set. Packages using `workspace:` / `file:` version specs are skipped.
- Scanning is single-threaded in this release. Large repos (>10K files) may take 30–60 seconds.

---

## What we found scanning 20 real repos

| Metric | Result |
|--------|--------|
| Repos with findings | 9 / 20 (45%) |
| CRITICAL findings | 9 |
| HIGH findings | 36 |
| Most common issue | Missing route-level auth (VCS-005) |
| Most dangerous | Committed Django secret key + Supabase JWT in public repo |

Repos built with Lovable and Bolt were most likely to have Supabase RLS gaps. Repos built with Cursor had better route-level auth but more committed secrets in `.env` files.

---

## Roadmap

- [ ] GitHub App — scan PRs, annotate inline, block merge on CRITICAL
- [ ] VS Code extension — inline squiggles as you type
- [ ] VCS-007: Open CORS policy (`origin: "*"`)
- [ ] VCS-008: Missing HTTPS redirect
- [ ] VCS-009: SQL injection via string interpolation
- [ ] Cross-file RLS tracking (catch split-migration patterns)
- [ ] Platform attribution: identify Lovable vs Bolt vs Cursor output

---

## Contributing

Rules live in `packages/scanner/vibescan/rules/`. Each rule is a Python class. Drop a new file in — it runs automatically on the next scan.

Every new rule needs fixture files:
```
tests/fixtures/VCS-XXX/vulnerable.{ext}   # must produce a finding
tests/fixtures/VCS-XXX/clean.{ext}        # must produce zero findings
```

See `docs/rules.md` for the full authoring guide.

---

## License

MIT
