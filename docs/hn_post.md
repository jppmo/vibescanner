# Show HN: Vibescan – security scanner for AI-generated code

**Title:** Show HN: I scanned 20 vibe-coded repos – here's what I found

---

## Post body

I built a static analysis tool specifically for AI-generated code. After noticing the same security mistakes showing up in every Lovable/Cursor/Claude project I looked at, I wrote rules for them and ran it on 20 public repos.

**Results: 9 of 20 repos had real security findings. 4 had CRITICAL issues.**

Here's what it found and why these patterns keep appearing.

---

### The findings

**Supabase RLS not enabled (VCS-001) — CRITICAL**

Supabase exposes your database directly to clients via the anon key. Without Row Level Security, any logged-in user can read every row in every table. Found this in 2 repos, including one finance app with a `payments` table fully exposed.

Why AI does this: Lovable and Bolt scaffold the Supabase schema and auth in one pass. RLS is a separate step — ALTER TABLE, then a policy per operation — that feels like boilerplate, so the model skips it or defers it to "add later."

**Missing route-level auth (VCS-005) — HIGH**

Found routes with no authentication check in 5 of 20 repos. One FastAPI backend had zero auth on every endpoint — the `Depends(get_current_user)` pattern was imported but never applied to any route handler.

Why AI does this: it generates the happy path. A route that returns data works without auth, so the tests pass. Security middleware is added as a second thought, if at all.

**Committed secrets (VCS-010) — CRITICAL**

Found a Django secret key and a Supabase service role JWT committed in plain text to public repos. In one case, a template repo had `SUPABASE_KEY=eyJ...` in the committed `.env` file — the kind of project thousands of people fork as a starting point.

Why AI does this: when scaffolding a new project, the model fills in `.env` with working values to make the demo run. It rarely adds the file to `.gitignore` at the same time.

**Hallucinated packages (VCS-006) — CRITICAL**

Found 3 packages referenced in `package.json` that return 404 from the npm registry. All three used a `@org/internal-*` scoping pattern — the model invented an internal package that doesn't exist publicly.

Why AI does this: models are trained on code that references internal packages. When generating a new project, they sometimes hallucinate the same pattern. An attacker can register the invented name and have it silently installed by every `npm install`.

---

### Why these specific mistakes?

AI tools optimize for the demo. A route that returns data, a table that stores rows, a `.env` that makes the app start — these all work without security. The model learned from codebases where security was added iteratively, so it reproduces that pattern: ship first, secure later. Except "later" often means "never."

The riskiest pattern I found: Lovable-generated apps often have Supabase RLS missing on the first deployment. Supabase's anon key is public by design — the assumption is that RLS is the security layer. Without it, the first user who signs up can read every other user's data.

---

### What Vibescan checks

- VCS-001: Supabase tables without RLS
- VCS-002: Firebase open read/write rules
- VCS-003: Weak or hardcoded JWT secrets
- VCS-004: S3 buckets without public access block
- VCS-005: Route handlers with no server-side auth (Express + FastAPI/Flask)
- VCS-006: Hallucinated or suspicious npm/PyPI packages
- VCS-010: Private keys and secrets committed to the repo
- VCS-011: Secrets exposed via `VITE_*` / `NEXT_PUBLIC_*` env variables

It also scores each finding by AI-origin confidence, using git `Co-authored-by` metadata and code pattern heuristics.

---

### Install

```bash
pip install vibescan
vibescan scan .
```

GitHub: https://github.com/[your-handle]/vibescan

Happy to answer questions about any of the findings or the rule implementation.

---

## Notes for posting

- Post on a weekday morning (9–10am ET) for best traction
- r/netsec crosspost with different framing: "Static analysis rules for AI-generated code security anti-patterns"
- r/webdev angle: "If you're using Lovable/Bolt/Cursor, run this before you deploy"
- The specific findings (Django key, Supabase JWT in template repo) are the most shareable — consider a companion tweet thread with screenshots
- Don't name the specific repos in the HN post — anonymize them. People get defensive.
- The "45% hit rate" stat is the headline number. Lead with it.

## Reddit post (r/webdev / r/SideProject)

**Title:** Built a security scanner specifically for AI-generated code — scanned 20 Lovable/Cursor/Claude repos, 45% had real security issues

I kept seeing the same mistakes in every vibe-coded project I reviewed — no Supabase RLS, no auth on half the routes, secrets in `.env` files that got committed. So I wrote a scanner for them.

Vibescan is a CLI tool (pip install vibescan) that checks for these patterns specifically. Scanned 20 public repos built with various AI tools:

- 2 had payment/user tables with no RLS (anyone logged in could read all data)
- 5 had API routes with zero authentication
- 2 had real secrets committed to public repos (one was a template repo with 500 forks)
- 3 had packages referenced in package.json that don't exist on npm (hallucinated names an attacker could register)

The tool is open source. Would love feedback on which rules matter most and what I'm missing.

[GitHub link]
