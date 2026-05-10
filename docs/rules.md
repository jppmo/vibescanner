# Vibescan Rules Reference

Each section covers what the rule detects, how it verifies the issue, its known blind spots, and concrete improvements to consider once we have real-world scan data.

---

## VCS-001 — Supabase RLS not enabled

**Severity:** CRITICAL  
**Files:** `.sql`

### What it looks for

Every Supabase table exposed to the client must have Row Level Security enabled. Without it, any authenticated user can read or write every row in the table by calling `supabase.from('table').select('*')` directly from the browser.

The rule scans SQL migration files for every `CREATE TABLE` statement and checks that a matching `ALTER TABLE <name> ENABLE ROW LEVEL SECURITY` statement exists somewhere in the same file.

### How it verifies

1. Regex scan for `CREATE TABLE [IF NOT EXISTS] [schema.]name` → builds a set of table names.
2. Regex scan for `ALTER TABLE [ONLY] [schema.]name ENABLE ROW LEVEL SECURITY` → builds a set of protected names.
3. Any table in set 1 missing from set 2 gets a CRITICAL finding. The fix includes the exact `ALTER TABLE` and a baseline `CREATE POLICY` statement.

Schema prefixes (`public.users`) are stripped before comparison, so `CREATE TABLE public.users` matches `ALTER TABLE users ENABLE ROW LEVEL SECURITY`.

### Known blind spots

- **RLS enabled via dashboard, not SQL.** If a developer enabled RLS through the Supabase UI instead of a migration, there's nothing in the SQL files to scan.
- **Tables in separate migration files.** The check is per-file. If `CREATE TABLE` is in `001_init.sql` and `ENABLE ROW LEVEL SECURITY` is in `002_rls.sql`, VCS-001 will flag it even though the final state is correct.
- **RLS enabled but no policies.** Enabling RLS without any policy blocks all access by default. The rule doesn't check for policy existence — a table with RLS enabled but zero policies would pass the check.
- **Views and functions.** `SECURITY DEFINER` functions bypass RLS entirely. The rule doesn't scan for these.

### Future improvements

- [ ] **Cross-file analysis.** Aggregate all `.sql` files in a migration directory before checking. The final state matters, not the per-file state.
- [ ] **Policy presence check.** After confirming RLS is enabled, verify at least one `CREATE POLICY` statement exists for the table. Flag tables with RLS on but no policies as a separate finding (MEDIUM).
- [ ] **SECURITY DEFINER detector.** Add a sub-check that flags functions with `SECURITY DEFINER` that query tables, since these bypass RLS regardless of policy.
- [ ] **Supabase dashboard state.** Explore pulling the actual RLS state from the Supabase Management API during CI scans, so dashboard-only changes are visible.

---

## VCS-002 — Firebase open read/write rules

**Severity:** CRITICAL  
**Files:** `.rules` (Firestore), `.json` (Realtime Database)

### What it looks for

Firebase security rules default to denying all access — but AI-generated code routinely sets them to fully open during development and forgets to lock them down before shipping. Either `allow read, write: if true` (Firestore) or `".read": true` (Realtime Database) allows any visitor, authenticated or not, to read or write every record.

### How it verifies

**Firestore (`.rules` files):**
Regex per line: `allow [operations]: if true`. Case-insensitive. Flags the exact line, fix replaces `true` with `request.auth != null`.

**Realtime Database (`.json` files):**
Fast-exit if the file contains no `".read"` or `".write"` keys (avoids scanning unrelated JSON). Then regex per line: `".(read|write)": true` or `".(read|write)": "true"` (both boolean and string form are vulnerable).

### Known blind spots

- **Partial open rules.** A rule like `allow read: if true; allow write: if request.auth != null` correctly flags the read — but the fix suggestion says to add `request.auth != null` to both, which is misleading for write.
- **Nested Realtime Database rules.** The open rule might be scoped to a specific path (`/public`) rather than the root. Flagging it as CRITICAL may be too aggressive if the path is intentionally public.
- **Firestore rules with complex conditions.** `allow read: if true || someCondition` is flagged, but `allow read: if someCondition || true` would also be vulnerable and isn't caught.
- **Security rules in non-standard filenames.** Only `.rules` extension and `.json` files containing Firebase keys are scanned. Rules embedded in CI scripts or deployment configs are missed.

### Future improvements

- [ ] **Path-aware severity.** Downgrade from CRITICAL to HIGH when the open rule is scoped to a specific subcollection/path rather than the wildcard `/{document=**}`.
- [ ] **Condition analysis.** Parse the full `if` condition and flag any expression that trivially evaluates to true (e.g., `if true || x`, `if 1 == 1`).
- [ ] **Realtime Database path scoping.** Distinguish between `".read": true` at root (always CRITICAL) vs. inside a named path like `"public": { ".read": true }` (potentially acceptable, flag as MEDIUM).
- [ ] **`firebaseConfig` key detection.** If a scan finds an open-rule file alongside a `firebaseConfig` object with an `apiKey`, flag both together since the exposed key + open rules = immediate breach.

---

## VCS-003 — JWT secret hardcoded or weak

**Severity:** CRITICAL (hardcoded secret) / HIGH (missing expiry)  
**Files:** `.js`, `.ts`, `.tsx`

### What it looks for

Two distinct issues in `jsonwebtoken` (`jwt.sign()`) calls:

1. **Hardcoded secret (CRITICAL).** The second argument to `jwt.sign()` is a string literal. Any hardcoded string is wrong — it will be committed to version control and is often a known-bad value (`"secret"`, `"mysecret"`, `"1234567890"`) from tutorials or AI suggestions.
2. **Missing expiry (HIGH).** The options object (third argument) is missing an `expiresIn` key. Tokens that never expire remain valid indefinitely after a breach.

When both issues exist on the same call, a single CRITICAL finding is emitted with the fix covering both.

### How it verifies

Uses tree-sitter to walk the JavaScript AST and find `call_expression` nodes where:
- The function is a `member_expression` with property `sign`
- Pre-filter: file contains `jsonwebtoken` or `.sign(` (skips unrelated files early)

For each matching call:
- **Secret check:** second named argument is a `string` or `template_string` node with no interpolations → extract the literal value → flag CRITICAL
- **Entropy check:** computes Shannon entropy on the secret value. Values below 4.0 bits/char are noted as "low entropy" in the detail message. Known-bad values from a fixed list are called out explicitly.
- **Expiry check:** if the third argument is an `object` literal, checks its `pair` children for a key named `expiresIn`. If absent → flag HIGH. If the third argument is a variable reference, the check is skipped (can't inspect statically).

### Known blind spots

- **`jsonwebtoken` only.** The `jose` library (`new SignJWT(...).sign(secret)`) uses a chained builder pattern that the current AST walk doesn't detect. Same for `@auth/core`, `next-auth` internal token signing, and other JWT libraries.
- **Secret in a variable.** `const secret = 'mysecret'; jwt.sign(payload, secret)` — the hardcoded string is one step removed and won't be flagged. Data flow analysis would be needed.
- **Environment variable that's actually weak.** `jwt.sign(payload, process.env.JWT_SECRET)` passes the check even if `.env` contains `JWT_SECRET=secret`. The package validator (VCS-006) and a future `.env` checker would be needed to catch this.
- **TypeScript type assertions.** Some codebases use `jwt.sign(payload, secret as string)` — the cast node wraps the string node and the current visitor may miss it.

### Future improvements

- [ ] **`jose` library support.** Detect `new SignJWT(payload).sign(secret)` and `SignJWT` builder chains.
- [ ] **One-hop variable tracking.** If the secret argument is an `identifier`, look for its declaration in the same scope. If it's assigned a string literal, flag it.
- [ ] **`.env` correlation.** Cross-reference with a `.env` file scanner. If `JWT_SECRET=secret` is found in `.env`, emit a companion finding.
- [ ] **Algorithm weakness.** Flag `{ algorithm: 'none' }` or `{ algorithm: 'HS256' }` with a weak key as a separate MEDIUM finding (HS256 with a short secret is brute-forceable).
- [ ] **Asymmetric key detection.** Check if the secret starts with `-----BEGIN` — if so, it's a PEM key hardcoded as a multiline string, which is equally bad and should be flagged.

---

## VCS-004 — S3 bucket without public access block

**Severity:** CRITICAL  
**Files:** `.tf` (Terraform), `.ts`/`.tsx` (AWS CDK)

### What it looks for

S3 buckets created without a public access block are exposed to the internet by default. The four required settings are `block_public_acls`, `block_public_policy`, `ignore_public_acls`, and `restrict_public_buckets` — all must be `true`. A single `false` is enough to leave the bucket potentially readable or writable by anyone.

### How it verifies

**Terraform (`.tf` files):**
Uses a brace-depth parser (since there's no tree-sitter Terraform grammar) to extract all `resource` blocks. Builds two maps:
- `aws_s3_bucket` resources → name → line number
- `aws_s3_bucket_public_access_block` resources → parsed `bucket = aws_s3_bucket.NAME.id` reference → which bucket they protect

For each S3 bucket, checks if a matching access block exists with all four settings set to `true`. Missing block → CRITICAL. Block present but any setting not `true` → CRITICAL listing the specific missing settings.

**CDK TypeScript (`.ts`/`.tsx` files):**
Walks the tree-sitter AST for `new_expression` nodes where the constructor is a `member_expression` with property `Bucket`. Checks the props object (last `object` argument) for a `pair` with key `blockPublicAccess` whose value contains `BLOCK_ALL` anywhere in its text. Absent or partial block → CRITICAL.

### Known blind spots

- **Terraform module abstractions.** If the S3 bucket is created inside a reusable Terraform module, the `aws_s3_bucket_public_access_block` might be in a different file or defined by the module itself. The per-file check would flag the bucket even if the module handles it correctly.
- **Access block in a separate file.** Same as above — if `main.tf` defines the bucket and `security.tf` defines the access block, the bucket gets flagged.
- **CDK constructs wrapping `s3.Bucket`.** Internal company constructs like `new CompanyBucket(...)` that always set `BLOCK_ALL` internally won't be detected as safe because the constructor isn't named `Bucket`.
- **CDK `BlockPublicAccess` constructor with all-true settings.** `new s3.BlockPublicAccess({ blockPublicAcls: true, blockPublicPolicy: true, ignorePublicAcls: true, restrictPublicBuckets: true })` is safe but isn't `BLOCK_ALL` — the CDK check would flag it.
- **CloudFormation YAML/JSON.** Not covered at all. `AWS::S3::Bucket` resources in CloudFormation templates have their own `PublicAccessBlockConfiguration` property.

### Future improvements

- [ ] **Cross-file Terraform analysis.** Aggregate all `.tf` files in the same directory before checking bucket→access-block matching.
- [ ] **CDK `BlockPublicAccess` constructor analysis.** Parse the four individual boolean properties in `new s3.BlockPublicAccess({...})` instead of requiring the `BLOCK_ALL` shorthand.
- [ ] **CloudFormation support.** Add YAML/JSON detection for `AWS::S3::Bucket` resources missing `PublicAccessBlockConfiguration` or with any property set to `false`.
- [ ] **Pulumi support.** Detect `new aws.s3.BucketPublicAccessBlock(...)` in Pulumi TypeScript/Python.
- [ ] **Bucket purpose heuristic.** Public CDN/static-hosting buckets are intentionally public. If the bucket name or tags contain `static`, `cdn`, `assets`, `public`, downgrade severity to MEDIUM with a note.

---

## VCS-005 — Route handler missing server-side auth

**Severity:** HIGH  
**Files:** `.js`, `.ts`, `.tsx` (Express), `.py` (FastAPI, Flask)

### What it looks for

Route handlers that respond to any caller without checking who they are. The server will serve the request whether it comes from a logged-in user, an anonymous browser, or an attacker. This is the most common mistake in vibe-coded backends: the frontend redirects unauthenticated users to `/login`, but the API itself has no such guard.

### How it verifies

This is a heuristic, not a proof. It uses two signals per route.

**Express.js (JavaScript/TypeScript):**
Walks the AST for `call_expression` nodes on any HTTP method (`get`, `post`, `put`, `patch`, `delete`, `use`, `all`, `options`, `head`). For each:
1. First arg must be a string literal (the route path).
2. If the path contains a known public segment (`login`, `register`, `health`, `webhook`, `auth`, `callback`, `verify`, etc.) → skip.
3. If there are 3+ named arguments → a middleware function sits between path and handler → skip.
4. If the handler body text contains any auth signal (`req.user`, `req.auth`, `req.session`, `401`, `403`, `Unauthorized`, `jwt.verify`, `passport`, `authorization`) → skip.
5. Otherwise → flag HIGH.

**FastAPI / Flask (Python):**
Walks the AST for `decorated_definition` nodes. For each:
1. Finds the route decorator (`@app.get`, `@router.post`, `@bp.route`, etc.) and extracts the path.
2. Skips known public paths (same list as above).
3. Checks all decorators for `@login_required` or `@require_auth` → if present, skip.
4. Checks function parameters for `Depends(` or `current_user` → if present, skip.
5. Checks function body for Python auth signals (`current_user`, `HTTPException`, `401`, `403`) → if present, skip.
6. Otherwise → flag HIGH.

### Known blind spots

- **Global middleware in a different file.** `app.use(authenticate)` in `server.js` protects every route — but VCS-005 only sees the route file. This is the most common source of false positives.
- **Framework-level guards.** NestJS `@UseGuards()`, Fastify `preHandler`, Hono middleware, reverse proxies (nginx auth_request, Cloudflare Access) — none are visible to a file-level scan.
- **Intentionally public routes.** A public product listing, a blog post endpoint, or a search API doesn't need auth but would be flagged unless its path contains a public segment.
- **Auth in called functions.** If the handler calls `requireAuth(req)` as a helper instead of checking `req.user` directly, the text match won't catch it unless the function name is in the signal list.
- **Async middleware patterns.** `router.get('/path', asyncWrapper(authenticate), handler)` — the middleware is wrapped in a utility function and still registers as a 3-arg call, so it won't be flagged. But less conventional wrapping might not.

### Future improvements

- [ ] **Cross-file middleware detection.** If `app.use(...)` is found in a sibling file with the same router object, mark all routes on that router as protected. Requires tracking router identity across files.
- [ ] **Configurable signal list.** Let teams add custom auth signal strings via `.vibescan.yml` (e.g., their own `requireAdmin` or `checkSession` helper names).
- [ ] **Route-level suppression.** Add support for a `// vibescan-ignore VCS-005` comment on a route for intentionally public endpoints, so teams don't need to add fake auth signals just to silence the rule.
- [ ] **Severity based on HTTP method.** `GET` on a public-looking path is lower risk than `DELETE` or `POST` with no auth. Consider upgrading unprotected write routes to CRITICAL.
- [ ] **Data access heuristic.** If the handler body contains database access patterns (`db.`, `.query(`, `findOne`, `findAll`, `prisma.`, `orm.`) alongside no auth → upgrade confidence and severity. A pure in-memory or static response route is lower risk.
- [ ] **NestJS `@UseGuards()` support.** Detect the NestJS guard decorator pattern and treat it as auth-present.

---

## General improvements across all rules

- [ ] **False positive rate tracking.** Once scans are running on real repos, track suppression rates per rule. Any rule suppressed more than 20% of the time needs its detection logic tightened.
- [ ] **`.vibescan.yml` per-repo config.** Let repos disable specific rules or add path exclusions (e.g., `ignore_paths: ["legacy/"]`) without modifying the rule code.
- [ ] **Confidence score on findings.** Expose a `confidence` field (0.0–1.0) alongside severity. Heuristic rules like VCS-005 would emit lower confidence, letting teams filter accordingly.
- [ ] **Multi-file context.** Most blind spots above stem from single-file analysis. A second pass that builds a cross-file dependency graph (imports, router references, middleware registrations) would eliminate the largest class of false positives.
