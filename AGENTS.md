# @bymax-one/nest-auth — Agent Specification

`@bymax-one/nest-auth` is a **published npm library**, not an application: full-stack authentication
for NestJS, React and Next.js, with zero direct dependencies and all crypto through `node:crypto`.
Everything merged here reaches consumers as a versioned package, so a breaking change is one they
read about in the changelog rather than one they discover.

> **Prerequisite:** Read [CLAUDE.md](./CLAUDE.md) first for critical rules. This file extends it with architecture and patterns — load on demand, not every session.

---

## Code Review Rules

<!-- shared:begin -->
<!--
  CANONICAL COPY: bymaxone/.github → agents/code-review-rules.md
  Do not edit this block in a consuming repository. It is replaced wholesale by
  the `agents-sync` reusable workflow, so a local edit is reverted on the next
  run. Change it here, cut a release, and every repository is offered the update.

  Repository-specific rules go OUTSIDE this block, below the closing marker.

  FOR WHOEVER EDITS THIS FILE, not for the reviewer who reads it:

  Codex reads one AGENTS.md per directory, root to nested, within
  project_doc_max_bytes (32 KiB default). Never name a template or fixture
  AGENTS.md below the root: a change under it is read as the repo's guidance.

  This block is charged against every consumer's budget. A rule added here must
  be worth the bytes in the smallest-headroom repository, not only in this one;
  agents-sync reports each consumer's headroom and fails when it is exceeded.

  When you scope a rule, scope every rule in its paragraph or split the
  paragraph -- an unscoped neighbour reads as deliberate.
-->

These rules hold in every Bymax repository. What is specific to this one is written after this
block, and the two are read together.

The pipeline already enforces formatting, linting, dependency policy, coverage and — where the
repository has one — the mutation gate. Do not spend a review on a **violation** of one of those: it
is a red check, not a comment. What follows is what CI cannot see.

A violation of a rule in this block is reported at **P1** at minimum. Codex surfaces only P0 and P1
on a pull request, so a rule whose violations land at P2 is a rule nobody sees.

**When a rule moves from here into a check, it leaves here.** A red check is proportionate to a
correctness failure that is invisible without it, and disproportionate to style enforced at an
inconvenient moment. Never carry both: a rule stated here _and_ enforced by CI spends a reviewer's
attention on what a gate already reports.

**A change to the enforcing configuration is the opposite case, and it is in scope.** Every gate runs
the configuration from the branch under review — that branch's lint config, its coverage thresholds,
its mutation thresholds. So a pull request that deletes a rule, lowers a threshold or widens an
ignore glob turns the check **green**, because a gate reports on the rules it was handed. For those
diffs the review is the only independent check there is, and a weakened gate needs the same
justification a suppression does.

### A finding names what it read

Every factual claim in a review — about a library's API, about this repository's history, about what
a file contains — has to come from something read in the tree under review, and the finding should
say which. A claim assembled from recollection is likely to describe a previous version of whatever
it is about.

**Safe path**, by the kind of claim:

| Claim about                             | Read this                                                                      |
| --------------------------------------- | ------------------------------------------------------------------------------ |
| A library's API **shape**               | `node_modules/<pkg>/dist/**/*.d.ts` in this tree                               |
| A library's **runtime behaviour**       | that version's changelog entry, its documentation, or a test that exercises it |
| A commit's author or committer identity | out of scope: it is not text a change introduces                               |
| What a file contains                    | the file at the revision under review, not an earlier one                      |

The first two rows are separate on purpose, and the rule below says why: a field can stay optional
in the published type while becoming mandatory in behaviour. A `.d.ts` settles what a signature
accepts and nothing about what the implementation does with it, so a behavioural claim resting on
one is unfounded.

Weight the checking by what acting on the finding would cost. A comment that asks for a reworded
sentence is cheap to be wrong about; one that asks for history to be rewritten, a merge reverted, or
a release pulled is not — verify that class before raising it, and raise it at the severity the
evidence supports rather than the severity the consequence would deserve if true.

### A dependency upgrade migrates every call site, not only the ones that fail to compile

When an upgrade tightens a contract, the compiler catches only the call sites whose **shape**
changed. A field that stays optional in the published type while becoming mandatory in behaviour
compiles, passes the unit suite, and fails in production.

A `@bymax-one/*` version number carries **no compatibility information** while the libraries are
pre-stable: breaking changes ship in minor and patch releases by explicit policy, so `^` and `~`
protect against nothing. The migration note under **Apply to a derived backend** in the library's own
changelog is the compatibility contract.

**Safe path:** read **every** changelog entry from the version being replaced up to the proposed
one, not only the proposed one's, and check every call site they name — not only the ones the
compiler rejected. Upgrades routinely skip releases, and the entry that matters is often not the
last one: adopting `@bymax-one/nest-cache` 1.1.0 → 1.2.1 skipped 1.2.0, where a namespace-validation
security fix lives; 1.2.1's own entry is a field rename. Diff the `.d.ts` of the **previously adopted** version against
the **proposed** one — `npm pack` both, and name the two versions. Reaching for "the installed
declarations" is the trap: in a checkout of the branch under review the installed tree is already
the new version, so that diff compares a release with itself and shows nothing.

### Settled decisions are not review findings

Both are settled deliberately, and reopening either costs a round trip and changes nothing:

- **Do not propose a major version bump** for a breaking change in a `@bymax-one/*` library, and do
  not assert that this ecosystem follows strict SemVer. Until an API is declared stable, breaking
  changes ship in minor and patch releases; the migration note carries the compatibility information
  the number does not. If a document claims strict SemVer, the finding is that the claim is wrong —
  not that the version should be raised.
- **Do not propose pinning `bymaxone/.github` reusable workflows to a commit SHA.** They are
  referenced by the `@v1` alias on purpose: a fix has to land once and reach every repository, the
  tag is immutable and the alias moves only on a release, and pinning was measured to cost ~58
  dependency pull requests to propagate one change. Third-party actions are the opposite case and
  **are** pinned by SHA.

**Safe path:** if you believe a settled decision is now wrong, say so as a question in the pull
request rather than as a finding.

### Suppressions are refusals, not exceptions

`@ts-ignore`, `@ts-expect-error`, `@ts-nocheck`, `eslint-disable` in any form,
`as unknown as` laundering a real type error, `istanbul ignore`, and in Rust `#[allow(...)]` over a
lint gate or `unsafe` without a `// SAFETY:` comment are blocking findings.

Anything a configured gate already reports belongs to the gate, not to a review: where a repository
lints `no-explicit-any` as an error — most do — an `as any` is a red check, and raising it here only
duplicates it. Check the repository's lint configuration before reporting a suppression rather than
assuming the list is exhaustive in either direction.

A failing gate means the code is wrong, the type is wrong, or the rule is wrong. **Safe path:** fix
whichever it is. Changing a rule's configuration with a stated reason is legitimate; scattering
per-call-site silencers is not.

### Comments state constraints, never history

A comment must read as true for whoever opens the file next. Flag any comment that narrates what a
previous version did, names a phase, task, ticket or review round, or explains a change rather than
the code. **Safe path:** state the constraint that still holds, and let `git log` carry the history.

Evidence for a constraint is not history, and how the evidence was obtained does not decide which it
is. The test is whether the fact still binds the next reader. A measurement that predicts what they
will hit if they take the other path — what the alternative did when it was tried, what the cost is
in numbers — belongs beside the constraint it supports, whether it came from a deliberate trial or
from something breaking. What ages is the part that cannot recur for them: what a previous version
of this code did, a version number, a registry state, a review round, a failure that has since been
fixed. Flag those; keep the measurement.

### Size and layering

Functions over **50 lines** and nesting deeper than four levels are findings **for what a change
introduces** — a new function, or a change that pushes an existing one past the limit — in the
repository's own source and test directories. A test-suite grouping construct (`describe`, `context`,
`mod tests`, a table of cases) is not a function; the unit under the limit is the body of a single
`it`/`test`/`#[test]`. On the same terms, every non-trivial source file a change introduces opens
with a header stating its purpose and its layer, and every exported symbol a change introduces
carries a doc comment.

**The 800-line file limit applies to what a change introduces, not to what it inherits.** A
repository that already carries a file past the line — a generator, a long end-to-end suite — would
otherwise produce a finding on every pull request touching three lines of it, which the author
cannot act on and did not cause. Raise it for a **new** file over the limit, or when a change pushes
a file past it or materially grows one already over.

Markdown, generated output and lockfiles are **out of scope**: a changelog is an append-only log that
only grows, a lockfile is generated, and neither has layers. Reporting their length is a false
positive on every dependency bump and every release note.

**Safe path:** extract by responsibility rather than by line count — the limit is a symptom, and one
file doing two jobs is the defect.

### Language and attribution

Everything published is English — source, comments, tests, commit messages, pull request titles and
bodies, `README.md`, `CHANGELOG.md` and everything under `.github/`.

Each repository states its language policy for `docs/` below this block. Report a language finding in
`docs/` only against what the repository states; where it states nothing, `docs/` is English like
everything else. A `docs/` language other than English is a repository-owner decision recorded in the
narrowings, not a convention a contributor may introduce.

No commit, pull request, comment or code may attribute authorship to an AI assistant or coding tool,
in any form. **Only text the change introduces is in scope** — a trailer, a "generated with" line, a
signature in a comment or a description.

A commit's author and committer fields are not that: they come from the contributor's git
configuration rather than from the diff, and a review reading the diff cannot see them. Never report
an identity field, and never present a command's reconstructed output as evidence for one. Measured:
eight P1 findings in a single day across four pull requests, each naming a commit SHA that does not
exist in the repository it was reported against and quoting `git log` output no review had run. What
each one asked for was a force-push rewriting published history.

<!-- shared:end -->

## Where this repository narrows a shared rule

<!--
  BYTE BUDGET. Codex reads this file per directory, root to changed file, and stops at
  `project_doc_max_bytes` — 32768 by default — counting the root file and any nested
  `AGENTS.md` together. Past that it truncates silently: no error, no warning, and the tail
  of this file simply stops being guidance.

  The shared block above is centrally managed and grows when the org adds a rule, so the
  headroom is not yours alone to spend. Check `wc -c AGENTS.md` before adding a section, and
  prefer `docs/guidelines/` for anything a reviewer does not need in the diff.

  Never create a file named `AGENTS.md` anywhere below the root — a fixture or template under
  that name becomes real guidance for every change in its directory, and spends the same cap.
-->

Only the rules a reviewer of **this** repository gets wrong. Each one has cost something real here.

### A bare user id is a defect, not a simplification

`IUserRepository.findById` takes a tenant because **user ids are unique only within a tenant** — a
host that numbers users per tenant gives every tenant a user `1`. So any Redis key, index, cache,
counter or fan-out keyed on a bare id lets one tenant's action reach another's account. That is a
credential-free cross-tenant revocation, and removing it from the session index and the token epoch
is what 1.4.4 was.

The wrong version reads as the tidier one: a reviewer sees a composite key or a length-prefixed
subject and suggests collapsing it. Do not. The same rule holds outside the keyspace — a disconnect
that matches sockets by `userId` alone drops another tenant's user, and repeated logouts in one
tenant become a denial of service against another.

The dashboard and platform planes need separating for the same reason: their ids come from
different repositories and may collide.

### The OpenAPI security-scheme NAMES are stable; their definitions are not

`AUTH_SECURITY_SCHEMES` exports four names — `bymaxAuthAccessCookie`, `bymaxAuthAccessBearer`,
`bymaxAuthRefreshCookie`, `bymaxPlatformAccessBearer`. Renaming one is a break a generated client
feels, so treat a rename suggestion as a breaking change and not a tidy-up.

Their **definitions** are derived from resolved options and the registered controllers, which is why
the names are exported and the definitions are not. A scheme the options cannot satisfy is neither
defined nor referenced. Do not suggest hard-coding a definition or exporting one.

### `environment` is the only input that answers "is this production"

The library reads **no environment variable at runtime** — every `process.env` occurrence in `src/`
is inside a JSDoc example. Configuration arrives through `registerAsync`, and
`BymaxAuthModuleOptions.environment` is the single input deciding cookie `Secure`, OAuth redirect
enforcement and the production-gated validations. **An unset value resolves to `'production'`**,
which is deliberate: it fails safe rather than open.

So an absent `process.env['NODE_ENV']` read is the design, not a missing check. It replaced exactly
that test, which failed open on `NODE_ENV` unset, `staging`, `prod`, or `production ` with a
trailing space.

### `conformance/` does not ship

`files` is `dist`, `LICENSE`, `README.md`, `CHANGELOG.md`. The shared wire contract and the
generated OpenAPI artifacts live in `conformance/` and reach consumers through GitHub, never through
`node_modules`. A path that resolves from the repository and not from the published package is
correct; do not "fix" it.

### Only a `mutation:full` verdict may be reported

`stryker.config.json` sets `incremental: true`, so `pnpm mutation` and **any** `--mutate <file>` run
reuse recorded verdicts and print a whole-project score in seconds. Measured here: a scoped run over
a brand-new file answered `Final mutation score of 100.00` in 18 seconds having tested nothing in it.

A score in a pull-request description is therefore not evidence. What distinguishes a real run, in
order of reliability: an `Instrumented N source file(s) with M mutant(s)` line naming a real count,
the file appearing as a row in the final table, and wall-clock — the cold run here is about two
hours. Treat a reported score with none of those as unmeasured.

### Equivalent mutants carry their reason inline

`// Stryker disable next-line <Mutator>: <reason>` is acceptable **only** for a mutant no test can
kill, and never for one a test could. The per-line form binds to the line immediately after it,
which is not always the line intended — a mutant sharing its line with a callback's closing brace,
or a directive whose comment wrapped, both bind wrong and report as surviving. Use the block form
there and say why in the reason.

---

## Table of Contents

- [Code Review Rules](#code-review-rules) — shared across every Bymax repository
- [Where this repository narrows a shared rule](#where-this-repository-narrows-a-shared-rule)

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Backend Patterns](#3-backend-patterns)
4. [Frontend Patterns](#4-frontend-patterns)
5. [Security Specification](#5-security-specification)
6. [Testing Strategy](#6-testing-strategy)
7. [Build and Publish](#7-build-and-publish)
8. [Common Pitfalls](#8-common-pitfalls)
9. [Pre-Task Checklist](#9-pre-task-checklist)
10. [Guidelines Reference](#10-guidelines-reference)

---

## 1. Project Overview

`@bymax-one/nest-auth` is a **public npm library** — not an application. It provides full-stack authentication for the Bymax SaaS ecosystem.

**Features:** Registration, login/logout, JWT access+refresh tokens, MFA (TOTP), sessions (FIFO eviction), password reset (token/OTP), email verification, OAuth (Google, plugin-extensible), platform admin auth, invitations, RBAC with hierarchy, brute-force protection, rate limiting, multi-tenant isolation.

**What it does NOT do:** No database connections (defines `IUserRepository`), no email sending (defines `IEmailProvider`), no Redis connections (accepts injected client), no UI components, no Passport.

---

## 2. Architecture

### Dynamic Module — runs inside the host app

```
Host App (SaaS)
├── BymaxAuthModule.registerAsync({ ... })
│   ├── Controllers ←→ Services ←→ Redis
│   ├── Guards ←→ Crypto (node:crypto)
│   └── Decorators ←→ Token Manager (@nestjs/jwt)
│
├── Injected by host:
│   ├── IUserRepository (e.g., Prisma)
│   ├── IEmailProvider (e.g., Resend)
│   ├── Redis client (ioredis)
│   └── IAuthHooks (custom lifecycle)
```

### Initialization

1. `BymaxAuthModule.registerAsync()` → resolve options (shallow merge with defaults)
2. Validate injected providers → register controllers conditionally → ready

### Request Flow

```
Request → JwtAuthGuard → UserStatusGuard → RolesGuard → MfaRequiredGuard → Controller → Service
```

---

## 3. Backend Patterns

### Injection Tokens (7 Symbols)

| Token                                 | Type                      | Required                                                                                  |
| ------------------------------------- | ------------------------- | ----------------------------------------------------------------------------------------- |
| `BYMAX_AUTH_OPTIONS`                  | `ResolvedOptions`         | Always                                                                                    |
| `BYMAX_AUTH_USER_REPOSITORY`          | `IUserRepository`         | Always                                                                                    |
| `BYMAX_AUTH_PLATFORM_USER_REPOSITORY` | `IPlatformUserRepository` | If `platformAdmin.enabled`                                                                |
| `BYMAX_AUTH_EMAIL_PROVIDER`           | `IEmailProvider`          | Always (NoOp default)                                                                     |
| `BYMAX_AUTH_HOOKS`                    | `IAuthHooks`              | Always (NoOp default)                                                                     |
| `BYMAX_AUTH_REDIS_CLIENT`             | `Redis`                   | Always                                                                                    |
| `BYMAX_AUTH_BREACH_CHECKER`           | `IPasswordBreachChecker`  | Always (`AllowAllBreachChecker` default — the check reaches the network, so it is opt-in) |

### Service Method Structure

```typescript
async login(dto: LoginDto, req: Request, res: Response): Promise<AuthResult | MfaChallengeResult> {
  // 1. Validate — find user, check status, check brute-force
  // 2. Execute — verify password, check MFA requirement
  // 3. Generate — tokens, session
  // 4. Deliver — set cookies or return in body
  // 5. Hook — call afterLogin
  // 6. Return
}
```

### Controller Pattern — Thin, delegate everything

```typescript
@Post('login')
@Throttle(AUTH_THROTTLE_CONFIGS.login)
@HttpCode(HttpStatus.OK)
async login(
  @Body() dto: LoginDto,
  @Req() req: Request,
  @Res({ passthrough: true }) res: Response,
): Promise<AuthResult | MfaChallengeResult> {
  return this.authService.login(dto, req, res);
}
```

### Error Response Format

```json
{ "error": { "code": "INVALID_CREDENTIALS", "message": "...", "details": {} } }
```

All codes from `AUTH_ERROR_CODES` (33 codes). Throw `AuthException(code, statusCode?, details?)`.

### Redis Key Patterns

Format: `{namespace}:{prefix}:{identifier}`

| Prefix | Purpose                                                   | TTL                         |
| ------ | --------------------------------------------------------- | --------------------------- |
| `rt`   | Refresh token hash                                        | `refreshExpiresInDays`      |
| `rp`   | Rotation grace pointer (old hash → new session)           | `refreshGraceWindow`        |
| `cf`   | Consumed-token family marker (proves a replay is a reuse) | Refresh TTL                 |
| `fam`  | Family index — the live hashes of one login's lineage     | Refresh TTL                 |
| `ep`   | Per-user token epoch (bulk access-token revocation)       | 30 days                     |
| `rv`   | Revoked JWT (blacklist)                                   | Remaining token lifetime    |
| `lf`   | Login failures                                            | `bruteForce.windowSeconds`  |
| `rl`   | Per-IP rate-limit counter, keyed by `HMAC(ip)`            | The route's window          |
| `otp`  | OTP codes                                                 | `otpTtlSeconds`             |
| `sess` | Session set per user                                      | Session lifetime            |
| `sd`   | Session detail                                            | Session lifetime            |
| `us`   | Cached account status (`us:{tenantId}:{userId}`)          | `userStatusCacheTtlSeconds` |
| `uev`  | Cached email-verified flag (same scoping)                 | `userStatusCacheTtlSeconds` |

**Do not build these keys from the format, in library code or consumer code.** `us` and `uev` are
derived in exactly one place — a module-private helper in `account-status.service.ts`, deliberately
not exported — and dropped through `AccountStatusService.invalidate` — a second statement of a key format drifts out of agreement
silently, because a delete that stops matching raises nothing and merely defers the change by a
TTL. The same applies to a consumer: the prefix is readable, the format is not a contract, and the
supported way to name one of these entries is the method.

`us` and `uev` have no platform counterpart: the platform status check is uncached, because there
is no tenant to scope a cache key by and the population is small enough that a read per call beats
a keyspace nothing invalidates. The other prefixes DO mirror onto the platform plane under their
own names (`prt`, `prp`, `pcf`, `pfam`, `pep`, …)
so a "sign out everywhere" on one plane can never reach the other. The full keyspace, including
which of these are a contract with `rust-auth`, is in
[`conformance/wire-contract.json`](./conformance/wire-contract.json).

---

## 4. Frontend Patterns

The four subpaths and what each exports are documented in the README's
[Frontend](./README.md) sections, and in depth in
[REACT-GUIDELINES](./docs/guidelines/REACT-GUIDELINES.md) and
[NEXTJS-GUIDELINES](./docs/guidelines/NEXTJS-GUIDELINES.md). Only the rules that
bite without warning are repeated here:

- **React** — hooks only; memoize the context value; `AbortController` on unmount.
- **Next.js 16** — `cookies()` is async, `params`/`searchParams` are Promises, and the proxy
  runs on the **Node.js runtime, not Edge**. `proxy.ts` is the file middleware was renamed to.
- **`./shared` and `./client`** carry zero dependencies, and must keep carrying zero.

---

## 5. Security Specification

### Cryptographic Operations

| Operation        | Algorithm                            | File                     |
| ---------------- | ------------------------------------ | ------------------------ |
| Password hashing | scrypt (N=2^15, r=8, p=1, keyLen=64) | `crypto/scrypt.ts`       |
| MFA encryption   | AES-256-GCM (12-byte IV)             | `crypto/aes-gcm.ts`      |
| TOTP             | HMAC-SHA1 (RFC 4226/6238)            | `crypto/totp.ts`         |
| Token generation | `crypto.randomBytes` → hex           | `crypto/secure-token.ts` |
| Token storage    | SHA-256 hash                         | `crypto/secure-token.ts` |
| OTP codes        | `crypto.randomInt` (max length 8)    | `crypto/secure-token.ts` |

### JWT Token Types

| Type             | Lifetime | Transport       | Key Claims                                    |
| ---------------- | -------- | --------------- | --------------------------------------------- |
| Dashboard access | 15min    | Cookie/Bearer   | jti, sub, tenantId, role, status, mfaVerified |
| Platform access  | 15min    | Cookie/Bearer   | jti, sub, role, mfaVerified                   |
| Refresh          | 7d       | HttpOnly cookie | Opaque UUID → SHA-256 in Redis                |
| MFA temp         | 5min     | Cookie/Bearer   | sub, context (dashboard\|platform)            |

### Key Validations at Startup

- JWT secret: >= 32 chars, Shannon entropy >= 3.5 bits/char, reject repetitive patterns
- MFA encryption key: must decode from base64 to exactly 32 bytes
- Roles hierarchy: must not be empty
- OTP length: must be <= 8 (randomInt MAX_SAFE_INTEGER limit)

---

## 6. Testing Strategy

**100% statements / branches / functions / lines, every layer, no exceptions** — enforced by
`jest.config.ts` and `jest.coverage.config.ts`, both of which fail below it. A pre-publish gate,
not a target.

**Mutation testing is the deeper gate** (Stryker `break: 100`, currently holding 100%). Only a
cold `pnpm mutation:full` verdict may be reported, for the reason given under the review rules
above; `pnpm mutation` and any `--mutate` run reuse recorded verdicts. Survivors are a missing
test or an equivalent mutant carrying its reason. Full methodology, config rationale and the
per-file workflow: [docs/mutation_testing_plan.md](./docs/mutation_testing_plan.md); results:
[docs/mutation_testing_results.md](./docs/mutation_testing_results.md).

**Mock external dependencies, never the module.** Redis, repositories, the email provider,
`JwtService` and `fetch` are `jest.fn()`; `node:crypto` is spied per function and never mocked
whole. Detail: [JEST-TESTING-GUIDELINES](./docs/guidelines/JEST-TESTING-GUIDELINES.md).

---

## 7. Build and Publish

tsup builds 5 entry points → `dist/{subpath}/index.{mjs,cjs,d.ts}`

```bash
pnpm clean        # rm -rf dist coverage
pnpm typecheck    # tsc --noEmit
pnpm test         # jest
pnpm build        # tsup
pnpm release      # npm publish --access public
```

Post-build checks: all 5 exports resolve, CJS + ESM work, .d.ts present, no bundled peer deps.

---

## 8. Common Pitfalls

### Security

| Pitfall                    | Fix                              |
| -------------------------- | -------------------------------- |
| `===` for token comparison | `crypto.timingSafeEqual`         |
| Logging tokens/secrets     | Log event type + user ID only    |
| JWT secret < 32 chars      | Validate at startup, reject weak |
| External crypto packages   | `node:crypto` only               |
| Raw refresh token storage  | Store SHA-256 hash               |

### Architecture

| Pitfall                                | Fix                             |
| -------------------------------------- | ------------------------------- |
| Importing Prisma/ORM directly          | Use `IUserRepository` interface |
| String injection tokens                | `Symbol()`                      |
| Registering disabled features          | Conditional registration        |
| `Scope.REQUEST`                        | Singleton (default)             |
| Cross-subpath imports (react → server) | Only import from `shared`       |

### TypeScript

| Pitfall                       | Fix                                   |
| ----------------------------- | ------------------------------------- |
| Using `any`                   | `unknown`, generics, explicit types   |
| Missing `export type`         | Separate `export type` for interfaces |
| Barrel re-exporting internals | Export only public API                |
| Default exports               | Named exports only                    |

### Testing

| Pitfall                        | Fix                          |
| ------------------------------ | ---------------------------- |
| Testing implementation details | Test behavior, not internals |
| Real Redis in unit tests       | Mock ioredis                 |
| Shared mutable state           | Fresh mocks in `beforeEach`  |

---

## 9. Pre-Task Checklist

**Before starting:**

- [ ] Read CLAUDE.md critical rules
- [ ] Identify 1-2 relevant guidelines → load only those
- [ ] Check `docs/development_tasks.md` for dependencies and status

**Before finishing:**

- [ ] `pnpm typecheck && pnpm lint && pnpm test && pnpm build` — all pass
- [ ] Barrel export updated if new public API added
- [ ] JSDoc on new public exports
- [ ] All text in English

---

## 10. Guidelines Reference

> Load **only** the 1-2 files relevant to your task. Never preload all.

| Domain     | File                                            | Load when...                     |
| ---------- | ----------------------------------------------- | -------------------------------- |
| NestJS     | `docs/guidelines/NESTJS-GUIDELINES.md`          | Modifying `src/server/`          |
| TypeScript | `docs/guidelines/TYPESCRIPT-GUIDELINES.md`      | Type design, barrel exports      |
| Testing    | `docs/guidelines/JEST-TESTING-GUIDELINES.md`    | Writing or fixing tests          |
| Redis      | `docs/guidelines/REDIS-IOREDIS-GUIDELINES.md`   | Redis ops, sessions, brute-force |
| JWT        | `docs/guidelines/JWT-AUTH-GUIDELINES.md`        | Token management, auth guards    |
| React      | `docs/guidelines/REACT-GUIDELINES.md`           | Working on `src/react/`          |
| Next.js    | `docs/guidelines/NEXTJS-GUIDELINES.md`          | Working on `src/nextjs/`         |
| Build      | `docs/guidelines/TSUP-BUILD-GUIDELINES.md`      | Build config, exports map        |
| DTOs       | `docs/guidelines/CLASS-VALIDATOR-GUIDELINES.md` | Creating/modifying DTOs          |
| Crypto     | `docs/guidelines/NODE-CRYPTO-GUIDELINES.md`     | Crypto operations                |
