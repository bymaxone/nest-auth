# @bymax-one/nest-auth — AI Agent Quick Reference

> **Type:** npm public library (NOT an application)
> **Package:** `@bymax-one/nest-auth` — full-stack auth for NestJS 11, React 19, Next.js 16
> **Runtime:** Node.js 24+ | All crypto via `node:crypto` — zero direct dependencies (functionality via peer deps)

---

## Critical Rules

**1. npm Library — Not an App** (uses pnpm)

- Zero direct dependencies (`"dependencies": {}`). Everything is `peerDependency` or `node:` builtin.
- Define interfaces (`IUserRepository`, `IEmailProvider`) — never import concrete implementations.
- Export public API from `src/{subpath}/index.ts`. Use `export type` for interfaces/types, `export` for classes/constants/guards.

**2. English Only**

- All code, comments, JSDoc, variable names, and docs in English. JSDoc on every public export.
- `AUTH_ERROR_MESSAGES` in `src/server/errors/auth-error-codes.ts` are the end-user-facing default messages, written in **English** (like the rest of the project). Consumers can localize or override them via `BymaxAuthModule.forRoot({ messages: { ... } })` (planned i18n support) — do not hardcode a non-English locale as the default.

**3. TypeScript — Zero `any`**

- Never `any` in production code. Use `unknown`, generics, or explicit types.
- `interface` for contracts. `type` for unions/intersections. `I` prefix for repository interfaces only.
- `strict: true` — no exceptions.

**4. Security — Non-Negotiable**

- `node:crypto` only. Never bcrypt, argon2, otpauth, crypto-js, uuid, or nanoid.
- `crypto.timingSafeEqual` for all secret comparisons — never `===`.
- Never log tokens, secrets, passwords, or keys.
- HttpOnly + Secure + SameSite cookies by default.

**5. NestJS Patterns**

- No Passport. Guards validate JWT via `@nestjs/jwt` `JwtService.verify()`.
- Injection tokens: `Symbol()` — never strings. Controllers: thin (validate → delegate → return).
- Singletons only (no `Scope.REQUEST`). Unconfigured features are not registered.

**6. Code Style**

- Single quotes, no semicolons, 2-space indent. camelCase files, PascalCase classes.
- Import order: `node:` → external → internal → relative → types. One concern per file.

**7. Testing — TDD, 100% Coverage + 100% Mutation (hard gates)**

- Co-located tests (`*.spec.ts`). AAA pattern. Mock external deps — never real Redis/email in unit tests.
- **100% statements / branches / functions / lines** enforced by `jest.coverage.config.ts` (`pnpm test:cov:all`), per-subpath and global. Not a target — a pre-publish gate. Mutation testing (Stryker `break: 100`) is the deeper gate against weak tests, and the suite currently holds **100%**: no survivors, nothing uncovered. Keep it there — a new survivor is either a missing test or an equivalent that must carry its reason.

**8. Build** — tsup builds 5 subpaths → ESM (.mjs) + CJS (.cjs) + .d.ts. `sideEffects: false`. Peer deps always external.

---

## Subpaths

| Subpath      | Purpose                                       | Peer Deps                           |
| ------------ | --------------------------------------------- | ----------------------------------- |
| `.` (server) | NestJS module — guards, services, controllers | NestJS 11, ioredis, class-validator |
| `./shared`   | Types + constants                             | None                                |
| `./client`   | Fetch-based auth client                       | None                                |
| `./react`    | Hooks + AuthProvider                          | react ^19                           |
| `./nextjs`   | Proxy factory + route handlers                | next ^16, react ^19                 |

Graph: `shared` → `client` → `react` → `nextjs` (each depends on previous + shared). `server` is independent.

---

## Verification — Run Before Completing Any Task

```bash
pnpm typecheck && pnpm lint && pnpm format:check && pnpm test && pnpm build
```

`format:check` (`prettier --check .`) is a hard CI gate — the reusable pipeline runs it on
every PR and push to `main`. Run `pnpm format` to auto-fix. The pre-commit hook only formats
_staged_ files, so untouched files can still drift; this gate catches that.

### Mutation testing (before tagging a release)

Line coverage is 100%, but mutation testing is the real gate against weak tests.
Run under Node 24:

```bash
pnpm mutation             # incremental: reuses reports/stryker-incremental.json, minutes not an hour
pnpm mutation:full        # cold run — deletes that baseline first. The one that measures the truth.
pnpm mutation:dry-run     # fast sandbox/config smoke test (no mutants); use to verify config health
```

**Only a `mutation:full` verdict may be reported or acted on.** An incremental run — which is what
`pnpm mutation` and ANY `--mutate <file>` invocation do — reuses the recorded verdicts and prints a
score covering the whole project in seconds. Measured here: a scoped run over a **brand-new file**
answered `Final mutation score of 100.00` in 18 seconds having tested nothing in it, because
`--mutate` narrows what is RE-TESTED, not what is reported, and merges the baseline for the rest.
The three signals that separate a real run from a replayed one, in order of reliability:

1. `Instrumented N source file(s) with M mutant(s)` — a legitimate scoped run names a real count.
2. The file appears as a row in the final table. Absent means it was not measured.
3. Wall-clock. The cold run here is close to an hour; 18 seconds is not a measurement.

To measure one file without destroying the project baseline, point the run at a throwaway one:

```bash
npx stryker run --mutate 'src/path/file.ts' --incrementalFile /tmp/scratch/stryker-scoped.json
```

Stryker's own reuse rule, from `incremental-differ.js`, explains the second half of the trap: a
mutant is identified by file, mutator name, location and replacement; a killed mutant is reused
unless **its culprit test** changed, and a survivor is reused unless a test was **added**. So
rewriting an assertion inside an existing `it()` leaves the prior verdict standing. After touching
only spec files, an incremental run can hand back a stale verdict.

**The sandbox must not survive the run.** `cleanTempDir` is `"always"`, not `true`. `true` deletes
`.stryker-tmp` only after a run that PASSED — and a run that fails the 100 threshold is the normal
state while iterating, so it left a 45 MB copy of `src/` on disk after every failed run.
`jest.coverage.config.ts` names it in `modulePathIgnorePatterns` precisely because a second copy of
`src/` in the tree is hazardous; not having it there at all is cheaper than ignoring it correctly.

This does **not** explain the intermittent failure in the merged coverage run — that is still open,
and the honest summary is that it resisted three separate explanations.

The symptom is always transport-level: `socket hang up` on one request in a random e2e suite, or a
request that failed silently and starved a downstream assertion. It never reproduces under
`pnpm test:e2e` alone, only in the merged run.

What was ruled out: worker contention (`--maxWorkers=3` still failed), the 1 GB
`workerIdleMemoryLimit` (raising it to 4 GB still failed), unhandled rejections
(`--unhandled-rejections=warn` printed none), and the leftover sandbox — which looked convincing
at 4 failures in 11 runs with one present versus 0 in 5 with it removed, and then failed again
with no sandbox on disk.

The trap worth remembering is the shape of the data. Failures arrive in **bursts**: 2 in 3 runs,
then 8 consecutive clean. Any batch of 5 proves nothing, and a batch of 15 taken at one sitting —
which is how `main` was measured — is not comparable to a branch measured across a different hour.
Comparing batches from different times is how three wrong causes each looked established.

**Config invariants (Node 24 + pnpm — do not regress).** Both re-verified on Stryker **10.0.0**,
by breaking them rather than by reading the changelog.

Stryker loads `jest.stryker.config.ts` via native ESM `import()` in a child process, so relative
imports MUST carry an explicit extension (`import base from './jest.config.ts'`) — Node's ESM
resolver does not guess extensions and an extensionless specifier throws `ERR_MODULE_NOT_FOUND` in
the sandbox. Still true on v10: removing the extension fails the dry run with that exact error. A
sibling project could not reproduce this, and the difference is that their config is loaded through
ts-node, where extensionless resolves — so the constraint is Node's, and it applies to any repo
whose config Stryker imports natively.

The jest test environments (`jest-environment-node`, `jest-environment-jsdom`) MUST stay **direct
devDependencies**. The mechanism is not what an earlier version of this note said: the
`@stryker-mutator/jest-runner` env wrapper resolves them from the **project root**
(`require.resolve(name, { paths: [resolveFromDirectory] })`), and no Stryker major declares them
itself — so pnpm's strict layout finds them only when this project declares them. Both are needed
here; the four React specs under `src/react/__tests__/` run on jsdom.

After touching Stryker/Jest config or bumping either major, run `pnpm mutation:dry-run` to confirm
the sandbox still boots before the full run.

**What the v9 → v10 upgrade actually changed.** One breaking change (Node 20 dropped, 22+ required;
this project already requires 24). The config surface did not move — the shipped JSON schema
carries the same 53 options in both majors, `cleanTempDir: "always"` included. What moved is the
mutant population: v10 adds one mutator, `empty-expression-mutator`, which **reports itself as
`CallExpression`** — that is the name to grep for in a report. It deletes call expressions
(`f(x)` → `void 0`), expression statements (`f(x);` → `;`) and, the one that matters for this
library, `throw new SomeError(...)` in a guard clause. A test that asserts a rejection without
pinning which error will not kill that mutant. The population grew about 4% here
(`auth.service.ts`: 387 → 403 mutants).

**Do not raise `engines.node` to satisfy a devDependency.** Stryker v10 pulls Babel 8, and 145
`@babel/*` packages in the tree declare `engines.node: "^22.18.0 || >=24.11.0"`. That is a
contributor-side constraint and it is a warning, not an error (`engine-strict` is not enabled).
`engines.node` in `package.json` is a promise to CONSUMERS, who never install Stryker or Babel —
raising it to `>=24.11.0` would lock out consumers on Node 24.0–24.10 for a package they do not
receive.

Equivalent mutants are documented inline with `// Stryker disable next-line <Mutator>: <reason>`
— acceptable **only** for genuinely equivalent mutants (no test can kill them), each carrying a
reason. Minimize them, and **never** disable a mutant a test could kill.

**The per-line directive binds to the line immediately after it, which is not always the line you
mean.** Two shapes break it silently: a mutant sharing its line with a callback's closing brace
(`}, [])` on a `useCallback`/`useEffect`), and a directive whose comment wrapped onto a second
line — `next-line` then points at the comment's own continuation. In both cases the mutant is
reported as surviving and the disable looks broken rather than misplaced. Use the block form
(`// Stryker disable <Mutator>` … `// Stryker restore <Mutator>`) there, keep the region short,
and say in the reason why the per-line form did not serve. (They ship in the
unminified `.mjs` as cosmetic noise — negligible in size. Documenting equivalents in
`docs/mutation_testing_results.md` instead is the alternative, but only fits when there are few;
nest-auth's legitimate equivalents make inline the pragmatic choice — moving them to docs would
drop the score below the 95 gate.) Full setup, config rationale, and the iteration workflow live in
[docs/mutation_testing_plan.md](./docs/mutation_testing_plan.md). Do **not** add
mutation testing to `prepublishOnly` or the per-PR CI — it runs automatically post-merge on `main` via the shared reusable (`bymaxone/.github` → node-lib-ci) and can also be run on demand (`pnpm mutation`).

---

## Guidelines — Load Only What You Need

> **Do NOT load all guidelines at once.** Each is 30-80KB. Read only 1-2 relevant to your current task.

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
| Crypto     | `docs/guidelines/NODE-CRYPTO-GUIDELINES.md`     | Crypto operations, security      |

For full architecture and patterns, see **[docs/repository-guide.md](./docs/repository-guide.md)**
(load on demand — not every session). **[AGENTS.md](./AGENTS.md)** is the Codex review contract, not
a manual: it carries only rules that change a finding, and `src/server/`-scoped ones live in
[src/server/AGENTS.md](./src/server/AGENTS.md).
