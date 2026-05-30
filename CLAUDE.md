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

**7. Testing — TDD, 100% Coverage (hard gate)**

- Co-located tests (`*.spec.ts`). AAA pattern. Mock external deps — never real Redis/email in unit tests.
- **100% statements / branches / functions / lines** enforced by `jest.coverage.config.ts` (`pnpm test:cov:all`), per-subpath and global. Not a target — a pre-publish gate. Mutation testing (Stryker `break: 95`) is the deeper gate against weak tests.

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
pnpm typecheck && pnpm lint && pnpm test && pnpm build
```

### Mutation testing (before tagging a release)

Line coverage is 100%, but mutation testing is the real gate against weak tests.
Run under Node 24:

```bash
pnpm mutation             # full run (~10 min); writes reports/mutation/mutation.html
pnpm mutation:incremental # faster re-run using reports/stryker-incremental.json
```

Equivalent mutants are documented inline with `// Stryker disable next-line <Mutator>: <reason>`
— acceptable **only** for genuinely equivalent mutants (no test can kill them), each carrying a
reason. Minimize them, and **never** disable a mutant a test could kill. (They ship in the
unminified `.mjs` as cosmetic noise — negligible in size. Documenting equivalents in
`docs/mutation_testing_results.md` instead is the alternative, but only fits when there are few;
nest-auth's 184 legitimate equivalents make inline the pragmatic choice — moving them to docs would
drop the score below the 95 gate.) Full setup, config rationale, and the iteration workflow live in
[docs/mutation_testing_plan.md](./docs/mutation_testing_plan.md). Do **not** add
mutation testing to `prepublishOnly` or the per-PR CI — it is a manual/release gate.

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

For full architecture and patterns, see **[AGENTS.md](./AGENTS.md)** (load on demand — not every session).
