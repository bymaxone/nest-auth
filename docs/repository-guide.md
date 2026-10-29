# Repository guide

Orientation for someone new to this codebase: what it is, how it is laid out, how it is built, and
what to run before finishing a task.

Deliberately NOT in `AGENTS.md`. That file is loaded into a Codex review on every turn before the
diff is read and is budgeted against `project_doc_max_bytes`; nothing here changes whether a
reviewer flags something, so in that file it would be paid for on every review and used on none.
Rules that DO change a review's outcome live in [AGENTS.md](../AGENTS.md), and rules true only
under `src/server/` live in [src/server/AGENTS.md](../src/server/AGENTS.md).

**Codex does not follow these links.** They are for a person, or for an agent that chooses to open
them. Nothing normative belongs here for that reason.

## Project overview

`@bymax-one/nest-auth` is a **public npm library** — not an application. It provides full-stack authentication for the Bymax SaaS ecosystem.

**Features:** Registration, login/logout, JWT access+refresh tokens, MFA (TOTP), sessions (FIFO eviction), password reset (token/OTP), email verification, OAuth (Google, plugin-extensible), platform admin auth, invitations, RBAC with hierarchy, brute-force protection, rate limiting, multi-tenant isolation.

**What it does NOT do:** No database connections (defines `IUserRepository`), no email sending (defines `IEmailProvider`), no Redis connections (accepts injected client), no UI components, no Passport.

---

## Architecture

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

## Build and publish

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

## Pre-task checklist

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

## Guidelines reference

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
