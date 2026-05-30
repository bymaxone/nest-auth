# Contributing to @bymax-one/nest-auth

Thank you for your interest in contributing! This document describes the workflow
and quality gates for this library. By participating, you agree to abide by our
[Code of Conduct](./CODE_OF_CONDUCT.md).

## Reporting security issues

**Do not open public issues for security vulnerabilities.** Follow the private
reporting process described in [SECURITY.md](./SECURITY.md).

## Prerequisites

- Node.js >= 24
- pnpm 10.8.1 (`corepack enable`)

## Getting started

```bash
pnpm install
pnpm build
```

## Development workflow

This is a published npm library, not an application. Keep `dependencies` empty —
everything ships as a `peerDependency` or a `node:` builtin (all crypto via
`node:crypto`, never a third-party package). Conventions live in
[CLAUDE.md](./CLAUDE.md) and [AGENTS.md](./AGENTS.md).

1. Create a branch from `main`.
2. Make your change; add or update co-located `*.spec.ts` tests (TDD — 100%
   coverage is a hard gate, not a target). Mock external deps (Redis, email).
3. Run the full verification suite before opening a PR.

## Verification — run before every PR

```bash
pnpm typecheck && pnpm lint && pnpm test:cov:all && pnpm build && pnpm size
```

All of the following must pass:

- **Typecheck** — `tsc --noEmit` (strict, zero errors)
- **Lint** — ESLint (zero `any`, import order, security rules)
- **Coverage** — 100% statements / branches / functions / lines
- **Build** — tsup produces ESM + CJS + `.d.ts` for every subpath
- **Size** — every subpath stays within the budget in `scripts/check-size.mjs`

Mutation testing (`pnpm mutation`) is a **release gate**, run manually before
tagging a version — never on every PR.

## Commits — Conventional Commits

Commit messages are validated by commitlint via the `commit-msg` hook:

```
<type>(<scope>): <subject>
```

Types: `feat | fix | docs | refactor | perf | test | build | ci | chore | revert`.
The `pre-commit` hook runs lint-staged (ESLint + Prettier on staged files).

## Pull requests

- Keep PRs focused and small.
- Record user-facing changes under the `Unreleased` section of `CHANGELOG.md`.
- All CI checks (`ci`, `codeql`, `scorecard`) must be green.

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](./LICENSE).
