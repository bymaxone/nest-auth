# Mutation Testing Plan — @bymax-one/nest-auth

> **Type:** Technical execution plan for AI agents and contributors.
> **Goal:** Install and configure Stryker mutation testing, then iterate to reach the highest realistic mutation score (target ≥ 95%) before publishing v1 of this library to npm.
> **Status at time of writing (2026-05-19):** Line coverage is **100% in every metric** (statements, branches, functions, lines) across 1564 tests in 90 suites. Mutation testing is now the next quality gate.
>
> This document is the **single source of truth** for the task. Read it fully before executing — do not improvise.

---

## 0. TL;DR for an Executing Agent

1. Confirm baseline coverage is still 100% (`pnpm test:cov:all`). If not, **stop** and fix coverage first.
2. Install `@stryker-mutator/core`, `@stryker-mutator/jest-runner`, `@stryker-mutator/typescript-checker` as **devDependencies** (this is a library — these tools never leak to consumers).
3. Create `stryker.config.json` at the repo root with the configuration in **§5**.
4. Add the npm scripts and `.gitignore` entries in **§6**.
5. Run `pnpm mutation` (baseline run). Expect 15–25 min wall-clock.
6. Open `reports/mutation/mutation.html` and iterate per **§8** until mutation score ≥ 95% **or** the only remaining survived mutants are documented equivalent mutants.
7. Apply verification gates in **§9** after every phase. Never bypass them.
8. Update `CLAUDE.md`, `AGENTS.md`, and `docs/guidelines/JEST-TESTING-GUIDELINES.md` per **§10**.
9. Do **not** wire mutation testing into the per-PR CI workflow — see **§11** for the agreed strategy.

---

## 1. Why Mutation Testing for This Library

`@bymax-one/nest-auth` is a **public, security-critical** npm library. It handles:

- JWT issuance and verification
- TOTP / MFA secret encryption (`node:crypto`)
- Brute-force protection
- Password reset, OAuth (Google with PKCE), session management
- Cookie forwarding (Next.js proxy)
- Multi-tenant role-based authorization

100% line coverage proves every line **executes**, but it does **not** prove that tests would **fail** if the implementation regressed. Mutation testing introduces small, behaviour-changing edits (mutants) — flipped `<`/`<=`, removed `!`, replaced string literals — and checks whether the existing test suite **kills** them by failing.

For a security library, the cost of a silently-weakened test (e.g., a `timingSafeEqual` accidentally replaced by `===` in a future refactor with no test failure) is potentially severe. Mutation testing is the strongest cheap defence against that class of regression.

---

## 2. Pre-Flight: Baseline Verification

Before doing anything, **prove** the suite is in the state this plan assumes.

```bash
# 1) Suite is green and fast
pnpm test

# 2) Coverage is at 100% across all metrics (unit + e2e aggregated)
pnpm test:cov:all
```

**Expected output (must match — if not, STOP and fix first):**

- `Test Suites: 90 passed, 90 total` (or higher)
- `Tests: 1564 passed, 1564 total` (or higher)
- Coverage table: every file at `100 | 100 | 100 | 100`
- `jest.coverage.config.ts` thresholds (global 100/100/100/100) are met

If anything in this snapshot is below 100%, **do not start Stryker**. Fix the gap first (use `tester` skill, see `docs/guidelines/JEST-TESTING-GUIDELINES.md`). Mutation score with broken coverage produces misleading results.

---

## 3. Project Context an Executor Must Internalise

| Topic                | Reality                                                                                                            | Implication for Stryker                                                                                                                                                                                                                                        |
| -------------------- | ------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Package type         | Public npm lib, NOT an app                                                                                         | Stryker goes in `devDependencies` only. Never in `dependencies` / `peerDependencies`.                                                                                                                                                                          |
| Package manager      | `pnpm@11.20.0`                                                                                                     | Use `pnpm add -D`, set `"packageManager": "pnpm"` in stryker config.                                                                                                                                                                                           |
| Node version         | `>=24.0.0`                                                                                                         | Stryker 8.x supports Node 24 natively.                                                                                                                                                                                                                         |
| Module system        | `"type": "module"` (ESM)                                                                                           | Confirmed compatible with Stryker 8 + `@stryker-mutator/jest-runner`.                                                                                                                                                                                          |
| Test runner          | Jest 29 + ts-jest                                                                                                  | Use `@stryker-mutator/jest-runner` with `projectType: "custom"` pointing at `jest.config.ts`.                                                                                                                                                                  |
| TS strictness        | `strict + exactOptionalPropertyTypes + noUncheckedIndexedAccess + noImplicitOverride + noFallthroughCasesInSwitch` | `disableTypeChecks: "src/**/*.{ts,tsx}"` is **mandatory** — Stryker injects mutated code that intentionally violates types.                                                                                                                                    |
| Build system         | tsup, 5 entries (server/shared/client/react/nextjs)                                                                | Stryker only runs the **test** suite — `tsup` is irrelevant to mutation testing. Never call `tsup` from Stryker config.                                                                                                                                        |
| Subpath aliases      | `@bymax-one/nest-auth{,/shared,/client,/react,/nextjs}` mapped via Jest `moduleNameMapper`                         | Stryker copies the entire project to `.stryker-tmp` and re-runs Jest — aliases work because `jest.config.ts` carries them. **Do not** duplicate the mapping in `stryker.config.json`.                                                                          |
| Dependency injection | NestJS with `Symbol()`-based tokens (never strings)                                                                | `StringLiteral` mutator may mutate the symbol description (`Symbol("X")` → `Symbol("")`), which **does not break** behaviour because Symbols are referentially unique — these can be left alone or disabled with `// Stryker disable next-line StringLiteral`. |
| Validation           | `class-validator` decorators on DTOs (e.g., `@IsEmail()`, `@IsString()`)                                           | Decorator metadata is built at module load. With `ignoreStatic: true`, Stryker skips mutants that only execute at load time, avoiding noise on DTOs.                                                                                                           |
| Error messages       | `AUTH_ERROR_MESSAGES` in **Portuguese** (intentional product design — see `CLAUDE.md`)                             | String literal mutants on these messages are usually equivalent (no consumer tests message text). Document the exception.                                                                                                                                      |
| Cryptography         | `node:crypto` only — `timingSafeEqual`, `randomBytes`, `createHmac`                                                | These are the **most important** files to score well. `EqualityOperator` mutants (`===` → `!==`) and `BooleanLiteral` (`true` → `false`) must all be killed. If they survive, tests are weak.                                                                  |
| E2E tests            | Live under `test/e2e/`, executed by `jest.e2e.config.ts` (30 s timeout each)                                       | **Do not** include e2e in the Stryker run. Adding them multiplies runtime by ~5x with marginal score gain. The unit suite already drives 100% line coverage on its own.                                                                                        |
| CI workflows         | `ci.yml` and `release.yml` currently `manual-only` (recent commit `8844410`)                                       | Mutation testing will follow the same manual / release-only pattern. **Do not** add it as a blocking job on every PR.                                                                                                                                          |

---

## 4. Required Packages

Run **exactly once**, from repo root:

```bash
pnpm add -D \
  @stryker-mutator/core@^9 \
  @stryker-mutator/jest-runner@^9 \
  @stryker-mutator/typescript-checker@^9
```

> **Installed version:** `9.6.1` (current stable major; Node `>=20` engine, satisfied by our `>=24`). Stryker releases all three packages in lockstep with **exact** peer deps (`jest-runner`/`typescript-checker` require `@stryker-mutator/core` at the same patch), so always install/upgrade the three together.
>
> **Supply-chain guard note:** this machine's `~/.zshrc` wraps `pnpm add` / `npm install` with `_pkg_age_guard`, which blocks any package whose **latest** published version is < 7 days old. The guard is not loaded in non-interactive shells. Before installing, replicate its check (`npm view <pkg> time --json`) and confirm the version is ≥ 7 days old; all three Stryker packages were 39 days old at install time. Honour this guard — do not blindly bypass it.

**Why each one:**

- `@stryker-mutator/core` — engine. Required.
- `@stryker-mutator/jest-runner` — bridges Stryker ↔ Jest. Required because our test runner is Jest.
- `@stryker-mutator/typescript-checker` — type-checks each mutant **before** running the tests. Eliminates ~30% of mutants that would have failed compilation anyway, drastically reducing wall-clock time. With our strict TS settings (`exactOptionalPropertyTypes`, etc.) this is **strongly recommended**.

**Do not** install `@stryker-mutator/dashboard-reporter` yet — Stryker Dashboard requires a public API token, and we have not decided whether to publish results publicly. (See §11.)

---

## 5. Stryker Configuration

Create the file **`stryker.config.json`** at the repo root. Use exactly this content (annotated; remove comments before saving since JSON does not support them — leave the `$schema` line):

```jsonc
{
  "$schema": "./node_modules/@stryker-mutator/core/schema/stryker-schema.json",

  // --- Project ---
  "packageManager": "pnpm",

  // --- Test runner ---
  "testRunner": "jest",
  "coverageAnalysis": "perTest",
  "jest": {
    "projectType": "custom",
    "configFile": "jest.config.ts",
    "enableFindRelatedTests": true
  },

  // --- Type checker ---
  "checkers": ["typescript"],
  "tsconfigFile": "tsconfig.json",
  "typescriptChecker": {
    "prioritizePerformanceOverAccuracy": true
  },

  // Mandatory because Stryker injects code that intentionally fails strict TS.
  // Without this, ts-jest fails before tests even run.
  "disableTypeChecks": "src/**/*.{ts,tsx}",

  // IMPORTANT: keep this `false` for THIS codebase. With `coverageAnalysis:
  // "perTest"`, `ignoreStatic: true` causes mutants on module-level constant
  // initializers (e.g. the UUID v4 regex in assert-token-type.ts, route
  // constants, error-code strings) to FALSELY survive: the const is evaluated
  // once at import, before any test runs, so per-test mutant toggling never
  // takes effect. Empirically, assert-token-type.ts scored 59% with `true`
  // and 100% with `false`. The trade-off (static mutants run the full suite,
  // slightly slower) is acceptable on a modern multi-core machine.
  "ignoreStatic": false,

  // --- Mutation scope ---
  // Mirror `collectCoverageFrom` in jest.config.ts exactly. If those two
  // ever diverge, mutation results become incomparable with coverage.
  "mutate": [
    "src/**/*.ts",
    "src/**/*.tsx",
    "!src/**/*.spec.ts",
    "!src/**/*.spec.tsx",
    "!src/**/*.test.ts",
    "!src/**/__tests__/**",
    "!src/**/index.ts",
    "!src/**/*.d.ts"
  ],

  // --- Thresholds (mutation score, 0-100) ---
  //   high   — at or above this, the report shows green ("good")
  //   low    — between low and high, report shows orange ("warning")
  //   break  — below this, `stryker run` exits non-zero (CI fails)
  //
  // Starting values: break=80 to allow first run to land without
  // failing. After Phase 4 we raise break to 90.
  "thresholds": {
    "high": 95,
    "low": 85,
    "break": 80
  },

  // --- Performance ---
  // 4 workers is conservative on an 8-core dev machine. Each worker
  // boots a full Jest + NestJS module compiler, which is RAM-heavy.
  // Raise to 6-8 only if `free -h` (Linux) / Activity Monitor (macOS)
  // shows headroom.
  "concurrency": 4,

  // NestJS module compilation in `beforeEach` is slow on cold start.
  // 5 s (Stryker default) produces false-positive Timeouts. 30 s is safe.
  "timeoutMS": 30000,

  // --- Incremental mode ---
  // Off for the baseline run (Phase 3) so that the report is complete.
  // After the first run, switch to true via `pnpm mutation:incremental`.
  "incremental": false,
  "incrementalFile": "reports/stryker-incremental.json",

  // --- Reporters ---
  // `html` is the one to read interactively (open in a browser).
  // `clear-text` prints the per-file score table to stdout.
  // `progress` shows a live counter (essential for long runs).
  // Dashboard reporter intentionally omitted — see docs §11.
  "reporters": ["progress", "clear-text", "html"],
  "htmlReporter": {
    "fileName": "reports/mutation/mutation.html"
  },

  // --- Sandbox ---
  "tempDirName": ".stryker-tmp",
  "cleanTempDir": true
}
```

> ⚠️ **JSON does not support comments.** When saving the file, strip every `//` comment line. The annotated version above is for the agent's reference only. The actual file should be valid JSON.

### 5.1 Why we did not set certain options

| Option                      | Value            | Reason for not setting                                                                                           |
| --------------------------- | ---------------- | ---------------------------------------------------------------------------------------------------------------- |
| `ignorePatterns`            | (default)        | `mutate` already restricts scope. Stryker's default ignores `node_modules`, `dist`, etc., which is correct here. |
| `mutator.excludedMutations` | (none initially) | We want to see the full picture in the baseline. Excluded only in Phase 4 with documented reasons.               |
| `dryRunOnly`                | `false`          | We want real results, not just dry runs.                                                                         |
| `dashboard.*`               | (omitted)        | Requires deciding on public sharing — see §11.                                                                   |
| `dryRunTimeoutMinutes`      | (default 5)      | Baseline measurement; if dry run exceeds 5 min we have a deeper problem to debug.                                |

### 5.2 Setup corrections discovered during execution (REQUIRED)

The original plan assumed defaults that did not hold for this ESM + pnpm + ts-jest project. The working configuration includes these additions — do not remove them:

1. **`"plugins": ["@stryker-mutator/jest-runner", "@stryker-mutator/typescript-checker"]`** — pnpm's symlinked `node_modules` defeats Stryker's default plugin auto-discovery glob (`@stryker-mutator/*`). Without an explicit `plugins` array the run fails with `Cannot find Checker plugin "typescript"` and `Unknown stryker config option "jest"`. Declare plugins explicitly.

2. **Dedicated `jest.stryker.config.ts`** (referenced via `jest.configFile`) instead of the base `jest.config.ts`. `coverageAnalysis: "perTest"` requires Stryker's instrumented test environments. The Stryker config spreads the base config and overrides `testEnvironment` to `@stryker-mutator/jest-runner/jest-env/node`; the base config stays on plain `'node'` so `pnpm test` never depends on the mutation toolchain.

3. **The four React specs' `@jest-environment jsdom` docblocks** were changed to `@jest-environment @stryker-mutator/jest-runner/jest-env/jsdom`. The wrapper is transparent when Stryker is not running (verified: the 40 React tests still pass under plain `pnpm test`). Without this, those specs report no coverage to Stryker and the dry-run aborts.

4. **Node 24 is required at run time.** The project's `engines.node` is `>=24`, and the dev machine's default shell may sit on an older nvm version. Run Stryker under Node 24 (e.g. prepend `$HOME/.nvm/versions/node/v24.x.x/bin` to `PATH`, or `nvm use 24`). Stryker core itself only needs `>=20`, but matching the project runtime avoids surprises.

5. **Supply-chain guard:** `pnpm add` is wrapped by `_pkg_age_guard` in `~/.zshrc` (blocks packages whose latest version is < 7 days old). It is not loaded in non-interactive shells. Verify package age manually (`npm view <pkg> time --json`) before installing; all three Stryker packages were 39 days old at install.

### 5.3 Fast iteration with scoped runs

For per-file verification during §8, scope the run to production files only and bump concurrency:

```bash
export PATH="$HOME/.nvm/versions/node/v24.14.1/bin:$PATH"   # Node 24
./node_modules/.bin/stryker run --mutate "src/path/to/file.ts" --concurrency 10 --reporters clear-text
```

⚠️ A CLI `--mutate` glob **overrides** the config's `mutate` (including the `!**/*.spec.ts` exclusions). Never pass a broad glob like `src/server/guards/**/*.ts` — it will also mutate the `*.spec.ts` files and pollute the score with meaningless test-code mutants. List specific production files, or append `"!src/**/*.spec.ts" "!src/**/*.spec.tsx"` to the `--mutate` arguments.

---

## 6. File and Script Changes

### 6.1 `package.json` — add scripts

Add the following three keys inside `"scripts"` **after the existing test scripts** (preserve order — never reformat the file):

```jsonc
{
  "scripts": {
    // ... existing scripts unchanged ...
    "mutation": "stryker run",
    "mutation:incremental": "stryker run --incremental",
    "mutation:dry-run": "stryker run --dryRunOnly"
  }
}
```

`mutation:dry-run` is a fast sanity check (~30 s) that proves Stryker can boot, copy the sandbox, and run the test suite once **without** introducing any mutant. Use it to debug ESM, alias, or NestJS DI issues before paying the cost of a real run.

### 6.2 `.gitignore` — add entries

Append a new section at the bottom of `.gitignore`:

```
# ============================================
# Mutation Testing (Stryker)
# ============================================
/.stryker-tmp/
/reports/
```

`.stryker-tmp/` holds the sandboxed project copy during a run (gigabytes possible). `reports/` holds the generated HTML and the incremental JSON cache — useful locally, never committed.

### 6.3 Optional — create `reports/.gitkeep`

**Do not create this file.** The whole `reports/` directory is gitignored. Stryker creates it on first run.

---

## 7. Baseline Run (Phase 3 Execution)

Once §5 and §6 are in place, execute:

```bash
# 1) Smoke test: prove Stryker can boot and run the suite once.
pnpm mutation:dry-run
```

**Expected:** Stryker prints a "Ran X tests in Y s" summary with no errors. If it fails:

- "Cannot find module '@bymax-one/nest-auth/...'" → `moduleNameMapper` is not being applied in the sandbox. Verify `jest.config.ts` is being picked up (`jest.configFile` in stryker.config.json).
- "SyntaxError: Cannot use import statement outside a module" → ESM/CJS confusion. Confirm `"type": "module"` is intact and ts-jest is on `^29.4.x` or newer.
- "TS2322" / "TS2345" type errors during run → `disableTypeChecks` glob is wrong; widen it.

**Only after dry-run succeeds, do the real run:**

```bash
pnpm mutation
```

**Expected wall-clock:** 15–25 minutes on an 8-core machine with `concurrency: 4`. Stryker prints a progress line: `Mutation testing 23% (mutants 240/1043) | ETA 12m`.

**Expected output artefacts:**

- `reports/mutation/mutation.html` — interactive report
- `reports/stryker-incremental.json` — diff cache for next run
- stdout: per-file mutation score table and overall percentage

**What "good" looks like for the baseline:**

- Overall mutation score **70 – 88%** is normal for a project with 100% line coverage. Anything below 60% means coverage is gaming line metrics; anything above 90% on the first try is suspicious.
- No tests should **time out** (if many do, raise `timeoutMS` to 60000 and re-run).
- No tests should **error** outside of expected mutant kills.

---

## 8. Iteration Workflow (Phase 4)

Open `reports/mutation/mutation.html` in a browser. Use the file tree on the left to drill into directories. **Filter by "Survived"** (and "Timeout" / "Runtime errors" if any). Each survived mutant is a TODO.

### 8.1 Decision tree per survived mutant

```
┌─ Open the file in the report.
│   Read the mutator name (e.g., "EqualityOperator", "StringLiteral",
│   "ConditionalExpression", "BooleanLiteral", "ArithmeticOperator",
│   "ArrayDeclaration", "ObjectLiteral").
│
├─ Could a real bug be introduced with this mutation?
│   (i.e., would a malicious or careless refactor that makes this exact
│    change cause incorrect behaviour visible to a consumer?)
│
│   ├── YES → It's a GAP. Add a test that kills it.
│   │
│   └── NO  → It's EQUIVALENT or ACCEPTABLE. Disable with a comment.
│
└─ See §8.2 / §8.3 / §8.4 below.
```

### 8.2 GAP — write a test that kills the mutant

Use the existing `tester` workflow (`docs/guidelines/JEST-TESTING-GUIDELINES.md`):

1. Locate the corresponding `*.spec.ts` file (co-located with the source).
2. Add **one** new `it(...)` that pins the behaviour the mutant would violate.
3. The test header comment must follow the standards in `bymax-workflow:standards` §4: scenario → expected → why → optional edge-case tag.
4. Run `pnpm test -- <file>.spec.ts` locally to confirm the new test passes against current code.
5. Run `pnpm mutation:incremental` to confirm the mutant is now killed.

**Example.** A `BooleanLiteral` mutant in `mfa.service.ts`:

```ts
// Source line:
if (user.mfaEnabled === true) {
  /* ... */
}
//                      ^^^^ mutant: replaces `true` with `false`
```

Add to `mfa.service.spec.ts`:

```ts
/**
 * Boundary: explicit `true` comparison.
 *
 * The MFA enabled flag uses strict-equality against `true`. If a regression
 * were to flip it to compare against `false`, the guard would invert and
 * users with MFA on would skip the challenge. Pins the comparison.
 */
it('rejects challenge when user.mfaEnabled is undefined', async () => {
  // Arrange
  const user = buildUser({ mfaEnabled: undefined })

  // Act
  const result = await service.challenge(user, 'totp')

  // Assert
  expect(result.isError()).toBe(true)
})
```

### 8.3 EQUIVALENT — mutant is semantically identical to the original

Common cases:

- `>` → `>=` where the boundary value cannot occur (guarded earlier in the function).
- `&&` → `||` in dead code paths.
- String literals in log messages that no test inspects.
- Symbol descriptions in DI tokens (`Symbol('AUTH_OPTIONS')` → `Symbol("")`).

**Action:** add an inline disable directly above the line, with a one-sentence reason in English:

```ts
// Stryker disable next-line StringLiteral: DI token description — Symbols
// are referentially unique, mutation does not alter behaviour.
export const BYMAX_AUTH_OPTIONS = Symbol('BYMAX_AUTH_OPTIONS')
```

For a whole block (e.g., a Portuguese error-messages map):

```ts
// Stryker disable all: user-facing localised strings, not behaviour.
// Replaced via consumer-provided overrides; mutation of literals here
// is irrelevant to the lib's behaviour.
export const AUTH_ERROR_MESSAGES: Readonly<Record<AuthErrorCode, string>> = {
  // ... pt-BR strings ...
} as const
// Stryker restore all
```

> ⚠️ Every `// Stryker disable` MUST include a `: <reason>`. A disable without a reason is a code-review failure (see §9.3).

### 8.4 ACCEPTABLE — would be a real bug but covering it is genuinely impractical

Examples are rare. If you find one, prefer §8.2 (write the test) first. Only fall back to a disabled mutant when:

- The mutant lives in defensive code intentionally unreachable in production (e.g., a `default:` branch in an exhaustive `switch` on a TS literal-union type, plus a `assertNever(x)` call).
- Or the test would require simulating filesystem-/OS-level failures that the rest of the codebase deliberately does not mock.

Document the reasoning in the disable comment **and** add an issue to the tracker so future maintainers can re-evaluate.

### 8.5 Hot paths — review first

These directories are highest priority because of security impact. Survived mutants here are nearly always real gaps:

1. `src/server/crypto/` — AES-GCM, secure tokens, TOTP
2. `src/server/guards/` — all NestJS guards
3. `src/server/services/auth.service.ts`, `password.service.ts`, `brute-force.service.ts`, `mfa.service.ts`, `token-manager.service.ts`, `session.service.ts`
4. `src/server/oauth/` — Google OAuth + PKCE (recently changed, commit `3687836`)
5. `src/nextjs/internal/proxyHandlers.ts` — cookie forwarding (recently changed, commit `9e1393e`)
6. `src/client/createAuthFetch.ts`, `createLogoutHandler.ts` (recently changed, commit `9e1393e`)

Tackle these in this order. After each is at ≥ 95%, raise `thresholds.break` in `stryker.config.json` and re-run to lock in progress.

### 8.6 Cycle target

Repeat **§8.1 → §8.5** until either:

- (a) Overall mutation score ≥ 95% **and** every hot-path directory in §8.5 is ≥ 95%, **or**
- (b) Every remaining survived mutant is a documented equivalent in §8.3 / §8.4 with an inline reason.

Whichever comes first.

After hitting the target, **raise `thresholds.break` to 90** and commit `stryker.config.json` so the value is enforced for future contributors.

---

## 9. Verification Gates

The library already has a strict prepublish chain:

```
pnpm clean && pnpm typecheck && pnpm lint && pnpm test && pnpm build
```

Mutation testing **does not replace** any of those gates. It runs **before** them, manually, before a release tag.

### 9.1 After every phase

```bash
pnpm typecheck   # must pass
pnpm lint        # must pass — disable comments must not trip ESLint
pnpm test        # must pass — Jest is the authoritative gate
```

### 9.2 After every iteration in Phase 4

```bash
pnpm mutation:incremental    # mutation score must be monotonically non-decreasing
```

If the score drops after a change, the change introduced or weakened a test. Revert and re-think.

### 9.3 Disable-comment audit

Before merging mutation work:

```bash
# Every Stryker disable must include a reason after the colon.
grep -rn "Stryker disable" src/ | grep -v ":.*:" | grep -v ":$"
# Should output zero lines. Any line printed has a disable without a reason.
```

Run `/bymax-quality:code-review` after Phase 4 to enforce the no-suppression rule from `bymax-workflow:standards` §8 — note that `// Stryker disable` is the **one** allowed exception, **only with a documented reason**.

### 9.4 Release gate

The final commit for this work must pass:

```bash
pnpm prepublishOnly   # already exists in package.json
```

This runs the full chain. Do **not** include mutation testing inside `prepublishOnly` — it is too slow for an interactive `pnpm publish`. Mutation is an out-of-band, human-triggered gate per §11.

---

## 10. Documentation Updates

After Phase 5 succeeds, update these three files (English, no Portuguese in code/docs per `CLAUDE.md`):

### 10.1 `CLAUDE.md` — Critical Rules section

Append a new entry under **Verification — Run Before Completing Any Task**:

```markdown
For release validation, also run:

\`\`\`bash
pnpm mutation # full mutation testing (~15-25 min)
pnpm mutation:incremental # incremental (uses reports/stryker-incremental.json)
\`\`\`

Mutation score must be ≥ 95% before tagging a release. See
[docs/mutation_testing_plan.md](./docs/mutation_testing_plan.md).
```

### 10.2 `AGENTS.md`

Add a short "Mutation testing" subsection pointing at this file. Do not duplicate content — link.

### 10.3 `docs/guidelines/JEST-TESTING-GUIDELINES.md`

Add a "Mutation testing" subsection that:

- Briefly explains the relationship between line coverage and mutation score.
- Tells contributors to run `pnpm mutation:incremental` locally when adding tests to a hot path.
- References §8 of this file for the iteration workflow.

---

## 11. CI Strategy (Phase 5 — Documentation Only, No Wiring)

**Decision:** Do **not** add mutation testing as a blocking job on the per-PR `ci.yml` workflow.

**Reasons:**

- A full run is 15–25 minutes. PR feedback latency would balloon.
- Stryker forks the suite many times — CI minute costs and energy consumption scale poorly.
- The `ci.yml` and `release.yml` workflows are currently `manual-only` (commit `8844410`), and that policy is honoured here.

**Recommended strategy (document in `AGENTS.md`, do not implement now):**

1. Add a separate `.github/workflows/mutation.yml` triggered by:
   - `workflow_dispatch` (manual)
   - `push` to release branches (`release/*`)
   - **Not** on every PR.
2. Cache `node_modules`, the Jest haste-map, and `reports/stryker-incremental.json`.
3. Upload `reports/mutation/mutation.html` as a build artefact.
4. Optional future enhancement: integrate Stryker Dashboard once a decision is made on whether to publish results publicly.

**Implementing this workflow is OUT OF SCOPE for the current task.** Capture it as a follow-up issue.

---

## 12. Risk Register

| ID  | Severity | Risk                                                                                                  | Mitigation                                                                                                                                                                                                  |
| --- | -------- | ----------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R1  | 🔴 HIGH  | Wall-clock runtime balloons past 30 min, making local iteration impractical.                          | Tune `concurrency`. Enable `incremental: true` after baseline. If still slow, split config per-subpath into `stryker.server.config.json`, `stryker.client.config.json`, etc., and run separately.           |
| R2  | 🔴 HIGH  | NestJS DI `Symbol()` token mutations cause cascade failures with unclear root cause.                  | Identify in baseline. Add `// Stryker disable StringLiteral` blocks to `*.constants.ts` files holding DI tokens, with the reason from §8.3.                                                                 |
| R3  | 🟡 MED   | ESM + ts-jest + Stryker sandbox mismatch on first run.                                                | Run `pnpm mutation:dry-run` first (cheap). If it fails, see §7's failure modes. Fallback: temporary `jest.config.cjs` shim used **only** by Stryker.                                                        |
| R4  | 🟡 MED   | `class-validator` decorators lose metadata in the sandbox.                                            | `disableTypeChecks` + `ignoreStatic: true` cover the common cases. If specific DTOs still misbehave, target them with `// Stryker disable BlockStatement: decorator metadata, tested at integration level`. |
| R5  | 🟡 MED   | Mutation score caps at ~90% due to unavoidable equivalent mutants in localised strings and DI tokens. | Set `thresholds.break: 90` (not 95) for the long-term gate. Document the equivalent-mutant inventory in §13 as the project's "definition of done".                                                          |
| R6  | 🟢 LOW   | `reports/` directory bloats the working tree.                                                         | `.gitignore` entry in §6.2.                                                                                                                                                                                 |
| R7  | 🟢 LOW   | Stryker version drift breaks the config in the future.                                                | Pin all three Stryker packages to the same major. Use `@^8` initially, bump together.                                                                                                                       |
| R8  | 🟢 LOW   | Devs run `pnpm mutation` accidentally in CI by including it in `prepublishOnly`.                      | Explicitly do NOT add it to `prepublishOnly`. Document in §9.4.                                                                                                                                             |

---

## 13. Acceptance Criteria (Definition of Done)

This task is **done** when **all** of the following hold:

1. ✅ `pnpm test:cov:all` still produces 100% coverage in every metric.
2. ✅ `stryker.config.json` exists at the repo root and matches §5.
3. ✅ `package.json` has the three scripts from §6.1.
4. ✅ `.gitignore` has the entries from §6.2.
5. ✅ `pnpm mutation` exits with code 0.
6. ✅ Overall mutation score ≥ **95%** (or ≥ 90% with every gap below the threshold documented per §8.3).
7. ✅ Every directory in §8.5 (hot paths) scores ≥ 95%.
8. ✅ Every `// Stryker disable` comment has a `: <reason>` (verified via the `grep` in §9.3).
9. ✅ `pnpm typecheck && pnpm lint && pnpm test && pnpm build` all pass.
10. ✅ `CLAUDE.md`, `AGENTS.md`, `docs/guidelines/JEST-TESTING-GUIDELINES.md` updated per §10.
11. ✅ `thresholds.break` in `stryker.config.json` set to the floor of whatever score we achieved (e.g., 90 if we landed at 92%, 95 if we landed at 96%).
12. ✅ No new entries appear in `dependencies` or `peerDependencies` of `package.json` (Stryker is dev-only).

If criterion 6 cannot be met (e.g., mutation score plateaus at 88%), **stop and report**. Do not lower thresholds to make the gate pass. A surviving mutant is by definition a real or equivalent issue — categorise and decide explicitly, do not paper over.

---

## 14. Out of Scope (Do NOT Do in This Task)

- ❌ Adding mutation testing to `prepublishOnly` or to `ci.yml`.
- ❌ Implementing `.github/workflows/mutation.yml` (only document the strategy).
- ❌ Stryker Dashboard integration / public sharing of results.
- ❌ Including E2E tests (`test/e2e/**`) in the Stryker run.
- ❌ Refactoring production source to "make mutants easier to kill". If a real gap exists, **add a test**, do not change the source.
- ❌ Disabling mutants without a reason. Every `// Stryker disable` needs a `: <reason>` (English).
- ❌ Lowering thresholds to mask a failure. Either fix the test or document the equivalent mutant.
- ❌ Touching `peerDependencies`, `dependencies`, or build/runtime files outside the test infrastructure.

---

## 15. References

- Stryker JS official docs: https://stryker-mutator.io/docs/stryker-js/introduction/
- Jest runner: https://stryker-mutator.io/docs/stryker-js/jest-runner/
- TypeScript checker: https://stryker-mutator.io/docs/stryker-js/typescript-checker/
- Disabling mutants: https://stryker-mutator.io/docs/stryker-js/configuration/#disable-mutants-with-comments
- Configuration reference: https://github.com/stryker-mutator/stryker-js/blob/master/docs/configuration.md
- Project standards: `bymax-workflow:standards` skill (loaded via `/bymax-workflow:standards`)
- Project rules: [`CLAUDE.md`](../CLAUDE.md)
- Detailed architecture: [`AGENTS.md`](../AGENTS.md)
- Testing guide: [`docs/guidelines/JEST-TESTING-GUIDELINES.md`](./guidelines/JEST-TESTING-GUIDELINES.md)

---

## 16.5 Outcome (2026-05-19)

- **Baseline:** 73.59% (then re-baselined to 74.45% after correcting `ignoreStatic` → `false`).
- **Final mutation score:** **99.10%** (Stryker 9.6.1, Node 24, full unit suite).
- **Line coverage:** still 100% across all metrics (1980 tests, unit + e2e).
- **Per hot-path:** crypto 100%, guards 100%, services 99.45%, oauth 99.12%, nextjs 98.49%, client 97.47%. (`react` dir 93.65% — see below.)
- **`thresholds.break`** raised `80 → 95` to lock the floor.
- **92 documented equivalent-mutant disables** (`// Stryker disable next-line <Mutator>: <reason>`), every one carrying a reason.
- **10 documented equivalents remain reported as "survived"** — a Stryker limitation: `disable next-line` does not attach when the comment is the _trailing_ comment of a block body (before `}, [dep])` in a `useEffect`/`useCallback`, before `} catch {`, or between `if (` and a multi-line condition's operands). They are: 4 `ArrayDeclaration` dep-array mutants in `react/AuthProvider.tsx` (stable refs), 5 `BlockStatement` `catch {}` mutants (createAuthFetch, oauth.service, invitation.service, password-reset.service, session.service), and 1 `ConditionalExpression` in a multi-line `if` (session.service). All carry inline reasons; suppressing them would require region `disable`/`restore` pairs that risk also masking legitimately-killed sibling mutants, so they were left as documented equivalents. This is why `react` reads 93.65% rather than ~100%.

## 16. Execution Checklist (for the agent picking this up)

Copy this checklist into a task list and tick items as you go:

- [ ] §2 — Confirm baseline: `pnpm test:cov:all` shows 100% across all metrics.
- [ ] §4 — Install Stryker dev dependencies.
- [ ] §5 — Create `stryker.config.json` (valid JSON, no comments).
- [ ] §6.1 — Add `mutation`, `mutation:incremental`, `mutation:dry-run` scripts to `package.json`.
- [ ] §6.2 — Add `.stryker-tmp/` and `reports/` to `.gitignore`.
- [ ] §7 — Run `pnpm mutation:dry-run` and resolve any boot errors.
- [ ] §7 — Run `pnpm mutation` (baseline). Save the score.
- [ ] §8 — Iterate: for each survived mutant, decide GAP / EQUIVALENT / ACCEPTABLE.
- [ ] §8.5 — Bring every hot-path directory to ≥ 95%.
- [ ] §8.6 — Land overall score ≥ 95%, then raise `thresholds.break` to the achieved floor.
- [ ] §9 — Run all verification gates clean.
- [ ] §9.3 — Audit disable comments — every one has a reason.
- [ ] §10 — Update `CLAUDE.md`, `AGENTS.md`, `JEST-TESTING-GUIDELINES.md`.
- [ ] §13 — Verify every acceptance criterion ✅.
- [ ] Hand off — commit with `chore(test): add Stryker mutation testing (score: NN%)`. Do **not** push without user approval.
